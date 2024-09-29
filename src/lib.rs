use std::{
    cmp,
    collections::VecDeque,
    num::{NonZeroU16, NonZeroU32, Wrapping},
    time::Duration,
};

use bit_field::{BitArray, BitField};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use error::{DecodeError, EncodeError, Error};
use futures::{future::OptionFuture, SinkExt, StreamExt};
use packet::{Connect, ControlPacket, Disconnect, DisconnectReasonCode, Publish, Subscribe};
use property::{
    AuthenticationData, AuthenticationMethod, ContentType, CorrelationData, MaximumPacketSize,
    MessageExpiryInterval, PayloadFormatIndicator, ReasonString, ReceiveMaximum,
    RequestProblemInformation, RequestResponseInformation, ResponseTopic, ServerReference,
    SessionExpiryInterval, SubscriptionIdentifierMultiple, SubscriptionIdentifierSingle,
    TopicAlias, TopicAliasMaximum, UserProperty,
};
use tokio::{
    io::AsyncWriteExt,
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
    select,
    time::{sleep_until, timeout, Instant},
};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tracing::{error, trace};

use error::Result;

use crate::packet::PingReq;

pub mod error;
pub mod packet;
pub mod property;

pub struct Client<'a> {
    addr: (&'a str, u16),
    connection_settings: ConnectionSettings,
    session_state: &'a mut ClientSessionState,
    connection: Connection,
    reconnect_state: ReconnectState,
}

impl<'a> Client<'a> {
    pub async fn new(
        addr: (&'a str, u16),
        connection_settings: ConnectionSettings,
        mut session_state: &'a mut ClientSessionState,
    ) -> Result<Client<'a>> {
        let mut reconnect_state = ReconnectState::new(&connection_settings);

        loop {
            let res = Connection::new(addr, &connection_settings).await;
            let connection = match res {
                Ok(connection) => connection,
                Err(err) => {
                    error!(%err, "failed to connect");
                    reconnect_state
                        .start_reconnect(&connection_settings)
                        .await?;
                    continue;
                }
            };

            let mut client = Self {
                addr,
                connection_settings: connection_settings.clone(),
                session_state,
                connection,
                reconnect_state,
            };
            let res = client.connect().await;
            match res {
                Ok(()) => break Ok(client),
                Err(err) => {
                    error!(%err, "failed to connect");

                    session_state = client.session_state;
                    reconnect_state = client.reconnect_state;

                    reconnect_state
                        .start_reconnect(&connection_settings)
                        .await?;

                    continue;
                }
            }
        }
    }

    async fn reconnect(&mut self, err: impl Into<Error>) -> Result<()> {
        let err: Error = err.into();
        let err = self.reconnect_state.request_reconnect(err)?;
        error!(%err, "encountered error. reconnecting...");

        loop {
            self.reconnect_state
                .start_reconnect(&self.connection_settings)
                .await?;

            let res = Connection::new(self.addr, &self.connection_settings).await;
            match res {
                Ok(connection) => self.connection = connection,
                Err(err) => {
                    error!(%err, "failed to connect");
                    self.reconnect_state
                        .start_reconnect(&self.connection_settings)
                        .await?;
                    continue;
                }
            };

            let res = Box::pin(self.connect()).await;
            match res {
                Ok(()) => break Ok(()),
                Err(err) => {
                    error!(%err, "failed to connect");
                    self.reconnect_state
                        .start_reconnect(&self.connection_settings)
                        .await?;
                    continue;
                }
            }
        }
    }

    /// This method is cancellation safe.
    async fn recv(&mut self) -> Result<ControlPacket> {
        // This method is also responsible for sending ping packets whenever
        // the keep alive duration elapses. If this method is not called and
        // no other function sends a packet, this will lead to us not sending
        // packets within the keep alive duration and the sever may close the
        // connection. This isn't a problem because we transparently handle
        // reconnects and if the user isn't sending nor receiving messages we
        // might as let connection die.

        loop {
            let mut timeout = self.connection_settings.timeout;
            let keep_alive_elapsed = if let Some(keep_alive) = self.connection.keep_alive {
                let duration = Duration::from_secs(u64::from(keep_alive.get()));
                timeout = cmp::max(timeout, duration * 2);
                Some(sleep_until(self.connection.last_sent + duration))
            } else {
                None
            };
            let receive_timeout = sleep_until(self.connection.last_received + timeout);

            select! {
                biased;
                res = self.connection.framed_read.next() => {
                    let raw = res.ok_or(DecodeError::UnexpectedEof)??;
                    self.connection.last_received = Instant::now();
                    let packet = ControlPacket::decode(raw)?;
                    return Ok(packet);
                }
                _ = receive_timeout => return Err(Error::Timeout),
                Some(_) = OptionFuture::from(keep_alive_elapsed) => {
                    // Send a keep-alive packet.
                    // Sending isn't cancellation safe, but we don't care if
                    // this get's cancelled, we'll either let the connection
                    // die or send one too many ping requests both of which are
                    // fine.
                    self.send(&ControlPacket::PingReq(PingReq {})).await?;
                }
            }
        }
    }

    async fn send(&mut self, packet: &ControlPacket) -> Result<()> {
        let raw = packet.encode()?;
        timeout(
            self.connection_settings.timeout,
            self.connection.framed_write.send(raw),
        )
        .await??;
        self.connection.last_sent = Instant::now();
        Ok(())
    }

    async fn connect(&mut self) -> Result<()> {
        let connect = Connect {
            protocol_name: "MQTT".to_owned(),
            protocol_level: 5,
            clean_start: self.connection_settings.clean_start,
            keep_alive: self.connection_settings.keep_alive,
            session_expiry_interval: self
                .connection_settings
                .session_expiry_interval
                .map(SessionExpiryInterval::new)
                .unwrap_or_default(),
            receive_maximum: ReceiveMaximum::default(),
            maximum_packet_size: MaximumPacketSize::new(
                self.connection_settings.maximum_packet_size,
            ),
            topic_alias_maximum: TopicAliasMaximum::default(),
            request_response_information: RequestResponseInformation::default(),
            request_problem_information: RequestProblemInformation::default(),
            user_property: UserProperty::default(),
            authentication_method: AuthenticationMethod::default(),
            authentication_data: AuthenticationData::default(),
            client_identifier: self.session_state.client_identifier.clone(),
            will: None,
            user_name: self.connection_settings.user_name.clone(),
            password: self.connection_settings.password.clone(),
        };
        self.send(&ControlPacket::Connect(connect)).await?;

        let packet = self.recv().await?;
        let conn_ack = if let ControlPacket::ConnAck(conn_ack) = packet {
            conn_ack
        } else {
            self.connection.framed_write.get_mut().shutdown().await?;
            return Err(Error::UnexpectedPacket);
        };

        if !conn_ack.connect_reason_code.is_success() {
            return Err(Error::ConnectFailed(conn_ack.connect_reason_code));
        }

        if !conn_ack.session_present {
            self.session_state.reset();
        }

        if let Some(assigned_client_identifier) = conn_ack.assigned_client_identifier.get() {
            self.session_state.client_identifier = Some(assigned_client_identifier.to_owned());
        }

        self.connection.keep_alive = conn_ack
            .server_keep_aliave
            .get()
            .unwrap_or(self.connection_settings.keep_alive);

        self.connection.framed_write.encoder_mut().max_packet_length = conn_ack
            .maximum_packet_size
            .get()
            .map_or(u32::MAX, NonZeroU32::get);

        self.reconnect_state.set_connected();

        Ok(())
    }

    /// This method is not cancellation safe.
    pub async fn publish(
        &mut self,
        topic_name: impl Into<String>,
        data: Bytes,
        qos_level: QoSLevel,
    ) -> Result<()> {
        let packet_identifier = match qos_level {
            QoSLevel::AtMostOnce => None,
            QoSLevel::AtLeastOnce | QoSLevel::ExactlyOnce => {
                Some(self.session_state.id_allocator.allocate()?)
            }
        };
        let packet = ControlPacket::Publish(Publish {
            retain: false,
            qos_level,
            dup_flag: false,
            topic_name: topic_name.into(),
            packet_identifier,
            payload_format_indicator: PayloadFormatIndicator::default(),
            message_expiry_interval: MessageExpiryInterval::default(),
            topic_alias: TopicAlias::default(),
            response_topic: ResponseTopic::default(),
            correlation_data: CorrelationData::default(),
            user_property: UserProperty::default(),
            subscription_identifier: SubscriptionIdentifierMultiple::default(),
            content_type: ContentType::default(),
            data,
        });

        for _ in 0..=self.connection_settings.max_retries {
            if let Err(err) = self.send(&packet).await {
                self.reconnect(err).await?;
                continue;
            }

            match qos_level {
                QoSLevel::AtMostOnce => {}
                QoSLevel::AtLeastOnce => todo!(),
                QoSLevel::ExactlyOnce => todo!(),
            }

            return Ok(());
        }
        Err(Error::TooManyRetries)
    }

    /// This method is not cancellation safe.
    pub async fn subscribe(&mut self, topic_name: &str) -> Result<()> {
        let packet_identifier = self.session_state.id_allocator.allocate()?;
        let packet = ControlPacket::Subscribe(Subscribe {
            packet_identifier,
            subscription_identifier: SubscriptionIdentifierSingle::default(),
            user_property: UserProperty::default(),
            topic_filters: vec![(topic_name.to_owned(), 2 << 4)],
        });

        'outer: for _ in 0..=self.connection_settings.max_retries {
            if let Err(err) = self.send(&packet).await {
                self.reconnect(err).await?;
                continue;
            }

            let sub_ack = loop {
                let packet = match self.recv().await {
                    Ok(packet) => packet,
                    Err(err) => {
                        self.reconnect(err).await?;
                        continue 'outer;
                    }
                };
                match packet {
                    ControlPacket::SubAck(sub_ack)
                        if sub_ack.packet_identifier == packet_identifier =>
                    {
                        break sub_ack;
                    }
                    ControlPacket::Publish(publish) => self.try_buffer_publish(publish),
                    ControlPacket::PingResp(_) => {}
                    ControlPacket::Disconnect(disconnect) => {
                        self.connection.framed_write.get_mut().shutdown().await?;
                        return Err(Error::Disconnected(disconnect.disconnect_reason_code));
                    }
                    unexpected => {
                        error!(packet = ?unexpected, "unexpected packet");
                        self.disconnect(DisconnectReasonCode::PROTOCOL_ERROR)
                            .await?;
                        return Err(Error::UnexpectedPacket);
                    }
                }
            };

            self.session_state
                .id_allocator
                .deallocate(packet_identifier);

            let sub_ack_reason_code = sub_ack.reason_codes[0];
            if !sub_ack_reason_code.is_success() {
                return Err(Error::SubscriptionFailed(sub_ack_reason_code));
            }

            return Ok(());
        }
        Err(Error::TooManyRetries)
    }

    fn try_buffer_publish(&mut self, publish: Publish) {
        self.connection.buffered_publish_messages.push_back(publish);
    }

    /// This method is cancellation safe.
    pub async fn receive(&mut self) -> Result<(String, Bytes)> {
        let publish = if let Some(publish) = self.connection.buffered_publish_messages.pop_front() {
            publish
        } else {
            loop {
                let packet = match self.recv().await {
                    Ok(packet) => packet,
                    Err(err) => {
                        self.reconnect(err).await?;
                        continue;
                    }
                };
                match packet {
                    ControlPacket::Publish(publish) => break publish,
                    ControlPacket::PingResp(_) => {}
                    ControlPacket::Disconnect(disconnect) => {
                        self.connection.framed_write.get_mut().shutdown().await?;
                        return Err(Error::Disconnected(disconnect.disconnect_reason_code));
                    }
                    unexpected => {
                        error!(packet = ?unexpected, "unexpected packet");
                        self.disconnect(DisconnectReasonCode::PROTOCOL_ERROR)
                            .await?;
                        return Err(Error::UnexpectedPacket);
                    }
                }
            }
        };

        match publish.qos_level {
            QoSLevel::AtMostOnce => {}
            QoSLevel::AtLeastOnce => todo!(),
            QoSLevel::ExactlyOnce => todo!(),
        };

        Ok((publish.topic_name, publish.data))
    }

    pub async fn close(mut self) -> Result<()> {
        self.disconnect(DisconnectReasonCode::SUCCESS).await?;
        Ok(())
    }

    async fn disconnect(&mut self, disconnect_reason_code: DisconnectReasonCode) -> Result<()> {
        let res = self
            .send(&ControlPacket::Disconnect(Disconnect {
                disconnect_reason_code,
                session_expiry_interval: SessionExpiryInterval::default(),
                reason_string: ReasonString::default(),
                user_property: UserProperty::default(),
                server_reference: ServerReference::default(),
            }))
            .await;
        self.connection.framed_write.get_mut().shutdown().await?;
        res
    }
}

struct Connection {
    framed_read: FramedRead<OwnedReadHalf, MqttDecoder>,
    framed_write: FramedWrite<OwnedWriteHalf, MqttEncoder>,

    keep_alive: Option<NonZeroU16>,
    last_sent: Instant,
    last_received: Instant,
    buffered_publish_messages: VecDeque<Publish>,
}

impl Connection {
    async fn new(addr: (&str, u16), connection_settings: &ConnectionSettings) -> Result<Self> {
        let socket = timeout(connection_settings.timeout, TcpStream::connect(addr)).await??;
        let (read_half, write_half) = socket.into_split();
        Ok(Self {
            framed_read: FramedRead::new(
                read_half,
                MqttDecoder {
                    max_packet_length: connection_settings.maximum_packet_size(),
                    decoder_state: DecoderState::default(),
                },
            ),
            framed_write: FramedWrite::new(
                write_half,
                MqttEncoder {
                    max_packet_length: 1000,
                },
            ),
            keep_alive: connection_settings.keep_alive,
            last_sent: Instant::now(),
            last_received: Instant::now(),
            buffered_publish_messages: VecDeque::new(),
        })
    }
}

#[derive(Clone)]
pub struct ConnectionSettings {
    pub timeout: Duration,
    pub max_retries: u32,
    pub max_reconnects: u32,
    pub reconnect_delay: Duration,
    pub clean_start: bool,
    pub keep_alive: Option<NonZeroU16>,
    pub session_expiry_interval: Option<u32>,
    pub user_name: Option<String>,
    pub password: Option<Bytes>,
    pub maximum_packet_size: Option<NonZeroU32>,
}

impl ConnectionSettings {
    fn maximum_packet_size(&self) -> usize {
        self.maximum_packet_size
            .and_then(|size| usize::try_from(size.get()).ok())
            .unwrap_or(usize::MAX)
    }
}

impl Default for ConnectionSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            max_retries: 3,
            max_reconnects: 3,
            reconnect_delay: Duration::from_secs(1),
            clean_start: false,
            keep_alive: NonZeroU16::new(10),
            session_expiry_interval: None,
            user_name: None,
            password: None,
            maximum_packet_size: NonZeroU32::new(0x10000),
        }
    }
}

enum ReconnectState {
    Connected,
    Connecting {
        last_reconnect: Instant,
        reconnect_counter: u32,
    },
}

impl ReconnectState {
    pub fn new(settings: &ConnectionSettings) -> Self {
        Self::Connecting {
            last_reconnect: Instant::now(),
            reconnect_counter: settings.max_reconnects,
        }
    }

    async fn start_reconnect(&mut self, settings: &ConnectionSettings) -> Result<()> {
        match self {
            ReconnectState::Connected => *self = Self::new(settings),
            ReconnectState::Connecting {
                last_reconnect,
                reconnect_counter,
            } => {
                let deadline = *last_reconnect + settings.reconnect_delay;
                sleep_until(deadline).await;
                *reconnect_counter = reconnect_counter
                    .checked_sub(1)
                    .ok_or(Error::TooManyReconnects)?;
            }
        }
        Ok(())
    }

    fn set_connected(&mut self) {
        *self = Self::Connected;
    }

    /// Check if a send/receive op can reconnect.
    ///
    /// Reconnecting is not allowed when the client is already reconnecting or
    /// connecting for the first time.
    fn request_reconnect<E: Into<Error>>(&mut self, err: E) -> Result<E> {
        match self {
            ReconnectState::Connected => Ok(err),
            ReconnectState::Connecting { .. } => Err(err.into()),
        }
    }
}

pub struct ClientSessionState {
    client_identifier: Option<String>,
    id_allocator: IdAllocator,
}

impl ClientSessionState {
    pub fn new() -> Self {
        Self {
            client_identifier: None,
            id_allocator: IdAllocator::new(),
        }
    }

    fn reset(&mut self) {}
}

impl Default for ClientSessionState {
    fn default() -> Self {
        Self::new()
    }
}

struct IdAllocator {
    id_counter: Wrapping<u16>,
    bits: Box<[u8; 8192]>,
}

impl IdAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn allocate(&mut self) -> Result<u16> {
        let start = self.id_counter.0;
        loop {
            let id = self.id_counter.0;
            if !self.bits.get_bit(usize::from(id)) {
                self.bits.set_bit(usize::from(id), true);
                return Ok(id);
            }
            self.id_counter += 1;
            if self.id_counter.0 == start {
                return Err(Error::OutOfPacketIdentifiers);
            }
        }
    }

    pub fn deallocate(&mut self, id: u16) {
        assert!(self.bits.get_bit(usize::from(id)));
        self.bits.set_bit(usize::from(id), false);
    }
}

impl Default for IdAllocator {
    fn default() -> Self {
        let mut this = Self {
            id_counter: Default::default(),
            bits: Box::new([0; 8192]),
        };
        this.bits.set_bit(0, true);
        this
    }
}

struct MqttDecoder {
    max_packet_length: usize,
    decoder_state: DecoderState,
}

#[derive(Default, Clone, Copy)]
enum DecoderState {
    #[default]
    Initial,
    DecodingFixedHeader {
        flags: u8,
        packet_type: u8,
        remaining_length: u32,
        remaining_length_bytes_read: u8,
    },
    DecodedFixedHeader {
        flags: u8,
        packet_type: u8,
        remaining_length: usize,
    },
}

impl Decoder for MqttDecoder {
    type Item = RawPacket;
    type Error = DecodeError;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.decoder_state {
                DecoderState::Initial => {
                    if src.is_empty() {
                        return Ok(None);
                    }
                    let first_byte = src.get_u8();
                    let flags = first_byte.get_bits(0..=3);
                    let packet_type = first_byte.get_bits(4..=7);
                    trace!(packet_type, flags = ?format_args!("{flags:#06b}"), "read flags");
                    self.decoder_state = DecoderState::DecodingFixedHeader {
                        flags,
                        packet_type,
                        remaining_length: 0,
                        remaining_length_bytes_read: 0,
                    };
                }
                DecoderState::DecodingFixedHeader {
                    flags,
                    packet_type,
                    ref mut remaining_length,
                    ref mut remaining_length_bytes_read,
                } => {
                    if *remaining_length_bytes_read >= 4 {
                        return Err(DecodeError::VariableByteIntTooLong);
                    }
                    if src.is_empty() {
                        return Ok(None);
                    }

                    let byte = src.get_u8();
                    remaining_length.set_bits(
                        usize::from(*remaining_length_bytes_read * 7)
                            ..=usize::from(*remaining_length_bytes_read * 7) + 6,
                        u32::from(byte.get_bits(0..=6)),
                    );
                    *remaining_length_bytes_read += 1;
                    trace!(remaining_length, byte, "reading remaining length");

                    if !byte.get_bit(7) {
                        let remaining_length_usize = usize::try_from(*remaining_length)
                            .map_err(|_| DecodeError::PacketTooLong(*remaining_length))?;
                        if remaining_length_usize > self.max_packet_length {
                            return Err(DecodeError::PacketTooLong(*remaining_length));
                        }
                        self.decoder_state = DecoderState::DecodedFixedHeader {
                            flags,
                            packet_type,
                            remaining_length: remaining_length_usize,
                        };
                    }
                }
                DecoderState::DecodedFixedHeader {
                    flags,
                    packet_type,
                    remaining_length,
                } => {
                    if src.len() < remaining_length {
                        return Ok(None);
                    }
                    let variable_data = src.split_to(remaining_length).freeze();
                    self.decoder_state = DecoderState::Initial;
                    return Ok(Some(RawPacket {
                        flags,
                        packet_type,
                        remaining_data: variable_data,
                    }));
                }
            }
        }
    }
}

struct MqttEncoder {
    max_packet_length: u32,
}

impl Encoder<RawPacket> for MqttEncoder {
    type Error = EncodeError;

    fn encode(&mut self, item: RawPacket, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let mut first_byte = 0;
        first_byte.set_bits(0..=3, item.flags);
        first_byte.set_bits(4..=7, item.packet_type);
        dst.put_u8(first_byte);

        let remaining_length = item.remaining_data.len();
        let remaining_length = u32::try_from(remaining_length).unwrap();
        if remaining_length > self.max_packet_length {
            return Err(EncodeError::PacketTooLong(remaining_length));
        }
        write_variable_byte_integer(remaining_length, &mut *dst)?;

        dst.extend_from_slice(&item.remaining_data);

        Ok(())
    }
}

struct RawPacket {
    flags: u8,
    packet_type: u8,
    remaining_data: Bytes,
}

fn read_variable_byte_integer(mut buf: impl Buf) -> Result<u32, DecodeError> {
    let mut value = 0;
    let mut bytes_read = 0;
    loop {
        if bytes_read >= 4 {
            return Err(DecodeError::VariableByteIntTooLong);
        }
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }

        let byte = buf.get_u8();

        value.set_bits(
            (bytes_read * 7)..=(bytes_read * 7) + 6,
            u32::from(byte.get_bits(0..=6)),
        );
        bytes_read += 1;

        if !byte.get_bit(7) {
            break;
        }
    }
    Ok(value)
}

fn read_string(mut buf: impl Buf) -> Result<String, DecodeError> {
    if buf.remaining() < 2 {
        return Err(DecodeError::UnexpectedEof);
    }
    let len = usize::from(buf.get_u16());
    if buf.remaining() < len {
        return Err(DecodeError::UnexpectedEof);
    }
    let mut bytes = vec![0; len];
    buf.copy_to_slice(&mut bytes);

    let string = String::from_utf8(bytes).map_err(|_| DecodeError::MalformedString)?;
    if string.chars().any(|c| c == '\0') {
        return Err(DecodeError::MalformedString);
    }
    if cfg!(feature = "strict")
        && string.chars().any(|c| {
            c.is_control()
                || (0xfdd0..=0xfdef).contains(&u32::from(c))
                || u32::from(c) & 0xfffe == 0xfffe
        })
    {
        return Err(DecodeError::MalformedString);
    }

    Ok(string)
}

fn read_binary_data(mut buf: impl Buf) -> Result<Bytes, DecodeError> {
    if buf.remaining() < 2 {
        return Err(DecodeError::UnexpectedEof);
    }
    let len = usize::from(buf.get_u16());
    if buf.remaining() < len {
        return Err(DecodeError::UnexpectedEof);
    }
    Ok(buf.copy_to_bytes(len))
}

fn write_variable_byte_integer(mut value: u32, mut buf: impl BufMut) -> Result<(), EncodeError> {
    if value >= 268435456 {
        return Err(EncodeError::VariableByteIntTooLong(value));
    }
    loop {
        let mut byte = value.get_bits(0..=6) as u8;
        value >>= 7;
        byte.set_bit(7, value != 0);
        buf.put_u8(byte);
        if value == 0 {
            break;
        }
    }
    Ok(())
}

fn write_string(value: &str, mut buf: impl BufMut) -> Result<(), EncodeError> {
    let len = u16::try_from(value.len()).map_err(|_| EncodeError::StringTooLong(value.len()))?;
    buf.put_u16(len);
    buf.put_slice(value.as_bytes());
    Ok(())
}

fn write_binary_data(value: &[u8], mut buf: impl BufMut) -> Result<(), EncodeError> {
    let len =
        u16::try_from(value.len()).map_err(|_| EncodeError::BinaryDataTooLong(value.len()))?;
    buf.put_u16(len);
    buf.put_slice(value);
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QoSLevel {
    AtMostOnce = 0,
    AtLeastOnce = 1,
    ExactlyOnce = 2,
}
