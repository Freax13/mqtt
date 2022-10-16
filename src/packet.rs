use std::num::NonZeroU16;

use bit_field::BitField;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::{
    property::{
        read_properties, write_properties, AssignedClientIdentifier, AuthenticationData,
        AuthenticationMethod, ContentType, CorrelationData, MaximumPacketSize, MaximumQoS,
        MessageExpiryInterval, PayloadFormatIndicator, ReasonString, ReceiveMaximum,
        RequestProblemInformation, RequestResponseInformation, ResponseInformation, ResponseTopic,
        RetainAvailable, ServerKeepAlive, ServerReference, SessionExpiryInterval,
        SharedSubscriptionAvailable, SubscriptionIdentifierMultiple, SubscriptionIdentifierSingle,
        SubscriptionIdentifiersAvailable, TopicAlias, TopicAliasMaximum, UserProperty,
        WildcardSubscriptionAvailable, WillDelayInterval,
    },
    read_binary_data, read_string, write_binary_data, write_string, DecodeError, EncodeError,
    QoSLevel, RawPacket,
};

#[derive(Debug)]
pub enum ControlPacket {
    Connect(Connect),
    ConnAck(ConnAck),
    Publish(Publish),
    Subscribe(Subscribe),
    SubAck(SubAck),
    PingReq(PingReq),
    PingResp(PingResp),
    Disconnect(Disconnect),
}

impl ControlPacket {
    pub(super) fn decode(raw: RawPacket) -> Result<Self, DecodeError> {
        let mut buf = raw.remaining_data;
        let packet = match raw.packet_type {
            1 => Connect::decode(&mut buf).map(Self::Connect)?,
            2 => ConnAck::decode(&mut buf).map(Self::ConnAck)?,
            3 => Publish::decode(raw.flags, &mut buf).map(Self::Publish)?,
            9 => SubAck::decode(&mut buf).map(Self::SubAck)?,
            12 => PingReq::decode(&mut buf).map(Self::PingReq)?,
            13 => PingResp::decode(&mut buf).map(Self::PingResp)?,
            14 => Disconnect::decode(&mut buf).map(Self::Disconnect)?,
            other => return Err(DecodeError::UnknownPacketType(other)),
        };
        if !buf.is_empty() {
            return Err(DecodeError::TooMuchData);
        }
        Ok(packet)
    }

    pub(super) fn encode(&self) -> Result<RawPacket, EncodeError> {
        let (packet_type, flags, remaining_data) = match self {
            ControlPacket::Connect(connect) => (1, 0, connect.encode()?),
            ControlPacket::ConnAck(_) => todo!(),
            ControlPacket::Publish(publish) => {
                let (flags, raw) = publish.encode()?;
                (3, flags, raw)
            }
            ControlPacket::Subscribe(subscribe) => (8, 2, subscribe.encode()?),
            ControlPacket::SubAck(_) => todo!(),
            ControlPacket::PingReq(ping_req) => (12, 0, ping_req.encode()?),
            ControlPacket::PingResp(ping_resp) => (12, 0, ping_resp.encode()?),
            ControlPacket::Disconnect(disconnect) => (14, 0, disconnect.encode()?),
        };
        Ok(RawPacket {
            flags,
            packet_type,
            remaining_data,
        })
    }
}

#[derive(Debug)]
pub struct Connect {
    pub protocol_name: String,
    pub protocol_level: u8,
    pub clean_start: bool,
    pub keep_alive: Option<NonZeroU16>,
    pub session_expiry_interval: SessionExpiryInterval,
    pub receive_maximum: ReceiveMaximum,
    pub maximum_packet_size: MaximumPacketSize,
    pub topic_alias_maximum: TopicAliasMaximum,
    pub request_response_information: RequestResponseInformation,
    pub request_problem_information: RequestProblemInformation,
    pub user_property: UserProperty,
    pub authentication_method: AuthenticationMethod,
    pub authentication_data: AuthenticationData,
    pub client_identifier: Option<String>,
    pub will: Option<Will>,
    pub user_name: Option<String>,
    pub password: Option<Bytes>,
}

#[derive(Debug)]
pub struct Will {
    pub will_qos: u8,
    pub will_retain: bool,
    pub will_delay_interval: WillDelayInterval,
    pub payload_format_indicator: PayloadFormatIndicator,
    pub message_expiry_interval: MessageExpiryInterval,
    pub content_type: ContentType,
    pub response_topic: ResponseTopic,
    pub correlation_data: CorrelationData,
    pub user_property: UserProperty,
    pub topic: String,
    pub payload: Bytes,
}

impl Connect {
    fn decode(mut buf: impl Buf) -> Result<Self, DecodeError> {
        let protocol_name = read_string(&mut buf)?;
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let protocol_level = buf.get_u8();
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let connect_flags = buf.get_u8();
        let clean_start = connect_flags.get_bit(1);
        let will_flag = connect_flags.get_bit(2);
        let will_qos = connect_flags.get_bits(3..=4);
        let will_retain = connect_flags.get_bit(5);
        let password_flag = connect_flags.get_bit(6);
        let user_name_flag = connect_flags.get_bit(7);
        if !will_flag && (will_qos != 0 || will_retain) {
            return Err(DecodeError::InvalidWillFlags);
        }
        if buf.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let keep_alive = buf.get_u16();
        let keep_alive = NonZeroU16::new(keep_alive);

        let mut session_expiry_interval = SessionExpiryInterval::default();
        let mut receive_maximum = ReceiveMaximum::default();
        let mut maximum_packet_size = MaximumPacketSize::default();
        let mut topic_alias_maximum = TopicAliasMaximum::default();
        let mut request_response_information = RequestResponseInformation::default();
        let mut request_problem_information = RequestProblemInformation::default();
        let mut user_property = UserProperty::default();
        let mut authentication_method = AuthenticationMethod::default();
        let mut authentication_data = AuthenticationData::default();

        read_properties(
            [
                &mut session_expiry_interval,
                &mut receive_maximum,
                &mut maximum_packet_size,
                &mut topic_alias_maximum,
                &mut request_response_information,
                &mut request_problem_information,
                &mut user_property,
                &mut authentication_method,
                &mut authentication_data,
            ],
            &mut buf,
        )?;

        let client_identifier = read_string(&mut buf)?;
        let client_identifier = if client_identifier.is_empty() {
            None
        } else if cfg!(feature = "strict")
            && (!(1..23).contains(&client_identifier.len())
                || client_identifier
                    .chars()
                    .any(|c| !c.is_ascii_alphabetic() && c.is_ascii_digit()))
        {
            return Err(DecodeError::InvalidClientIdentifier);
        } else {
            Some(client_identifier)
        };

        let will = will_flag
            .then(|| -> Result<_, DecodeError> {
                let mut will_delay_interval = WillDelayInterval::default();
                let mut payload_format_indicator = PayloadFormatIndicator::default();
                let mut message_expiry_interval = MessageExpiryInterval::default();
                let mut content_type = ContentType::default();
                let mut response_topic = ResponseTopic::default();
                let mut correlation_data = CorrelationData::default();
                let mut user_property = UserProperty::default();

                read_properties(
                    [
                        &mut will_delay_interval,
                        &mut payload_format_indicator,
                        &mut message_expiry_interval,
                        &mut content_type,
                        &mut response_topic,
                        &mut correlation_data,
                        &mut user_property,
                    ],
                    &mut buf,
                )?;

                let topic = read_string(&mut buf)?;
                let payload = read_binary_data(&mut buf)?;

                Ok(Will {
                    will_qos,
                    will_retain,
                    will_delay_interval,
                    payload_format_indicator,
                    message_expiry_interval,
                    content_type,
                    response_topic,
                    correlation_data,
                    user_property,
                    topic,
                    payload,
                })
            })
            .transpose()?;

        let user_name = user_name_flag.then(|| read_string(&mut buf)).transpose()?;

        let password = password_flag
            .then(|| read_binary_data(&mut buf))
            .transpose()?;

        Ok(Self {
            protocol_name,
            protocol_level,
            clean_start,
            keep_alive,
            session_expiry_interval,
            receive_maximum,
            maximum_packet_size,
            topic_alias_maximum,
            request_response_information,
            request_problem_information,
            user_property,
            authentication_method,
            authentication_data,
            client_identifier,
            will,
            user_name,
            password,
        })
    }

    pub fn encode(&self) -> Result<Bytes, EncodeError> {
        let mut buf = BytesMut::new();

        write_string(&self.protocol_name, &mut buf)?;
        buf.put_u8(self.protocol_level);
        let mut flags = 0;
        flags.set_bit(1, self.clean_start);
        if let Some(will) = self.will.as_ref() {
            flags.set_bit(2, true);
            flags.set_bits(3..=4, will.will_qos);
            flags.set_bit(5, will.will_retain);
        }
        flags.set_bit(6, self.password.is_some());
        flags.set_bit(7, self.user_name.is_some());
        buf.put_u8(flags);

        buf.put_u16(self.keep_alive.map(NonZeroU16::get).unwrap_or(0));

        write_properties(
            [
                &self.session_expiry_interval,
                &self.receive_maximum,
                &self.maximum_packet_size,
                &self.topic_alias_maximum,
                &self.request_response_information,
                &self.request_problem_information,
                &self.user_property,
                &self.authentication_method,
                &self.authentication_data,
            ],
            &mut buf,
        )?;

        write_string(self.client_identifier.as_deref().unwrap_or(""), &mut buf)?;

        if let Some(will) = self.will.as_ref() {
            write_properties(
                [
                    &will.will_delay_interval,
                    &will.payload_format_indicator,
                    &will.message_expiry_interval,
                    &will.content_type,
                    &will.response_topic,
                    &will.correlation_data,
                    &will.user_property,
                ],
                &mut buf,
            )?;

            write_string(&will.topic, &mut buf)?;
            write_binary_data(&will.payload, &mut buf)?;
        }

        if let Some(user_name) = self.user_name.as_deref() {
            write_string(user_name, &mut buf)?;
        }

        if let Some(password) = self.password.as_deref() {
            write_binary_data(password, &mut buf)?;
        }

        Ok(buf.freeze())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ConnectReasonCode {
    Success = 0x00,
    UnspecifiedError = 0x80,
    MalformedPacket = 0x81,
    ProtocolError = 0x82,
    ImplementationSpecificError = 0x83,
    UnsupportedProtocolVesrion = 0x84,
    ClientIdentifierNotValid = 0x85,
    BadUserNameOrPassword = 0x86,
    NotAuthorized = 0x87,
    ServerUnavailable = 0x88,
    ServerBusy = 0x89,
    Banned = 0x8a,
    BadAuthentificationMethod = 0x8c,
    TopicNameInvalid = 0x90,
    PacketTooLarge = 0x95,
    QuotaExceeded = 0x97,
    PayloadFormatInvalid = 0x99,
    RetainNotSupported = 0x9a,
    QoSNotSupported = 0x9b,
    UseAnotherServer = 0x9c,
    ServerMoved = 0x9d,
    ConnectionRateExceeded = 0x9f,
}

impl ConnectReasonCode {
    pub fn is_success(self) -> bool {
        !(self as u8).get_bit(7)
    }
}

#[derive(Debug)]
pub struct ConnAck {
    pub session_present: bool,
    pub connect_reason_code: ConnectReasonCode,
    pub session_expiry_interval: SessionExpiryInterval,
    pub receive_maximum: ReceiveMaximum,
    pub maximum_qos: MaximumQoS,
    pub retain_available: RetainAvailable,
    pub maximum_packet_size: MaximumPacketSize,
    pub assigned_client_identifier: AssignedClientIdentifier,
    pub topic_alias_maximum: TopicAliasMaximum,
    pub reason_string: ReasonString,
    pub user_property: UserProperty,
    pub wildcard_subscription_available: WildcardSubscriptionAvailable,
    pub subscription_identifiers_available: SubscriptionIdentifiersAvailable,
    pub shared_subscription_available: SharedSubscriptionAvailable,
    pub server_keep_aliave: ServerKeepAlive,
    pub response_information: ResponseInformation,
    pub server_reference: ServerReference,
    pub authentication_data: AuthenticationData,
    pub authentication_method: AuthenticationMethod,
}

impl ConnAck {
    fn decode(mut buf: impl Buf) -> Result<Self, DecodeError> {
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let connect_acknowledge_flags = buf.get_u8();
        let session_present = connect_acknowledge_flags.get_bit(0);

        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let connect_reason_code = buf.get_u8();
        let connect_reason_code = match connect_reason_code {
            0x00 => ConnectReasonCode::Success,
            0x80 => ConnectReasonCode::UnspecifiedError,
            0x81 => ConnectReasonCode::MalformedPacket,
            0x82 => ConnectReasonCode::ProtocolError,
            0x83 => ConnectReasonCode::ImplementationSpecificError,
            0x84 => ConnectReasonCode::UnsupportedProtocolVesrion,
            0x85 => ConnectReasonCode::ClientIdentifierNotValid,
            0x86 => ConnectReasonCode::BadUserNameOrPassword,
            0x87 => ConnectReasonCode::NotAuthorized,
            0x88 => ConnectReasonCode::ServerUnavailable,
            0x89 => ConnectReasonCode::ServerBusy,
            0x8a => ConnectReasonCode::Banned,
            0x8c => ConnectReasonCode::BadAuthentificationMethod,
            0x90 => ConnectReasonCode::TopicNameInvalid,
            0x95 => ConnectReasonCode::PacketTooLarge,
            0x97 => ConnectReasonCode::QuotaExceeded,
            0x99 => ConnectReasonCode::PayloadFormatInvalid,
            0x9a => ConnectReasonCode::RetainNotSupported,
            0x9b => ConnectReasonCode::QoSNotSupported,
            0x9c => ConnectReasonCode::UseAnotherServer,
            0x9d => ConnectReasonCode::ServerMoved,
            0x9f => ConnectReasonCode::ConnectionRateExceeded,
            other => return Err(DecodeError::UnknownReasonCode(other)),
        };

        let mut session_expiry_interval = SessionExpiryInterval::default();
        let mut receive_maximum = ReceiveMaximum::default();
        let mut maximum_qos = MaximumQoS::default();
        let mut retain_available = RetainAvailable::default();
        let mut maximum_packet_size = MaximumPacketSize::default();
        let mut assigned_client_identifier = AssignedClientIdentifier::default();
        let mut topic_alias_maximum = TopicAliasMaximum::default();
        let mut reason_string = ReasonString::default();
        let mut user_property = UserProperty::default();
        let mut wildcard_subscription_available = WildcardSubscriptionAvailable::default();
        let mut subscription_identifiers_available = SubscriptionIdentifiersAvailable::default();
        let mut shared_subscription_available = SharedSubscriptionAvailable::default();
        let mut server_keep_aliave = ServerKeepAlive::default();
        let mut response_information = ResponseInformation::default();
        let mut server_reference = ServerReference::default();
        let mut authentication_data = AuthenticationData::default();
        let mut authentication_method = AuthenticationMethod::default();

        read_properties(
            [
                &mut session_expiry_interval,
                &mut receive_maximum,
                &mut maximum_qos,
                &mut retain_available,
                &mut maximum_packet_size,
                &mut assigned_client_identifier,
                &mut topic_alias_maximum,
                &mut reason_string,
                &mut user_property,
                &mut wildcard_subscription_available,
                &mut subscription_identifiers_available,
                &mut shared_subscription_available,
                &mut server_keep_aliave,
                &mut response_information,
                &mut server_reference,
                &mut authentication_data,
                &mut authentication_method,
            ],
            &mut buf,
        )?;

        Ok(Self {
            session_present,
            connect_reason_code,
            session_expiry_interval,
            receive_maximum,
            maximum_qos,
            retain_available,
            maximum_packet_size,
            assigned_client_identifier,
            topic_alias_maximum,
            reason_string,
            user_property,
            wildcard_subscription_available,
            subscription_identifiers_available,
            shared_subscription_available,
            server_keep_aliave,
            response_information,
            server_reference,
            authentication_data,
            authentication_method,
        })
    }
}

#[derive(Debug)]
pub struct Publish {
    pub retain: bool,
    pub qos_level: QoSLevel,
    pub dup_flag: bool,
    pub topic_name: String,
    pub packet_identifier: Option<u16>,
    pub payload_format_indicator: PayloadFormatIndicator,
    pub message_expiry_interval: MessageExpiryInterval,
    pub topic_alias: TopicAlias,
    pub response_topic: ResponseTopic,
    pub correlation_data: CorrelationData,
    pub user_property: UserProperty,
    pub subscription_identifier: SubscriptionIdentifierMultiple,
    pub content_type: ContentType,
    pub data: Bytes,
}

impl Publish {
    fn decode(flags: u8, mut buf: impl Buf) -> Result<Self, DecodeError> {
        let retain = flags.get_bit(0);
        let qos_level = flags.get_bits(1..=2);
        let qos_level = match qos_level {
            0 => QoSLevel::AtMostOnce,
            1 => QoSLevel::AtLeastOnce,
            2 => QoSLevel::ExactlyOnce,
            _ => return Err(DecodeError::InvalidQoSLevel),
        };
        let dup_flag = flags.get_bit(3);

        let topic_name = read_string(&mut buf)?;

        let packet_identifier =
            if matches!(qos_level, QoSLevel::AtLeastOnce | QoSLevel::ExactlyOnce) {
                if buf.remaining() < 2 {
                    return Err(DecodeError::UnexpectedEof);
                }
                Some(buf.get_u16())
            } else {
                None
            };

        let mut payload_format_indicator = PayloadFormatIndicator::default();
        let mut message_expiry_interval = MessageExpiryInterval::default();
        let mut topic_alias = TopicAlias::default();
        let mut response_topic = ResponseTopic::default();
        let mut correlation_data = CorrelationData::default();
        let mut user_property = UserProperty::default();
        let mut subscription_identifier = SubscriptionIdentifierMultiple::default();
        let mut content_type = ContentType::default();
        read_properties(
            [
                &mut payload_format_indicator,
                &mut message_expiry_interval,
                &mut topic_alias,
                &mut response_topic,
                &mut correlation_data,
                &mut user_property,
                &mut subscription_identifier,
                &mut content_type,
            ],
            &mut buf,
        )?;

        let data = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            retain,
            qos_level,
            dup_flag,
            topic_name,
            packet_identifier,
            payload_format_indicator,
            message_expiry_interval,
            topic_alias,
            response_topic,
            correlation_data,
            user_property,
            subscription_identifier,
            content_type,
            data,
        })
    }

    pub fn encode(&self) -> Result<(u8, Bytes), EncodeError> {
        let mut flags = 0;
        flags.set_bit(0, self.retain);
        flags.set_bits(1..=2, self.qos_level as u8);
        flags.set_bit(3, self.dup_flag);

        let mut buf = BytesMut::new();

        write_string(&self.topic_name, &mut buf)?;

        if let Some(packet_identifier) = self.packet_identifier {
            assert!(matches!(
                self.qos_level,
                QoSLevel::AtLeastOnce | QoSLevel::ExactlyOnce
            ));
            buf.put_u16(packet_identifier);
        } else {
            assert_eq!(self.qos_level, QoSLevel::AtMostOnce);
        }

        write_properties(
            [
                &self.payload_format_indicator,
                &self.message_expiry_interval,
                &self.topic_alias,
                &self.response_topic,
                &self.correlation_data,
                &self.user_property,
                &self.subscription_identifier,
                &self.content_type,
            ],
            &mut buf,
        )?;

        buf.extend_from_slice(&self.data);

        Ok((flags, buf.freeze()))
    }
}

#[derive(Debug)]
pub struct Subscribe {
    pub packet_identifier: u16,
    pub subscription_identifier: SubscriptionIdentifierSingle,
    pub user_property: UserProperty,
    pub topic_filters: Vec<(String, u8)>,
}

impl Subscribe {
    fn encode(&self) -> Result<Bytes, EncodeError> {
        let mut buf = BytesMut::new();

        buf.put_u16(self.packet_identifier);

        write_properties(
            [&self.subscription_identifier, &self.user_property],
            &mut buf,
        )?;

        assert!(!self.topic_filters.is_empty());
        for (topic_filter, options_byte) in self.topic_filters.iter() {
            write_string(topic_filter, &mut buf)?;
            buf.put_u8(*options_byte);
        }

        Ok(buf.freeze())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum SubAckReasonCode {
    GrantedQoS0 = 0x00,
    GrantedQoS1 = 0x01,
    GrantedQoS2 = 0x02,
    UnspecifiedError = 0x80,
    ImplementationSpecificError = 0x83,
    NotAuthorized = 0x87,
    TopicFilterInvalid = 0x8f,
    PackedIdentifierInUse = 0x91,
    QuotaExceeded = 0x97,
    SharedSubscriptionsNotSupported = 0x9e,
    SubscriptionIdentifiersNotSupported = 0xa1,
    WildcardSubscriptionsNotSupported = 0xa2,
}

impl SubAckReasonCode {
    pub fn is_success(self) -> bool {
        !(self as u8).get_bit(7)
    }
}

#[derive(Debug)]
pub struct SubAck {
    pub packet_identifier: u16,
    pub reason_string: ReasonString,
    pub user_property: UserProperty,
    pub reason_codes: Vec<SubAckReasonCode>,
}

impl SubAck {
    fn decode(mut buf: impl Buf) -> Result<Self, DecodeError> {
        if buf.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let packet_identifier = buf.get_u16();

        let mut reason_string = ReasonString::default();
        let mut user_property = UserProperty::default();

        read_properties([&mut reason_string, &mut user_property], &mut buf)?;

        let mut reason_codes = Vec::new();
        while buf.has_remaining() {
            let reason_code = match buf.get_u8() {
                0x00 => SubAckReasonCode::GrantedQoS0,
                0x01 => SubAckReasonCode::GrantedQoS1,
                0x02 => SubAckReasonCode::GrantedQoS2,
                0x80 => SubAckReasonCode::UnspecifiedError,
                0x83 => SubAckReasonCode::ImplementationSpecificError,
                0x87 => SubAckReasonCode::NotAuthorized,
                0x8f => SubAckReasonCode::TopicFilterInvalid,
                0x91 => SubAckReasonCode::PackedIdentifierInUse,
                0x97 => SubAckReasonCode::QuotaExceeded,
                0x9e => SubAckReasonCode::SharedSubscriptionsNotSupported,
                0xa1 => SubAckReasonCode::SubscriptionIdentifiersNotSupported,
                0xa2 => SubAckReasonCode::WildcardSubscriptionsNotSupported,
                other => return Err(DecodeError::UnknownReasonCode(other)),
            };
            reason_codes.push(reason_code);
        }
        if reason_codes.is_empty() {
            return Err(DecodeError::UnexpectedEof);
        }

        Ok(Self {
            packet_identifier,
            reason_string,
            user_property,
            reason_codes,
        })
    }
}

#[derive(Debug)]
pub struct PingReq {}

impl PingReq {
    fn decode(_buf: impl Buf) -> Result<Self, DecodeError> {
        Ok(Self {})
    }

    fn encode(&self) -> Result<Bytes, EncodeError> {
        Ok(Bytes::new())
    }
}

#[derive(Debug)]
pub struct PingResp {}

impl PingResp {
    fn decode(_buf: impl Buf) -> Result<Self, DecodeError> {
        Ok(Self {})
    }

    fn encode(&self) -> Result<Bytes, EncodeError> {
        Ok(Bytes::new())
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DisconnectReasonCode(pub u8);

impl DisconnectReasonCode {
    pub const SUCCESS: Self = Self(0);
    pub const PROTOCOL_ERROR: Self = Self(0x82);
}

#[derive(Debug)]
pub struct Disconnect {
    pub disconnect_reason_code: DisconnectReasonCode,
    pub session_expiry_interval: SessionExpiryInterval,
    pub reason_string: ReasonString,
    pub user_property: UserProperty,
    pub server_reference: ServerReference,
}

impl Disconnect {
    fn decode(mut buf: impl Buf) -> Result<Self, DecodeError> {
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let disconnect_reason_code = buf.get_u8();
        let disconnect_reason_code = DisconnectReasonCode(disconnect_reason_code);

        let mut session_expiry_interval = SessionExpiryInterval::default();
        let mut reason_string = ReasonString::default();
        let mut user_property = UserProperty::default();
        let mut server_reference = ServerReference::default();

        if buf.has_remaining() {
            read_properties(
                [
                    &mut session_expiry_interval,
                    &mut reason_string,
                    &mut user_property,
                    &mut server_reference,
                ],
                buf,
            )?;
        }

        Ok(Self {
            disconnect_reason_code,
            session_expiry_interval,
            reason_string,
            user_property,
            server_reference,
        })
    }

    pub fn encode(&self) -> Result<Bytes, EncodeError> {
        let mut buf = BytesMut::new();

        buf.put_u8(self.disconnect_reason_code.0);

        write_properties(
            [
                &self.session_expiry_interval,
                &self.reason_string,
                &self.user_property,
                &self.server_reference,
            ],
            &mut buf,
        )?;

        Ok(buf.freeze())
    }
}
