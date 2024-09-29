use std::num::{NonZeroU16, NonZeroU32};

use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

use crate::{
    read_binary_data, read_string, read_variable_byte_integer, write_binary_data, write_string,
    write_variable_byte_integer, DecodeError, EncodeError,
};

pub fn read_properties<const SIZE: usize>(
    mut properties: [&mut dyn Property; SIZE],
    mut buf: impl Buf,
) -> Result<(), DecodeError> {
    let property_length = read_variable_byte_integer(&mut buf)?;
    let mut buf = buf.take(usize::try_from(property_length).unwrap());
    while buf.has_remaining() {
        let property_id = read_variable_byte_integer(&mut buf)?;
        trace!(property_id, "reading property");
        let property = properties
            .iter_mut()
            .find(|prop| prop.property_id() == property_id)
            .ok_or(DecodeError::UnknownPropertyId(property_id))?;
        property.read(&mut buf)?;
    }
    Ok(())
}

pub fn write_properties<const SIZE: usize>(
    properties: [&dyn Property; SIZE],
    mut buf: impl BufMut,
) -> Result<(), EncodeError> {
    let mut properties_buf = BytesMut::new();
    properties
        .into_iter()
        .try_for_each(|prop| prop.write(&mut properties_buf))?;
    write_variable_byte_integer(properties_buf.len() as u32, &mut buf)?;
    buf.put(properties_buf);
    Ok(())
}

pub trait Property {
    fn property_id(&self) -> u32;
    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError>;
    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError>;
}

#[derive(Default, Debug)]
pub struct PayloadFormatIndicator {
    value: Option<PayloadFormat>,
}

#[derive(Clone, Copy, Debug)]
pub enum PayloadFormat {
    Unspecified,
    Utf8,
}

impl PayloadFormatIndicator {
    pub fn get(&self) -> PayloadFormat {
        self.value.unwrap_or(PayloadFormat::Unspecified)
    }
}

impl Property for PayloadFormatIndicator {
    fn property_id(&self) -> u32 {
        0x1
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => PayloadFormat::Unspecified,
            1 => PayloadFormat::Utf8,
            _ => return Err(DecodeError::InvalidPropertyValue(self.property_id())),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(match value {
            PayloadFormat::Unspecified => 0,
            PayloadFormat::Utf8 => 1,
        });
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct MessageExpiryInterval {
    value: Option<u32>,
}

impl MessageExpiryInterval {
    pub fn get(&self) -> Option<u32> {
        self.value
    }
}

impl Property for MessageExpiryInterval {
    fn property_id(&self) -> u32 {
        0x2
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        self.value = Some(buf.get_u32());
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u32(value);
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ContentType {
    value: Option<String>,
}

impl ContentType {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for ContentType {
    fn property_id(&self) -> u32 {
        0x3
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ResponseTopic {
    value: Option<String>,
}

impl ResponseTopic {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for ResponseTopic {
    fn property_id(&self) -> u32 {
        0x8
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct CorrelationData {
    value: Option<Bytes>,
}

impl CorrelationData {
    pub fn get(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

impl Property for CorrelationData {
    fn property_id(&self) -> u32 {
        0x9
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_binary_data(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_binary_data(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct SubscriptionIdentifierSingle {
    value: Option<NonZeroU32>,
}

impl SubscriptionIdentifierSingle {
    pub fn new(value: NonZeroU32) -> Self {
        Self { value: Some(value) }
    }

    pub fn get(&self) -> Option<NonZeroU32> {
        self.value
    }
}

impl Property for SubscriptionIdentifierSingle {
    fn property_id(&self) -> u32 {
        0xb
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_variable_byte_integer(buf)?;
        let value = NonZeroU32::new(value)
            .ok_or_else(|| DecodeError::InvalidPropertyValue(self.property_id()))?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_variable_byte_integer(value.get(), &mut *buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct SubscriptionIdentifierMultiple {
    values: Vec<NonZeroU32>,
}

impl SubscriptionIdentifierMultiple {
    pub fn get(&self) -> &[NonZeroU32] {
        &self.values
    }
}

impl Property for SubscriptionIdentifierMultiple {
    fn property_id(&self) -> u32 {
        0xb
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        let value = read_variable_byte_integer(buf)?;
        let value = NonZeroU32::new(value)
            .ok_or_else(|| DecodeError::InvalidPropertyValue(self.property_id()))?;
        self.values.push(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        for value in self.values.iter().copied() {
            write_variable_byte_integer(self.property_id(), &mut *buf)?;
            write_variable_byte_integer(value.get(), &mut *buf)?;
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct SessionExpiryInterval {
    value: Option<u32>,
}

impl SessionExpiryInterval {
    pub fn new(value: u32) -> SessionExpiryInterval {
        SessionExpiryInterval { value: Some(value) }
    }

    pub fn get(&self) -> u32 {
        self.value.unwrap_or(0)
    }
}

impl Property for SessionExpiryInterval {
    fn property_id(&self) -> u32 {
        0x11
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        self.value = Some(buf.get_u32());
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u32(value);
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct AssignedClientIdentifier {
    value: Option<String>,
}

impl AssignedClientIdentifier {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for AssignedClientIdentifier {
    fn property_id(&self) -> u32 {
        0x12
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ServerKeepAlive {
    value: Option<Option<NonZeroU16>>,
}

impl ServerKeepAlive {
    pub fn get(&self) -> Option<Option<NonZeroU16>> {
        self.value
    }
}

impl Property for ServerKeepAlive {
    fn property_id(&self) -> u32 {
        0x13
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        self.value = Some(NonZeroU16::new(buf.get_u16()));
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u16(value.map_or(0, NonZeroU16::get));
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct AuthenticationMethod {
    value: Option<String>,
}

impl AuthenticationMethod {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for AuthenticationMethod {
    fn property_id(&self) -> u32 {
        0x15
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct AuthenticationData {
    value: Option<Bytes>,
}

impl AuthenticationData {
    pub fn get(&self) -> Option<&[u8]> {
        self.value.as_deref()
    }
}

impl Property for AuthenticationData {
    fn property_id(&self) -> u32 {
        0x16
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_binary_data(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_binary_data(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct RequestProblemInformation {
    value: Option<bool>,
}

impl RequestProblemInformation {
    pub fn get(&self) -> bool {
        self.value.unwrap_or(false)
    }
}

impl Property for RequestProblemInformation {
    fn property_id(&self) -> u32 {
        0x17
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::InvalidPropertyValue(self.property_id())),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(u8::from(value));
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct WillDelayInterval {
    value: Option<u32>,
}

impl WillDelayInterval {
    pub fn get(&self) -> u32 {
        self.value.unwrap_or(0)
    }
}

impl Property for WillDelayInterval {
    fn property_id(&self) -> u32 {
        0x18
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        self.value = Some(buf.get_u32());
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u32(value);
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct RequestResponseInformation {
    value: Option<bool>,
}

impl RequestResponseInformation {
    pub fn get(&self) -> bool {
        self.value.unwrap_or(false)
    }
}

impl Property for RequestResponseInformation {
    fn property_id(&self) -> u32 {
        0x19
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::InvalidPropertyValue(self.property_id())),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(u8::from(value));
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ResponseInformation {
    value: Option<String>,
}

impl ResponseInformation {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for ResponseInformation {
    fn property_id(&self) -> u32 {
        0x1a
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ServerReference {
    value: Option<String>,
}

impl ServerReference {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for ServerReference {
    fn property_id(&self) -> u32 {
        0x1c
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ReasonString {
    value: Option<String>,
}

impl ReasonString {
    pub fn get(&self) -> Option<&str> {
        self.value.as_deref()
    }
}

impl Property for ReasonString {
    fn property_id(&self) -> u32 {
        0x1f
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        let value = read_string(buf)?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value.as_deref() {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        write_string(value, buf)?;
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct ReceiveMaximum {
    value: Option<u16>,
}

impl ReceiveMaximum {
    pub fn get(&self) -> u16 {
        self.value.unwrap_or(0xffff)
    }
}

impl Property for ReceiveMaximum {
    fn property_id(&self) -> u32 {
        0x21
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        self.value = Some(buf.get_u16());
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u16(value);
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct TopicAliasMaximum {
    value: Option<u16>,
}

impl TopicAliasMaximum {
    pub fn get(&self) -> u16 {
        self.value.unwrap_or(0)
    }
}

impl Property for TopicAliasMaximum {
    fn property_id(&self) -> u32 {
        0x22
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        self.value = Some(buf.get_u16());
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u16(value);
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct TopicAlias {
    value: Option<NonZeroU16>,
}

impl TopicAlias {
    pub fn get(&self) -> Option<NonZeroU16> {
        self.value
    }
}

impl Property for TopicAlias {
    fn property_id(&self) -> u32 {
        0x23
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 2 {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = buf.get_u16();
        let value = NonZeroU16::new(value)
            .ok_or_else(|| DecodeError::InvalidPropertyValue(self.property_id()))?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u16(value.get());
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct MaximumQoS {
    value: Option<u8>,
}

impl MaximumQoS {
    pub fn get(&self) -> u8 {
        self.value.unwrap_or(2)
    }
}

impl Property for MaximumQoS {
    fn property_id(&self) -> u32 {
        0x24
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = buf.get_u8();
        if !matches!(value, 0 | 1) {
            return Err(DecodeError::InvalidPropertyValue(self.property_id()));
        }
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(value);
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct RetainAvailable {
    value: Option<bool>,
}

impl RetainAvailable {
    pub fn get(&self) -> bool {
        self.value.unwrap_or(true)
    }
}

impl Property for RetainAvailable {
    fn property_id(&self) -> u32 {
        0x25
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::UnexpectedEof),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(u8::from(value));
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct UserProperty {
    values: Vec<(String, String)>,
}

impl UserProperty {
    pub fn get(&self) -> impl Iterator<Item = (&str, &str)> {
        self.values.iter().map(|(name, value)| (&**name, &**value))
    }
}

impl Property for UserProperty {
    fn property_id(&self) -> u32 {
        0x26
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        let name = read_string(&mut *buf)?;
        let value = read_string(buf)?;
        self.values.push((name, value));
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        for (name, value) in self.values.iter() {
            write_variable_byte_integer(self.property_id(), &mut *buf)?;
            write_string(name, &mut *buf)?;
            write_string(value, &mut *buf)?;
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct MaximumPacketSize {
    value: Option<NonZeroU32>,
}

impl MaximumPacketSize {
    pub fn new(value: Option<NonZeroU32>) -> Self {
        Self { value }
    }

    pub fn get(&self) -> Option<NonZeroU32> {
        self.value
    }
}

impl Property for MaximumPacketSize {
    fn property_id(&self) -> u32 {
        0x27
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if buf.remaining() < 4 {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = NonZeroU32::new(buf.get_u32())
            .ok_or_else(|| DecodeError::InvalidPropertyValue(self.property_id()))?;
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u32(value.get());
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct WildcardSubscriptionAvailable {
    value: Option<bool>,
}

impl WildcardSubscriptionAvailable {
    pub fn get(&self) -> bool {
        self.value.unwrap_or(true)
    }
}

impl Property for WildcardSubscriptionAvailable {
    fn property_id(&self) -> u32 {
        0x28
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::UnexpectedEof),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(u8::from(value));
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct SubscriptionIdentifiersAvailable {
    value: Option<bool>,
}

impl SubscriptionIdentifiersAvailable {
    pub fn get(&self) -> bool {
        self.value.unwrap_or(true)
    }
}

impl Property for SubscriptionIdentifiersAvailable {
    fn property_id(&self) -> u32 {
        0x29
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::UnexpectedEof),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(u8::from(value));
        Ok(())
    }
}

#[derive(Default, Debug)]
pub struct SharedSubscriptionAvailable {
    value: Option<bool>,
}

impl SharedSubscriptionAvailable {
    pub fn get(&self) -> bool {
        self.value.unwrap_or(true)
    }
}

impl Property for SharedSubscriptionAvailable {
    fn property_id(&self) -> u32 {
        0x2a
    }

    fn read(&mut self, buf: &mut dyn Buf) -> Result<(), DecodeError> {
        if self.value.is_some() {
            return Err(DecodeError::DuplicateProperty(self.property_id()));
        }
        if !buf.has_remaining() {
            return Err(DecodeError::UnexpectedEof);
        }
        let value = match buf.get_u8() {
            0 => false,
            1 => true,
            _ => return Err(DecodeError::UnexpectedEof),
        };
        self.value = Some(value);
        Ok(())
    }

    fn write(&self, buf: &mut dyn BufMut) -> Result<(), EncodeError> {
        let value = if let Some(value) = self.value {
            value
        } else {
            return Ok(());
        };
        write_variable_byte_integer(self.property_id(), &mut *buf)?;
        buf.put_u8(u8::from(value));
        Ok(())
    }
}
