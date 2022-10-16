use thiserror::Error;
use tokio::time::error::Elapsed;

use crate::packet::{ConnectReasonCode, DisconnectReasonCode, SubAckReasonCode};

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Decode(#[from] DecodeError),
    #[error(transparent)]
    Encode(#[from] EncodeError),
    #[error("timeout")]
    Timeout,
    #[error("unexpected packet")]
    UnexpectedPacket,
    #[error("ran out of packet identifiers")]
    OutOfPacketIdentifiers,
    #[error("subscription failed {0:?}")]
    SubscriptionFailed(SubAckReasonCode),
    #[error("connect failed, reason code: {0:?}")]
    ConnectFailed(ConnectReasonCode),
    #[error("disconnected, reason code: {0:?}")]
    Disconnected(DisconnectReasonCode),
}

impl From<Elapsed> for Error {
    fn from(_: Elapsed) -> Self {
        Error::Timeout
    }
}

#[derive(Error, Debug)]
pub enum DecodeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("variable byte int too long")]
    VariableByteIntTooLong,
    #[error("packet too long: {0} bytes")]
    PacketTooLong(u32),
    #[error("unexpected end of file")]
    UnexpectedEof,
    #[error("unknown property {0}")]
    UnknownPropertyId(u32),
    #[error("duplicate property {0}")]
    DuplicateProperty(u32),
    #[error("invalid value for property {0}")]
    InvalidPropertyValue(u32),
    #[error("malformed string")]
    MalformedString,
    #[error("invalid client identifier")]
    InvalidClientIdentifier,
    #[error("invalid will flags")]
    InvalidWillFlags,
    #[error("too much data")]
    TooMuchData,
    #[error("unknown reason code {0}")]
    UnknownReasonCode(u8),
    #[error("unknown packet type {0}")]
    UnknownPacketType(u8),
    #[error("invalid QoS")]
    InvalidQoSLevel,
}

#[derive(Error, Debug)]
pub enum EncodeError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("variable byte int too long")]
    VariableByteIntTooLong(u32),
    #[error("packet too long: {0} bytes")]
    PacketTooLong(u32),
    #[error("string too long: {0} bytes")]
    StringTooLong(usize),
    #[error("binary data too long: {0} bytes")]
    BinaryDataTooLong(usize),
}
