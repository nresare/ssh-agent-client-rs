//! Error types
use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::TryFromIntError;

/// A Result variant with this module's `Error` as its error type
pub type Result<T> = std::result::Result<T, Error>;

/// This enum represents the different Errors that might be returned
/// by this crate.
#[derive(Debug)]
pub enum Error {
    /// A message with an unknown type field was received.
    UnknownMessageType,
    /// An invalid message was received, optionally holding a String with additional detail.
    InvalidData(Option<String>),
    /// An operation returned a std::io::Error, enclosed with in the value optionally
    /// along with a String detailing the context when the error occurred.
    IO(Option<String>, std::io::Error),
    /// An operation returned a ssh_key::Error wrapped in this variant.
    SSHKey(ssh_key::Error),
    /// An operation returned the Failure message from the remote ssh-agent.
    RemoteFailure,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::IO(_, ref e) => Some(e),
            Error::SSHKey(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO(None, e)
    }
}

impl From<ssh_key::Error> for Error {
    fn from(e: ssh_key::Error) -> Self {
        Error::SSHKey(e)
    }
}

impl From<signature::Error> for Error {
    fn from(_: signature::Error) -> Self {
        Error::InvalidData(Some(String::from("Failed to parse signature")))
    }
}

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::InvalidData(Some("Value doesn't fit".to_string()))
    }
}
