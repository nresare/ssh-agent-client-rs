use std::fmt;
use std::fmt::{Display, Formatter};
use std::num::TryFromIntError;

#[derive(Debug)]
pub enum Error {
    UnknownMessageType,
    InvalidData(Option<String>),
    IO(Option<String>, std::io::Error),
    SSHKey(ssh_key::Error),
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

impl From<TryFromIntError> for Error {
    fn from(_: TryFromIntError) -> Self {
        Error::InvalidData(Some("Value doesn't fit".to_string()))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
