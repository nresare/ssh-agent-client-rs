use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(Debug)]
pub enum Error {
    UnknownMessageType,
    InvalidData,
    IO(std::io::Error)
}

impl Display for Error {
    fn fmt(&self, _f: &mut Formatter<'_>) -> fmt::Result {
        todo!()
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::IO(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::IO(e)
    }
}


pub type Result<T> = std::result::Result<T, Error>;
