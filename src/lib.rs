extern crate core;

use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use bytes::Bytes;
use crate::codec::{Message, read_message, write_message};

mod codec;
mod error;
#[cfg(test)]
mod testutil;
pub mod bits;

pub use self::error::Error;
pub use self::error::Result;

pub struct Client {
    reader: Box<dyn Read>,
    writer: Box<dyn Write>,
}

#[derive(Debug, PartialEq)]
pub struct Identity<> {
    pub public_key: Bytes,
    pub comment: String,
}

impl Client {
    /// Constructs a Client connected to a unix socket referenced by the
    /// path socket.
    pub fn connect(path: &Path) -> Result<Client> {
        let socket = UnixStream::connect(path)?;
        Ok(Client{reader: Box::new(socket.try_clone()?), writer: Box::new(socket.try_clone()?) })
    }

    /// Lists the identities that the ssh-agent has access to.
    pub fn list_identities(&mut self) -> Result<Vec<Identity>> {
        write_message(&mut self.writer, Message::RequestIdentities)?;
        let message =read_message(&mut self.reader)?;
        match message {
            Message::IdentitiesAnswer(identities) => Ok(identities),
            _ => Err(Error::UnknownMessageType)
        }
    }

    #[cfg(test)]
    fn from_reader_and_writer(reader: Box<dyn Read>, writer: Box<dyn Write>) -> Client {
        Client{reader, writer}
    }
}

impl Debug for Client {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish()
    }
}


#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use crate::Identity;
    use crate::testutil::reader;
    use super::Client;

    #[test]
    fn test_list_identities() {
        // given
        let w = Vec::new();
        let r = reader(b"\0\0\0\x17\x0c\0\0\0\x01\0\0\0\x03key\0\0\0\x07comment");
        let mut client = Client::from_reader_and_writer(Box::new(r),Box::new(w));

        // when
        let result = client.list_identities().unwrap();

        // then
        assert_eq!(
            vec![Identity{public_key: Bytes::from_static(b"key"), comment: "comment".to_string()}],
            result
        );
    }
}
