extern crate core;

use std::fmt::{Debug, Formatter};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use bytes::Bytes;

mod codec;
mod error;

pub use self::error::Error;
pub use self::error::Result;

#[allow(dead_code)]
pub struct Client<'a> {
    reader: Box<dyn Read + 'a>,
    writer: Box<dyn Write + 'a>,
}

#[derive(Debug, PartialEq)]
pub struct Identity {
    public_key: Bytes,
    comment: String,
}

impl <'a>Client<'a>{
    /// Constructs a Client connected to a unix socket referenced by the
    /// path socket.
    pub fn connect(socket: &Path) -> std::io::Result<Client> {
        let stream = UnixStream::connect(socket)?;
        Ok(Client{reader: Box::new( stream.try_clone()?), writer: Box::new(stream.try_clone()?) })
    }

    /// Lists the identities that the ssh-agent has access to.
    pub fn list_identities(&self) -> std::io::Result<&[Identity]> {
        todo!()
    }

    #[cfg(test)]
    fn from_reader_and_writer<R: Read + 'a, W: Write + 'a>(reader: R, writer: W) -> Client<'a> {
        Client{ reader: Box::new(reader), writer: Box::new(writer)}
    }
}

impl <'a>Debug for Client<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client").finish()
    }
}


#[cfg(test)]
mod tests {
    use std::path::Path;
    use super::Client;

    #[test]
    fn test_connect_failure() {
        let result = Client::connect(Path::new("/does/not/exist"));
        result.expect_err("Should return error");
    }

    #[test]
    fn test_list_identities() {
        let w = Vec::new();
        let r = b"\xde\xad\xbe\xef".as_slice();
        let client = Client::from_reader_and_writer(r, w);

        let _result = client.list_identities().unwrap();
    }
}
