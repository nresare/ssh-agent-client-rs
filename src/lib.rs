extern crate core;

use crate::codec::{read_message, write_message, ReadMessage, WriteMessage};
use ssh_key::{PrivateKey, PublicKey};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

pub mod bits;
mod codec;
mod error;

pub use self::error::Error;
pub use self::error::Result;

pub trait ReadWrite: Read + Write {}

pub struct Client {
    socket: Box<dyn ReadWrite>,
}

impl ReadWrite for UnixStream {}

impl Client {
    /// Constructs a Client connected to a unix socket referenced by the path socket.
    pub fn connect(path: &Path) -> Result<Client> {
        let socket = Box::new(UnixStream::connect(path)?);
        Ok(Client { socket })
    }

    pub fn with_socket_like(socket_like: Box<dyn ReadWrite>) -> Client {
        Client {
            socket: socket_like,
        }
    }

    /// Lists the identities that the ssh-agent has access to.
    pub fn list_identities(&mut self) -> Result<Vec<PublicKey>> {
        write_message(&mut self.socket, WriteMessage::RequestIdentities)?;
        let response = read_message(&mut self.socket)?;
        match response {
            ReadMessage::Identities(identities) => Ok(identities),
            _ => Err(Error::UnknownMessageType),
        }
    }

    /// Adds an identity to the ssh-agent
    pub fn add_identity(&mut self, key: PrivateKey) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::AddIdentity(Box::new(key)))?;
        self.expect_success()
    }

    /// Removes an identity from the ssh-agent
    pub fn remove_identity(&mut self, key: PrivateKey) -> Result<()> {
        write_message(
            &mut self.socket,
            WriteMessage::RemoveIdentity(Box::new(key)),
        )?;
        self.expect_success()
    }

    /// Removes an identity from the ssh-agent
    pub fn remove_all_identities(&mut self) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::RemoveAllIdentities)?;
        self.expect_success()
    }

    fn expect_success(&mut self) -> Result<()> {
        let response = read_message(&mut self.socket)?;
        match response {
            ReadMessage::Success => Ok(()),
            ReadMessage::Failure => Err(Error::RemoteFailure),
            _ => Err(Error::InvalidData(Some("Unexpected response".to_string()))),
        }
    }
}
