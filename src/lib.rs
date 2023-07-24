//! # ssh-agent-client-rs
//!
//! An ssh-agent client implementation in rust, aiming to provide a robust,
//! well tested and easy to use API to interact with an ssh-agent.
//!
//! # Examples
//! ```no_run
//! use ssh_agent_client_rs::Client;
//! # use std::env;
//! # use std::path::Path;
//! # use ssh_agent_client_rs::Error;
//! use ssh_key::PublicKey;
//!
//! # let env = env::var("SSH_AUTH_SOCK").unwrap();
//! # let path_to_ssh_auth_socket = Path::new(env.as_str());
//! let mut client = Client::connect(path_to_ssh_auth_socket).expect("failed to connect");
//!
//! // List the identities that the connected ssh-agent makes available
//! let identities: Vec<PublicKey> = client.list_identities().expect("failed to list identities");
//! ```

use crate::codec::{read_message, write_message, ReadMessage, WriteMessage};
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;

mod codec;
mod error;

pub use self::error::Error;
pub use self::error::Result;

/// A combination of the std::io::Read and std::io::Write traits.
pub trait ReadWrite: Read + Write {}

/// A Client instance is an object that can be used to interact with a ssh-agent,
/// typically using a Unix socket
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

    /// Constructs a Client backed by an implementation of ReadWrite, mainly useful for
    /// testing.
    pub fn with_read_write(read_write: Box<dyn ReadWrite>) -> Client {
        Client { socket: read_write }
    }

    /// Lists the identities that has been added to the connected ssh-agent.
    pub fn list_identities(&mut self) -> Result<Vec<PublicKey>> {
        write_message(&mut self.socket, WriteMessage::RequestIdentities)?;
        match read_message(&mut self.socket)? {
            ReadMessage::Identities(identities) => Ok(identities),
            _ => Err(Error::UnknownMessageType),
        }
    }

    /// Adds an identity to the connected ssh-agent.
    pub fn add_identity(&mut self, key: &PrivateKey) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::AddIdentity(key))?;
        self.expect_success()
    }

    /// Removes an identity from the connected ssh-agent.
    pub fn remove_identity(&mut self, key: &PrivateKey) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::RemoveIdentity(key))?;
        self.expect_success()
    }

    /// Removes all identities from the connected ssh-agent.
    pub fn remove_all_identities(&mut self) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::RemoveAllIdentities)?;
        self.expect_success()
    }

    /// Sign bytes with the given public_key. For now, sign requests with RSA
    /// keys are hard coded to use the SHA-512 hash algorithm.
    pub fn sign(&mut self, key: &PublicKey, data: &[u8]) -> Result<Signature> {
        write_message(&mut self.socket, WriteMessage::Sign(key, data))?;
        match read_message(&mut self.socket)? {
            ReadMessage::Signature(sig) => Ok(sig),
            ReadMessage::Failure => Err(Error::RemoteFailure),
            _ => Err(Error::UnknownMessageType),
        }
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
