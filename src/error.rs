//! Error types
use thiserror::Error;

/// A Result variant with this module's `Error` as its error type
pub type Result<T> = std::result::Result<T, Error>;

/// This enum represents the different Errors that might be returned
/// by this crate.
#[derive(Error, Debug)]
pub enum Error {
    /// A message with an unknown type field was received.
    #[error("Received an unknown message type: {0}")]
    UnknownMessageType(u8),
    /// There was a failure parsing the message
    #[error("An invalid message was received: {0}")]
    InvalidMessage(String),
    /// There was a failure connecting to git-bash ssh-agent
    #[error("Connection to git-bash ssh-agent error: {0}")]
    GitBashErrorMessage(String),
    /// There was an io::Error communicating with the agent
    #[error("An error occurred communicating with the agent")]
    AgentCommunicationError(#[from] std::io::Error),
    /// An operation returned a ssh_key::Error wrapped in this variant.
    #[error("An ssh key operation failed")]
    SSHKey(#[from] ssh_key::Error),
    #[error("An ssh encoding operation failed")]
    SSHEncoding(#[from] ssh_encoding::Error),
    #[error("The remote ssh agent returned the failure message")]
    /// An operation returned the Failure message from the remote ssh-agent.
    RemoteFailure,
}
