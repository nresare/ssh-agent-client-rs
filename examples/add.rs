use std::env;
use std::fs::read;
use std::path::Path;
use ssh_key::PrivateKey;
use ssh_agent_client_rs::{Client, Error, Result};

/// This example adds a private key to the ssh agent that listens to the socket
/// referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add KEY`
fn main() -> Result<()> {
    let path = env::args().nth(1).expect("argument KEY missing");
    let key_bytes = read(Path::new(&path)).map_err(|e| {
        Error::IO(Some(format!("Failed to read from {}", path)), e)
    })?;
    let key = PrivateKey::from_openssh(key_bytes)?;

    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;

    client.add_identity(key)
}
