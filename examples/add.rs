use ssh_agent_client_rs::{Client, Result};
use ssh_key::PrivateKey;
use std::env;
use std::fs::read;
use std::path::Path;

/// This example adds a private key to the ssh agent that listens to the socket
/// referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add KEY`
fn main() -> Result<()> {
    let path = env::args().nth(1).expect("argument KEY missing");
    let key = PrivateKey::from_openssh(read(Path::new(&path))?)?;

    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;

    client.add_identity(&key)
}
