use ssh_agent_client_rs::{Client, Result};
use std::env;
use std::path::Path;

/// This example removes all private keys from the ssh agent that listens to the socket
/// referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add -D`
fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;
    client.remove_all_identities()?;
    Ok(())
}
