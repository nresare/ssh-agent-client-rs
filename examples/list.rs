use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::{Client, Result};
use std::env;
use std::path::Path;

/// This example lists the hashes of keys that the ssh-agent that listens to
/// the socket referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add -l`
fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;
    let identities = client.list_all_identities()?;
    if identities.is_empty() {
        println!("The agent has no identities.");
    } else {
        identities.iter().for_each(print);
    }
    Ok(())
}

fn print(identity: &Identity) {
    let (public_key, comment, suffix) = match identity {
        Identity::PublicKey(key) => (key.key_data(), key.comment(), ""),
        Identity::Certificate(cert) => (cert.public_key(), cert.comment(), "-cert"),
    };
    let fingerprint = public_key.fingerprint(Default::default());
    let algo = public_key.algorithm();
    println!("{fingerprint} {comment} {algo}{suffix}")
}
