use std::env;
use std::path::Path;
use ssh_key::public::PublicKey;
use ssh_agent_client_rs::{Client, Identity, Result};
use ssh_agent_client_rs::bits::key_bits;

/// This example lists the hashes of keys that the ssh-agent that listens to
/// the socket referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add -l`
fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;
    for identity in client.list_identities()?.iter() {
        print(&identity);
    };
    Ok(())
}

fn print(identity: &Identity) {
    let key = PublicKey::from_bytes(identity.public_key.as_ref())
        .expect("failed to parse public key");
    println!("{} {} {} {}",
        key_bits(&key),
        key.fingerprint(Default::default()),
        identity.comment,
        key.algorithm().to_string()
    )
}
