use ssh_agent_client_rs::Identity;
use ssh_agent_client_rs::{Client, Result};
use ssh_key::public::PublicKey;
use std::env;
use std::path::Path;

/// This example lists the hashes of keys that the ssh-agent that listens to
/// the socket referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add -l`
fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;
    let identities = client.list_all_identities()?;
    if identities.len() < 1 {
        println!("The agent has no identities.");
    } else {
        identities.iter().for_each(|i| print(i));
    }
    Ok(())
}

fn print(identity: &Identity) {
    match identity {
        Identity::PublicKey(key) => print_pubkey(&key),
        Identity::Certificate(cert) => print_certificate(&cert),
    }
}
fn print_certificate(cert: &ssh_key::Certificate) {
    println!(
        "{} {} {}",
        cert.public_key().fingerprint(Default::default()),
        cert.comment(),
        cert.algorithm().to_string(),
    );
}
fn print_pubkey(key: &PublicKey) {
    println!(
        "{} {} {}",
        key.fingerprint(Default::default()),
        key.comment(),
        key.algorithm().to_string(),
    )
}
