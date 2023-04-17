use std::env;
use std::path::Path;
use ssh_key::public::PublicKey;
use ssh_agent_client_rs::{Client, Identity, Result};

fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("Missing env variable");
    let mut client = Client::connect(Path::new(path.as_str()))?;
    for identity in client.list_identities()?.iter() {
        to_string(&identity);
    };
    Ok(())
}

fn to_string(identity: &Identity) {
    let key = PublicKey::from_bytes(identity.public_key.as_ref()).expect("failed to parse public key");
    println!("256 {} {} {}", key.fingerprint(Default::default()), identity.comment, key.algorithm().to_string())
}