use bytes::BytesMut;
use getrandom::getrandom;
use signature::Verifier;
use ssh_agent_client_rs::{Client, Error, Result};
use ssh_key::PublicKey;
use std::env;
use std::fs::read_to_string;
use std::path::Path;

/// This example tests whether the ssh-agent referenced by the path
/// in the SSH_AUTH_SOCK environment variable holds a usable private
/// key that corresponds to PUBLIC_KEY much like the command
/// `ssh-add -K PUBLIC_KEY`
fn main() -> Result<()> {
    let path = env::args().nth(1).expect("argument PUBLIC_KEY missing");
    let key_bytes = read_to_string(Path::new(&path))
        .map_err(|e| Error::IO(Some(format!("Failed to read from {}", path)), e))?;
    let key = PublicKey::from_openssh(key_bytes.as_str())?;

    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;

    let mut data = BytesMut::zeroed(32);
    getrandom(&mut data[..]).expect("Failed to obtain random data to sign");
    let data = data.freeze();

    let sig = client.sign(&key, data.clone())?;

    key.key_data()
        .verify(data.as_ref(), &sig)
        .expect("verification failed");
    Ok(())
}
