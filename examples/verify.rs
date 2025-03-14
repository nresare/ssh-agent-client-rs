use bytes::BytesMut;
use rand::{rng, RngCore};
use signature::Verifier;
use ssh_agent_client_rs::{Client, Result};
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
    let key_bytes = read_to_string(Path::new(&path))?;
    let key = PublicKey::from_openssh(key_bytes.as_str())?;

    let agent_path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(agent_path.as_str()))?;

    let mut data = BytesMut::zeroed(32);
    rng().fill_bytes(&mut data);
    let data = data.freeze();

    let sig = client.sign(&key, &data)?;
    key.key_data()
        .verify(data.as_ref(), &sig)
        .expect("verification failed");
    println!(
        "Successfully verified a signature from the agent '{}' with the public key in '{}'",
        agent_path, path,
    );
    Ok(())
}
