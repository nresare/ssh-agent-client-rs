use bytes::BytesMut;
use rand::{rng, RngCore};
use signature::Verifier;
use ssh_agent_client_rs::Client;
use ssh_key::{Certificate, PublicKey};
use std::env;
use std::fs::read_to_string;
use std::path::Path;

/// This example tests whether the ssh-agent referenced by the path
/// in the SSH_AUTH_SOCK environment variable holds a usable private
/// key that corresponds to PUBLIC_KEY much like the command
/// `ssh-add -T PUBLIC_KEY_PATH`
fn main() -> anyhow::Result<()> {
    let path = env::args()
        .nth(1)
        .expect("argument PUBLIC_KEY_PATH missing");

    let identity = read_to_string(Path::new(&path))?;
    let key_type = identity.split(" ").next().expect("Invalid key format");
    let agent_path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(agent_path.as_str()))?;

    let mut data = BytesMut::zeroed(32);
    rng().fill_bytes(&mut data);
    let data = data.freeze();

    if key_type.contains("-cert-") {
        let cert = Certificate::from_openssh(&identity)?;
        let sig = client.sign(&cert, &data)?;
        cert.public_key().verify(&data, &sig)?;
    } else {
        let key = PublicKey::from_openssh(&identity)?;
        let sig = client.sign(&key, &data)?;
        key.key_data().verify(&data, &sig)?;
    }
    Ok(())
}
