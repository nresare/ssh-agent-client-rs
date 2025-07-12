use bytes::BytesMut;
use rand::{rng, RngCore};
use signature::Verifier;
use ssh_agent_client_rs::{Client, Identity, Result};
use ssh_key::public::KeyData;
use ssh_key::{Certificate, PublicKey, Signature};
use std::env;
use std::fs::read_to_string;
use std::path::Path;

/// This example tests whether the ssh-agent referenced by the path
/// in the SSH_AUTH_SOCK environment variable holds a usable private
/// key that corresponds to PUBLIC_KEY much like the command
/// `ssh-add -K PUBLIC_KEY`
/// It can use either a public key or a certificate as an argument.
/// If the second argument is "certificate" it will use a certificate,
fn main() -> Result<()> {
    let path_or_certificate = env::args().nth(1).expect("argument PUBLIC_KEY missing");
    // Let's add a second optional argument that tells us if we want to use a certificate
    // or a public key. If the argument is "certificate" it will not expect a path to a public key
    // but the OpenSSH string representation of a certificate as given by ssh-add -L
    // otherwise we will use a public key.
    let key_type = env::args()
        .nth(2)
        .unwrap_or_else(|| String::from("public_key"));

    let identity: &Identity = &match key_type.as_str() {
        "certificate" => {
            println!("Using a certificate");
            Certificate::from_openssh(path_or_certificate.as_str())
                .expect("failed to parse certificate from argument")
                .into()
        }
        "public_key" => {
            println!("Using a public key");
            let key_bytes = read_to_string(Path::new(&path_or_certificate))?;
            PublicKey::from_openssh(key_bytes.as_str())?.into()
        }
        _ => panic!("Unknown key type: {}", key_type),
    };

    let agent_path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(agent_path.as_str()))?;

    let mut data = BytesMut::zeroed(32);
    rng().fill_bytes(&mut data);
    let data = data.freeze();

    let sig = client.sign_with_ref(identity, &data)?;
    verify_signature(identity.into(), &data, &sig)?;
    Ok(())
}

fn verify_signature(key: &KeyData, data: &[u8], sig: &Signature) -> Result<()> {
    return Ok(key
        .verify(data.as_ref(), &sig)
        .expect("verification failed"));
}
