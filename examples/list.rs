use ssh_agent_client_rs::{Client, Result};
use ssh_key::public::{KeyData, PublicKey};
use ssh_key::{EcdsaCurve, MPInt};
use std::env;
use std::path::Path;

/// This example lists the hashes of keys that the ssh-agent that listens to
/// the socket referenced by the path in the SSH_AUTH_SOCK environment variable
/// much like the command `ssh-add -l`
fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("SSH_AUTH_SOCK is not set");
    let mut client = Client::connect(Path::new(path.as_str()))?;
    let identities = client.list_identities()?;
    if identities.len() < 1 {
        println!("The agent has no identities.");
    } else {
        identities.iter().for_each(|i| print(i));
    }
    Ok(())
}

fn print(key: &PublicKey) {
    println!(
        "{} {} {} {}",
        key_bits(&key),
        key.fingerprint(Default::default()),
        key.comment(),
        key.algorithm().to_string(),
    )
}

/// Returns the key size in bits for different PublicKey variants.
fn key_bits(key: &PublicKey) -> usize {
    match key.key_data() {
        KeyData::Rsa(k) => get_bits(&k.n),
        KeyData::Dsa(k) => get_bits(&k.p),
        KeyData::Ed25519(k) => k.0.len() * 8,
        KeyData::Ecdsa(k) => match k.curve() {
            EcdsaCurve::NistP256 => 256,
            EcdsaCurve::NistP384 => 384,
            EcdsaCurve::NistP521 => 521,
        },
        KeyData::SkEcdsaSha2NistP256(_) => 256,
        KeyData::SkEd25519(k) => k.public_key().0.len() * 8,
        _ => panic!("Unrecognised key {:?}", key),
    }
}

fn get_bits(int: &MPInt) -> usize {
    return int.as_positive_bytes().expect("should be positive").len() * 8;
}
