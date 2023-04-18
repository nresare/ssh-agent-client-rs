use ssh_key::public::KeyData;
use ssh_key::{EcdsaCurve, MPInt, PublicKey};

pub fn key_bits(key: &PublicKey) -> usize {
    match key.key_data() {
        KeyData::Rsa(k) => get_bits(&k.n),
        KeyData::Dsa(k) => get_bits(&k.p),
        KeyData::Ed25519(k) => k.0.len() * 8,
        KeyData::Ecdsa(k) => {
            match k.curve() {
                EcdsaCurve::NistP256 => 256,
                EcdsaCurve::NistP384 => 384,
                EcdsaCurve::NistP521 => 521,
            }
        }
        KeyData::SkEcdsaSha2NistP256(_) => 256,
        KeyData::SkEd25519(k) => k.public_key().0.len() * 8,
        _ => panic!("Unrecognised key {:?}", key)
    }
}

fn get_bits(int: &MPInt) -> usize {
    return int.as_positive_bytes().expect("should be positive").len() * 8
}
