use ssh_agent_client_rs::bits::key_bits;
use ssh_key::PublicKey;

#[test]
fn test_key_length() {
    test_length(include_str!("data/id_dsa.pub"), 1024);
    test_length(include_str!("data/id_rsa.pub"), 3072);
    test_length(include_str!("data/id_ecdsa.pub"), 256);
    test_length(include_str!("data/id_ed25519.pub"), 256);
}

fn test_length(pubkey: &str, length: usize) {
    let key = PublicKey::from_openssh(pubkey).unwrap();
    assert_eq!(length, key_bits(&key));
}
