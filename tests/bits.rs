use ssh_key::PublicKey;
use ssh_agent_client_rs::bits::key_bits;

const OPENSSH_DSA: &str = include_str!("examples/id_dsa.pub");
const OPENSSH_RSA: &str = include_str!("examples/id_rsa.pub");
const OPENSSH_ED25519: &str = include_str!("examples/id_ed25519.pub");
const OPENSSH_ECDSA_P256: &str = include_str!("examples/id_ecdsa_p256.pub");
const OPENSSH_ECDSA_P521: &str = include_str!("examples/id_ecdsa_p521.pub");

#[test]
fn test_key_length() {
    let key = PublicKey::from_openssh(OPENSSH_RSA).unwrap();
    assert_eq!(3072, key_bits(&key));
    let key = PublicKey::from_openssh(OPENSSH_DSA).unwrap();
    assert_eq!(1024, key_bits(&key));
    let key = PublicKey::from_openssh(OPENSSH_ED25519).unwrap();
    assert_eq!(256, key_bits(&key));
    let key = PublicKey::from_openssh(OPENSSH_ECDSA_P256).unwrap();
    assert_eq!(256, key_bits(&key));
    let key = PublicKey::from_openssh(OPENSSH_ECDSA_P521).unwrap();
    assert_eq!(521, key_bits(&key));
}