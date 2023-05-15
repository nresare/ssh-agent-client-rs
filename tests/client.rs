use bytes::Bytes;
use signature::Signer;
use ssh_agent_client_rs::Client;
use ssh_key::{PrivateKey, PublicKey};

mod mock;
use mock::MockSocket;

const LIST_IDENTITIES: &[u8] = b"\0\0\0\x01\x0b";
const IDENTITIES_RESPONSE: &[u8] = include_bytes!("data/ssh-add_response.bin");

const TEST_DATA: Bytes = Bytes::from_static(b"foobar");

#[test]
fn test_list_identities() {
    let socket = MockSocket::new(LIST_IDENTITIES, IDENTITIES_RESPONSE);
    let mut client = Client::with_read_write(Box::new(socket));
    let result = client.list_identities().expect("failed to list identities");

    let key = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();
    assert_eq!(vec![key], result);
}

#[test]
fn test_sign() {
    let socket = MockSocket::new(
        include_bytes!("data/sign_request.bin"),
        include_bytes!("data/sign_response.bin"),
    );

    let public_key = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();
    let private_key = PrivateKey::from_openssh(include_str!("data/id_ed25519")).unwrap();

    let mut client = Client::with_read_write(Box::new(socket));
    let result = client.sign(&public_key, TEST_DATA).unwrap();

    assert_eq!(private_key.key_data().sign(TEST_DATA.as_ref()), result);
}
