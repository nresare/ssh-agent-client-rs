use signature::Signer;
use ssh_agent_client_rs::{Client, Error};
use ssh_encoding::Decode;
use ssh_key::Signature;
use ssh_key::{PrivateKey, PublicKey};

mod mock;
use mock::MockSocket;

const LIST_IDENTITIES: &[u8] = b"\0\0\0\x01\x0b";
const IDENTITIES_RESPONSE: &[u8] = include_bytes!("data/ssh-add_response.bin");

const TEST_DATA: &[u8] = b"foobar";

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

    let mut public_key = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();
    // let's verify that changing the comment doesn't affect the request sent
    public_key.set_comment("another comment");

    let private_key = PrivateKey::from_openssh(include_str!("data/id_ed25519")).unwrap();

    let mut client = Client::with_read_write(Box::new(socket));

    let result = client.sign(&public_key, TEST_DATA).unwrap();

    assert_eq!(private_key.key_data().sign(TEST_DATA.as_ref()), result);
}

#[test]
fn test_sign_remote_failure() {
    let socket = MockSocket::new(
        include_bytes!("data/sign_request.bin"),
        include_bytes!("data/failure_response.bin"),
    );

    let public_key = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();

    let mut client = Client::with_read_write(Box::new(socket));
    let result = client.sign(&public_key, TEST_DATA).unwrap_err();
    assert!(matches!(result, Error::RemoteFailure));
}

#[test]
fn test_sign_invalid_response() {
    let socket = MockSocket::new(
        include_bytes!("data/sign_request.bin"),
        include_bytes!("data/sign_request.bin"),
    );

    let public_key = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();

    let mut client = Client::with_read_write(Box::new(socket));
    let result = client.sign(&public_key, TEST_DATA).unwrap_err();
    match result {
        Error::UnknownMessageType(_) => {}
        result => panic!("{}", result),
    }
}

#[test]
fn test_sk_ecdsa_sha2_signature() {
    let bytes = include_bytes!("data/sk_ecdsa_signature.bin");
    Signature::decode(&mut bytes.as_ref()).unwrap();
}
