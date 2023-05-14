use ssh_agent_client_rs::Client;
use ssh_key::PublicKey;

mod mock;
use mock::MockSocket;

const LIST_IDENTITIES: &[u8] = b"\0\0\0\x01\x0b";
const IDENTITIES_RESPONSE: &[u8] = include_bytes!("data/ssh-add_response.bin");

#[test]
fn test_list_identities() {
    let socket = MockSocket::new(LIST_IDENTITIES, IDENTITIES_RESPONSE);
    let mut client = Client::with_read_write(Box::new(socket));
    let result = client.list_identities().expect("failed to list identities");

    let key = PublicKey::from_openssh(include_str!("data/id_ed25519.pub")).unwrap();
    assert_eq!(vec![key], result);
}
