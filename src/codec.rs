use crate::codec::ReadMessage::{Failure, Success};
use crate::Error::UnknownMessageType;
use crate::{Error, Result};
use bytes::{Buf, Bytes, BytesMut};
use ssh_encoding::{Decode, Encode};
use ssh_key::{Algorithm, PrivateKey, PublicKey, Signature};
use std::io::{Read, Write};

type MessageTypeId = u8;
// This list is copied from
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1
const SSH_AGENTC_REQUEST_IDENTITIES: MessageTypeId = 11;
const SSH_AGENTC_SIGN_REQUEST: MessageTypeId = 13;
const SSH_AGENTC_ADD_IDENTITY: MessageTypeId = 17;
const SSH_AGENTC_REMOVE_IDENTITY: MessageTypeId = 18;
const SSH_AGENTC_REMOVE_ALL_IDENTITIES: MessageTypeId = 19;

const SSH_AGENT_FAILURE: MessageTypeId = 5;
const SSH_AGENT_SUCCESS: MessageTypeId = 6;
const SSH_AGENT_SIGN_RESPONSE: MessageTypeId = 14;
const SSH_AGENT_IDENTITIES_ANSWER: MessageTypeId = 12;

// This list is copied from
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-7.3
const SSH_AGENT_RSA_SHA2_512: usize = 0x04;

// to avoid allocating far too much memory
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

//#[repr(u8)]
pub enum WriteMessage<'a> {
    RequestIdentities,
    Sign(&'a PublicKey, &'a [u8]),
    AddIdentity(&'a PrivateKey),
    RemoveIdentity(&'a PrivateKey),
    RemoveAllIdentities,
}

#[derive(Debug)]
pub enum ReadMessage {
    Failure,
    Success,
    Identities(Vec<PublicKey>),
    Signature(Signature),
}

pub fn read_message(input: &mut dyn Read) -> Result<ReadMessage> {
    let (t, buf) = read_packet(input)?;
    match t {
        SSH_AGENT_FAILURE => Ok(Failure),
        SSH_AGENT_SUCCESS => Ok(Success),
        SSH_AGENT_IDENTITIES_ANSWER => Ok(ReadMessage::Identities(make_identities(buf)?)),
        SSH_AGENT_SIGN_RESPONSE => {
            // Discard the first 4 bytes, as they just encode the length of the field
            let mut buf = &buf[..];
            let sig_len: usize = buf.get_u32() as usize;
            if sig_len != buf.len() {
                return invalid_data("different inner and outer size");
            }
            let sig = Signature::decode(&mut buf)?;
            Ok(ReadMessage::Signature(sig))
        }
        _ => Err(UnknownMessageType(t)),
    }
}

pub fn write_message(output: &mut dyn Write, message: WriteMessage) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    match message {
        WriteMessage::RequestIdentities => buf.write_all(&[SSH_AGENTC_REQUEST_IDENTITIES])?,
        WriteMessage::AddIdentity(key) => {
            buf.write_all(&[SSH_AGENTC_ADD_IDENTITY])?;
            key.key_data().encode(&mut buf)?;

            let comment = key.comment();
            write_u32(comment.len(), &mut buf)?;
            buf.write_all(comment.as_ref())?
        }
        WriteMessage::RemoveIdentity(key) => {
            buf.write_all(&[SSH_AGENTC_REMOVE_IDENTITY])?;
            write_u32(key.public_key().key_data().encoded_len()?, &mut buf)?;
            key.public_key().key_data().encode(&mut buf)?;
        }
        WriteMessage::RemoveAllIdentities => buf.write_all(&[SSH_AGENTC_REMOVE_ALL_IDENTITIES])?,
        WriteMessage::Sign(key, data) => {
            buf.write_all(&[SSH_AGENTC_SIGN_REQUEST])?;
            write_u32(key.key_data().encoded_len()?, &mut buf)?;
            key.key_data().encode(&mut buf)?;
            write_u32(data.len(), &mut buf)?;
            buf.write_all(data)?;
            // Emit signature flags, see the spec section 4.5.1
            match key.algorithm() {
                // Let's always use the SHA2 512 bit hash when signing RSA keys, to simplify the API
                Algorithm::Rsa { hash: _ } => write_u32(SSH_AGENT_RSA_SHA2_512, &mut buf)?,
                _ => write_u32(0, &mut buf)?,
            }
        }
    }

    write_u32(buf.len(), output)?;
    output.write_all(&buf)?;
    Ok(())
}

fn write_u32(i: usize, output: &mut dyn Write) -> Result<()> {
    let i = u32::try_from(i)
        .map_err(|_| Error::InvalidMessage(format!("Could not encode {} into an u32 value", i)))?;
    output.write_all(&i.to_be_bytes())?;
    Ok(())
}

fn read_packet(mut input: impl Read) -> Result<(MessageTypeId, Bytes)> {
    let mut buf = [0u8; 5];
    input.read_exact(&mut buf)?;
    let mut buf = &buf[..];
    let len = buf.get_u32();
    let message_type = buf.get_u8();

    if len > MAX_MESSAGE_SIZE {
        // refusing to allocate more than MAX_MESSAGE_SIZE
        return invalid_data(&format!(
            "Refusing to read message with size larger than {}",
            MAX_MESSAGE_SIZE
        ));
    }
    let mut bytes: BytesMut = BytesMut::zeroed(len as usize - 1);
    input.read_exact(bytes.as_mut())?;
    Ok((message_type, bytes.freeze()))
}

fn invalid_data<T>(message: &str) -> Result<T> {
    Err(Error::InvalidMessage(String::from(message)))
}

fn make_identities(mut buf: Bytes) -> Result<Vec<PublicKey>> {
    let len = buf.get_u32() as usize;

    let mut result = Vec::with_capacity(len);
    for _ in 0..len {
        let key_len = buf.get_u32() as usize;
        let mut public_key = PublicKey::from_bytes(&buf.chunk()[..key_len])?;
        buf.advance(key_len);

        let comment_len = buf.get_u32() as usize;
        let comment = &buf.chunk()[..comment_len];
        let comment = std::str::from_utf8(comment).unwrap().to_string();
        buf.advance(comment_len);

        public_key.set_comment(comment);
        result.push(public_key);
    }
    Ok(result)
}

#[cfg(test)]
mod test {
    use crate::codec::{
        make_identities, read_message, write_message, write_u32, ReadMessage, WriteMessage,
    };
    use crate::Error;
    use bytes::Bytes;
    use ssh_key::{PrivateKey, PublicKey};
    use std::io::Cursor;

    pub fn reader(data: &'static [u8]) -> Cursor<&'static [u8]> {
        Cursor::new(data)
    }

    #[test]
    fn test_read_message_identities_answer() {
        let result =
            read_message(&mut reader(b"\0\0\0\x05\x0c\0\0\0\0")).expect("failed to read_message()");
        match result {
            ReadMessage::Identities(identities) => {
                assert_eq!(identities, vec![])
            }
            _ => panic!("result was not IdentitiesAnswer"),
        }
    }

    #[test]
    fn test_read_message_failure() {
        let result =
            read_message(&mut reader(b"\0\0\0\x01\x05")).expect("failed to read_message()");
        match result {
            ReadMessage::Failure => (),
            _ => panic!("result was not FailureAnswer"),
        }
    }

    #[test]
    fn test_read_message_success() {
        let result =
            read_message(&mut reader(b"\0\0\0\x01\x06")).expect("failed to read_message()");
        match result {
            ReadMessage::Success => (),
            _ => panic!("result was not SuccessAnswer"),
        }
    }

    #[test]
    fn test_read_message_unknown() {
        let result = read_message(&mut reader(b"\0\0\0\x01\xff"));
        match result {
            Err(Error::UnknownMessageType(_)) => (),
            _ => panic!("did not receive expected error UnknownMessageType"),
        }
    }

    #[test]
    fn test_read_overly_long_message_length() {
        let result = read_message(&mut reader(b"\x01\0\0\x01\xff"));
        match result {
            Err(Error::InvalidMessage(msg)) => assert_eq!(
                msg,
                "Refusing to read message with size larger than 1048576"
            ),
            _ => panic!("did not receive expected error InvalidData"),
        }
    }

    #[test]
    fn test_make_identities() {
        let data = Bytes::from_static(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/identity_list_response.bin"
        )));
        let key = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/id_ed25519.pub"
        ));
        let key = PublicKey::from_openssh(key).unwrap();

        assert_eq!(make_identities(data).expect("Could not decode"), vec![key])
    }

    #[test]
    fn test_write_message() {
        let mut output: Vec<u8> = Vec::new();
        write_message(&mut output, WriteMessage::RequestIdentities).expect("failed writing");
        assert_eq!(vec![0_u8, 0, 0, 1, 11], output)
    }

    macro_rules! add_identity {
        ($message_path:expr, $key_path:expr) => {
            let key = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/",
                $key_path
            ));
            let expected = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/",
                $message_path
            ));
            let mut output: Vec<u8> = Vec::new();
            let key = PrivateKey::from_openssh(key).expect("failed to parse key");
            write_message(&mut output, WriteMessage::AddIdentity(&key)).unwrap();
            assert_eq!(expected, output.as_slice());
        };
    }

    #[test]
    fn test_write_add_identity() {
        add_identity!("ssh-add_rsa.bin", "id_rsa");
        add_identity!("ssh-add_dsa.bin", "id_dsa");
        add_identity!("ssh-add_ed25519.bin", "id_ed25519");
        add_identity!("ssh-add_ecdsa.bin", "id_ecdsa");
    }

    macro_rules! remove_identity {
        ($message_path:expr, $key_path:expr) => {
            let key = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/",
                $key_path
            ));
            let expected = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/data/",
                $message_path
            ));
            let mut output: Vec<u8> = Vec::new();
            let key = PrivateKey::from_openssh(key).expect("failed to parse key");
            write_message(&mut output, WriteMessage::RemoveIdentity(&key)).unwrap();
            assert_eq!(expected, output.as_slice());
        };
    }

    #[test]
    fn test_write_remove_identity() {
        remove_identity!("ssh-remove_rsa.bin", "id_rsa");
        remove_identity!("ssh-remove_dsa.bin", "id_dsa");
        remove_identity!("ssh-remove_ed25519.bin", "id_ed25519");
        remove_identity!("ssh-remove_ecdsa.bin", "id_ecdsa");
    }

    #[test]
    fn test_write_remove_all_identities() {
        let mut output: Vec<u8> = Vec::new();
        write_message(&mut output, WriteMessage::RemoveAllIdentities).expect("failed writing");
        assert_eq!(vec![0_u8, 0, 0, 1, 19], output)
    }

    #[test]
    fn test_write_too_large() {
        let mut output: Vec<u8> = Vec::new();
        let result = write_u32(usize::MAX, &mut output);
        match result {
            Err(Error::InvalidMessage(msg)) => {
                assert_eq!(
                    format!("Could not encode {} into an u32 value", usize::MAX),
                    msg
                )
            }
            _ => panic!("expected InvalidMessage"),
        }
    }

    // let's verify that we set the correct signature flag, SSH_AGENT_RSA_SHA2_512
    #[test]
    fn test_write_sign_rsa() {
        let key = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/id_rsa.pub",
        ));
        let expected = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/data/sign_rsa.bin",
        ));

        let key = PublicKey::from_openssh(key).expect("failed to parse key");

        let mut output: Vec<u8> = Vec::new();
        write_message(&mut output, WriteMessage::Sign(&key, b"a")).unwrap();
        assert_eq!(expected, output.as_slice());
    }
}
