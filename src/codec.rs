use crate::codec::ReadMessage::{Failure, Success};
use crate::Error::UnknownMessageType;
use crate::{Error, Identity, Result};
use bytes::{Buf, Bytes, BytesMut};
use ssh_encoding::Encode;
use ssh_key::PrivateKey;
use std::io::{Read, Write};

type MessageTypeId = u8;
// This list is copied from
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1
const SSH_AGENTC_REQUEST_IDENTITIES: MessageTypeId = 11;
const SSH_AGENTC_ADD_IDENTITY: MessageTypeId = 17;

const SSH_AGENT_FAILURE: MessageTypeId = 5;
const SSH_AGENT_SUCCESS: MessageTypeId = 6;
const SSH_AGENT_IDENTITIES_ANSWER: MessageTypeId = 12;

// to avoid allocating far too much memory
const MAX_MESSAGE_SIZE: u32 = 1024 * 1024;

//#[repr(u8)]
pub enum WriteMessage {
    RequestIdentities,
    AddIdentity(Box<PrivateKey>),
}

pub enum ReadMessage {
    Failure,
    Success,
    Identities(Vec<Identity>),
}

pub fn read_message(input: &mut dyn Read) -> Result<ReadMessage> {
    let (t, buf) = read_packet(input)?;
    match t {
        SSH_AGENT_FAILURE => Ok(Failure),
        SSH_AGENT_SUCCESS => Ok(Success),
        SSH_AGENT_IDENTITIES_ANSWER => Ok(ReadMessage::Identities(make_identities(buf))),
        _ => Err(UnknownMessageType),
    }
}

pub fn write_message(output: &mut dyn Write, message: WriteMessage) -> Result<()> {
    let mut buf: Vec<u8> = Vec::new();
    match message {
        WriteMessage::RequestIdentities => {
            buf.write_all(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        }
        WriteMessage::AddIdentity(key) => {
            buf.write_all(&[SSH_AGENTC_ADD_IDENTITY])?;
            let comment = key.comment();
            key.key_data().encode(&mut buf)?;
            write_len(comment.len(), &mut buf)?;
            buf.write_all(comment.as_ref())?
        }
    }
    write_len(buf.len(), output)?;
    output.write_all(&buf)?;
    Ok(())
}

fn write_len(len: usize, output: &mut dyn Write) -> Result<()> {
    output.write_all(&u32::try_from(len)?.to_be_bytes())?;
    Ok(())
}

fn read_packet(mut input: impl Read) -> Result<(MessageTypeId, Bytes)> {
    let mut buf = [0u8; 5];
    input.read_exact(&mut buf)?;
    let mut buf = &buf[..];
    let len = buf.get_u32();
    let t = buf.get_u8();

    if len > MAX_MESSAGE_SIZE {
        // refusing to allocate more than MAX_MESSAGE_SIZE
        return invalid_data(format!(
            "Refusing to read message with size larger than {}",
            MAX_MESSAGE_SIZE
        ));
    }
    let mut bytes: BytesMut = BytesMut::zeroed(len as usize - 1);
    input.read_exact(bytes.as_mut())?;
    Ok((t, bytes.freeze()))
}

fn invalid_data<T>(message: String) -> Result<T> {
    Err(Error::InvalidData(Some(message)))
}

fn make_identities(mut buf: Bytes) -> Vec<Identity> {
    let len = buf.get_u32() as usize;

    let mut result = Vec::with_capacity(len);
    for _ in 0..len {
        let key_len = buf.get_u32() as usize;
        let public_key = Bytes::from(buf.chunk()[..key_len].to_vec());
        buf.advance(key_len);

        let comment_len = buf.get_u32() as usize;
        let comment = &buf.chunk()[..comment_len];
        let comment = std::str::from_utf8(comment).unwrap().to_string();
        buf.advance(comment_len);

        result.push(Identity {
            public_key,
            comment,
        });
    }
    result
}

#[cfg(test)]
mod test {
    use crate::codec::{make_identities, read_message, write_message, ReadMessage, WriteMessage};
    use crate::testutil::reader;
    use crate::{Error, Identity};
    use bytes::Bytes;
    use ssh_key::PrivateKey;

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
            Err(Error::UnknownMessageType) => (),
            _ => panic!("did not receive expected error UnknownMessageType"),
        }
    }

    #[test]
    fn test_read_overly_long_message_length() {
        let result = read_message(&mut reader(b"\x01\0\0\x01\xff"));
        match result {
            Err(Error::InvalidData(Some(msg))) => assert_eq!(
                msg,
                "Refusing to read message with size larger than 1048576"
            ),
            _ => panic!("did not receive expected error InvalidData"),
        }
    }

    #[test]
    fn test_make_identities() {
        let bytes =
            Bytes::from_static(b"\0\0\0\x02\0\0\0\x03foo\0\0\0\x03bar\0\0\0\x01a\0\0\0\x01b");
        assert_eq!(
            make_identities(bytes),
            vec![
                Identity {
                    public_key: Bytes::from(&b"foo"[..]),
                    comment: "bar".to_string()
                },
                Identity {
                    public_key: Bytes::from(&b"a"[..]),
                    comment: "b".to_string()
                }
            ]
        )
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
            write_message(&mut output, WriteMessage::AddIdentity(Box::new(key))).unwrap();
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
}
