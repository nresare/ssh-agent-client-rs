use std::io::{Read, Write};
use crate::{Identity, Result};
use bytes::{Buf, Bytes, BytesMut};
use crate::Error::UnknownMessageType;

type MessageTypeId = u8;
// This list is copied from
// https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04#section-5.1
const SSH_AGENTC_REQUEST_IDENTITIES: MessageTypeId = 11;
const SSH_AGENT_IDENTITIES_ANSWER: MessageTypeId = 12;

#[repr(u8)]
pub enum Message {
    RequestIdentities,
    IdentitiesAnswer(Vec<Identity>),
}


pub fn read_message(input: &mut dyn Read) -> Result<Message> {
    let (t, buf) = read_packet(input)?;
    match t {
        SSH_AGENT_IDENTITIES_ANSWER => Ok(Message::IdentitiesAnswer(make_identities(buf))),
        _ => {
            // TODO: convert this to proper logging
            println!("Don't recognise message type {}", t);
            Err(UnknownMessageType)
        },
    }
}

pub fn write_message(output: &mut dyn Write, message: Message) -> Result<()> {
    match message {
        Message::RequestIdentities => {
            output.write(&1_u32.to_be_bytes())?;
            output.write(&[SSH_AGENTC_REQUEST_IDENTITIES])?;
        },
        _ => return Err(UnknownMessageType),
    }
    Ok(())
}

fn read_packet(mut input: impl Read) -> Result<(MessageTypeId, Bytes)> {
    let mut buf = [0u8; 5];
    input.read_exact(&mut buf)?;
    let mut buf = &buf[..];
    let len = buf.get_u32();
    let t = buf.get_u8();

    // todo: prevent very large allocations due to bad input data
    let mut bytes: BytesMut = BytesMut::zeroed(len as usize - 1);
    input.read_exact(bytes.as_mut())?;
    Ok((t, bytes.freeze()))
}

fn make_identities(mut buf: Bytes) -> Vec<Identity> {
    let len = buf.get_u32() as usize;

    let mut result = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let key_len = buf.get_u32() as usize;
        let public_key = Bytes::from(buf.chunk()[..key_len].to_vec());
        buf.advance(key_len);

        let comment_len = buf.get_u32() as usize;
        let comment = &buf.chunk()[..comment_len];
        let comment = std::str::from_utf8(comment).unwrap().to_string();
        buf.advance(comment_len);

        result.push(Identity{public_key, comment});
    }
    result
}


#[cfg(test)]
mod test {
    use crate::codec::{read_message, Message, make_identities, write_message};
    use crate::testutil::reader;
    use bytes::Bytes;
    use crate::Identity;

    #[test]
    fn test_read_message() {
        let result = read_message( &mut reader(b"\0\0\0\x05\x0c\0\0\0\0"))
            .expect("Failed to read message");
        match result {
            Message::IdentitiesAnswer(identities) => {
                assert_eq!(identities, vec![])
            },
            _ => panic!("result was not IdentitiesAnswer"),
        }
    }


    #[test]
    fn test_make_identities() {
        let bytes = Bytes::from_static(
            b"\0\0\0\x02\0\0\0\x03foo\0\0\0\x03bar\0\0\0\x01a\0\0\0\x01b"
        );
        assert_eq!(
            make_identities(bytes),
            vec![
                Identity{public_key: Bytes::from(&b"foo"[..]), comment: "bar".to_string()},
                Identity{public_key: Bytes::from(&b"a"[..]), comment: "b".to_string()}
            ]

        )
    }

    #[test]
    fn test_write_message() {
        let mut output: Vec<u8> = Vec::new();
        write_message(&mut output, Message::RequestIdentities)
            .expect("failed writing");
        assert_eq!(vec![0_u8, 0, 0, 1, 11], output)
    }
}