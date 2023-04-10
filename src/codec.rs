use bytes::Bytes;
use crate::Identity;

#[repr(u8)]
enum Message {
    RequestIdentities = 11,
    IdentitiesAnswer(Vec<Identity>) = 12,
}

fn decode(input: Bytes) -> std::io::Result<Message> {
    todo!()
}

#[cfg(test)]
mod test {

}