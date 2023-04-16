use std::io::Cursor;

pub fn reader(data: &'static [u8]) -> Cursor<&[u8]> {
    Cursor::new(&data[..])
}
