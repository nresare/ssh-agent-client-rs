use ssh_agent_client_rs::ReadWrite;
use std::io::{Cursor, Read, Write};

pub struct MockSocket<'a> {
    expected: &'a [u8],
    response: Cursor<&'a [u8]>,
    output: Vec<u8>,
}

impl Read for MockSocket<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.response.read(buf)
    }
}

impl Write for MockSocket<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.output.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.output.flush()
    }
}

impl Drop for MockSocket<'_> {
    fn drop(&mut self) {
        assert_eq!(self.expected, self.output.as_slice())
    }
}

impl ReadWrite for MockSocket<'_> {}

impl<'a> MockSocket<'a> {
    pub fn new(expected: &'a [u8], response: &'a [u8]) -> MockSocket<'a> {
        let output = Vec::new();
        let response = Cursor::new(response);
        MockSocket {
            expected,
            response,
            output,
        }
    }
}
