//! # ssh-agent-client-rs
//!
//! An ssh-agent client implementation in rust, aiming to provide a robust,
//! well tested and easy to use synchronous API to interact with an ssh-agent.
//!
//! # Examples
//! ```no_run
//! use ssh_agent_client_rs::Client;
//! # use std::env;
//! # use std::path::Path;
//! # use ssh_agent_client_rs::Error;
//! use ssh_key::PublicKey;
//!
//! # let env = env::var("SSH_AUTH_SOCK").unwrap();
//! # let path_to_ssh_auth_socket = Path::new(env.as_str());
//! let mut client = Client::connect(path_to_ssh_auth_socket).expect("failed to connect");
//!
//! // List the identities that the connected ssh-agent makes available
//! let identities: Vec<PublicKey> = client.list_identities().expect("failed to list identities");
//! ```

use crate::codec::{read_message, write_message, ReadMessage, WriteMessage};
use ssh_key::{PrivateKey, PublicKey, Signature};
use std::io::{Read, Write};

// conditional compilation: differences between unix-like and 'windows git-bash'
#[cfg(target_family = "unix")]
use std::os::unix::net::UnixStream;
// git-bash works with TcpStream instead of UnixStream and has a strange handshaking
#[cfg(target_family = "windows")]
use std::net::TcpStream;

use std::path::Path;

mod codec;
mod error;

pub use self::error::Error;
pub use self::error::Result;

/// A combination of the std::io::Read and std::io::Write traits.
pub trait ReadWrite: Read + Write {}

/// A Client instance is an object that can be used to interact with an ssh-agent,
/// typically using a Unix socket
pub struct Client {
    socket: Box<dyn ReadWrite>,
}

#[cfg(target_family = "unix")]
impl ReadWrite for UnixStream {}
#[cfg(target_family = "windows")]
impl ReadWrite for TcpStream {}

impl Client {
    /// Constructs a Client connected to a unix socket referenced by path.
    #[cfg(target_family = "unix")]
    pub fn connect(path: &Path) -> Result<Client> {
        let socket = Box::new(UnixStream::connect(path)?);
        Ok(Client { socket })
    }

    /// Construct a Client backed by an implementation of ReadWrite, mainly useful for
    /// testing.
    pub fn with_read_write(read_write: Box<dyn ReadWrite>) -> Client {
        Client { socket: read_write }
    }

    /// List the identities that has been added to the connected ssh-agent.
    pub fn list_identities(&mut self) -> Result<Vec<PublicKey>> {
        write_message(&mut self.socket, WriteMessage::RequestIdentities)?;
        match read_message(&mut self.socket)? {
            ReadMessage::Identities(identities) => Ok(identities),
            m => Err(unexpected_response(m)),
        }
    }

    /// Add an identity to the connected ssh-agent.
    pub fn add_identity(&mut self, key: &PrivateKey) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::AddIdentity(key))?;
        self.expect_success()
    }

    /// Remove an identity from the connected ssh-agent.
    pub fn remove_identity(&mut self, key: &PrivateKey) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::RemoveIdentity(key))?;
        self.expect_success()
    }

    /// Remove all identities from the connected ssh-agent.
    pub fn remove_all_identities(&mut self) -> Result<()> {
        write_message(&mut self.socket, WriteMessage::RemoveAllIdentities)?;
        self.expect_success()
    }

    /// Instruct the connected ssh-agent to sign data with the private key associated with the
    /// provided public key. For now, sign requests with RSA keys are hard coded to use the
    /// SHA-512 hashing algorithm.
    pub fn sign(&mut self, key: &PublicKey, data: &[u8]) -> Result<Signature> {
        write_message(&mut self.socket, WriteMessage::Sign(key, data))?;
        match read_message(&mut self.socket)? {
            ReadMessage::Signature(sig) => Ok(sig),
            ReadMessage::Failure => Err(Error::RemoteFailure),
            m => Err(unexpected_response(m)),
        }
    }

    fn expect_success(&mut self) -> Result<()> {
        let response = read_message(&mut self.socket)?;
        match response {
            ReadMessage::Success => Ok(()),
            ReadMessage::Failure => Err(Error::RemoteFailure),
            _ => Err(Error::InvalidMessage("Unexpected response".to_string())),
        }
    }

    /// Constructs a Client connected to a tcp socket for 'windows git-bash'
    ///
    /// On Windows, git-for-windows, git-bash, cygwin, msysgit, msys2 and mingW64 provide functionality similar to a Linux distribution.  
    /// Linux uses UnixStream, but Windows before 2019 didn't have UDS 'Unix Domain Socket'.  
    /// Windows "git-bash" needed a different way for "ssh-add" (client) and "ssh-agent" (server) for inter process communication.  
    /// They invented a special protocol and use the Tcp Socket instead of Unix Socket.  
    /// <https://stackoverflow.com/questions/23086038/what-mechanism-is-used-by-msys-cygwin-to-emulate-unix-domain-sockets>
    /// <https://github.com/abourget/secrets-bridge/blob/master/pkg/agentfwd/agentconn_windows.go>
    #[cfg(target_family = "windows")]
    pub fn connect(path: &Path) -> Result<Client> {
        // ssh-agent exports the env variable SSH_AUTH_SOCK. This is normally the paths to the Unix Socket.
        // In 'windows git-bash' the fake unix domain socket path is just a normal file
        // that contains some data for the tcp connection")
        let conn_string = std::fs::read_to_string(path)?;

        // region: parse the SSH_AUTH_SOCK metadata
        // example: !<socket >49722 s 09B97624-72E2CDC5-38596B86-E9F0B690\0
        let conn_string = conn_string
            .trim_start_matches("!<socket >")
            .trim_end_matches("\0");
        let mut split_iter = conn_string.split_whitespace();
        let tcp_port = split_iter.next().ok_or_else(|| {
            Error::GitBashErrorMessage("Bad format in ssh agent connection file.".to_string())
        })?;
        let is_cygwin = split_iter.next().ok_or_else(|| {
            Error::GitBashErrorMessage("Bad format in ssh agent connection file.".to_string())
        })?;
        let key_guid = split_iter.next().ok_or_else(|| {
            Error::GitBashErrorMessage("Bad format in ssh agent connection file.".to_string())
        })?;
        if is_cygwin != "s" {
            return Err(Error::GitBashErrorMessage(
                "Old version of MSysGit ssh-agent implementation is not supported.".to_string(),
            ));
        }
        // endregion: parse the SSH_AUTH_SOCK metadata

        // The character 's' defines the newer version of MSys2 or cygwin or mingw64.
        // This ssh-agent implementation is supported.
        let tcp_address = format!("localhost:{}", tcp_port);
        let mut tcp_stream = std::net::TcpStream::connect(&tcp_address)?;

        // region: mixing bytes for the handshake
        let mut b1: [u8; 16] = [0; 16];
        let parsed_into_bytes = sscanf::sscanf!(key_guid, "{u8:x}{u8:x}{u8:x}{u8:x}-{u8:x}{u8:x}{u8:x}{u8:x}-{u8:x}{u8:x}{u8:x}{u8:x}-{u8:x}{u8:x}{u8:x}{u8:x}")
        .or_else(|_| Err(Error::GitBashErrorMessage("Bad format in ssh agent connection file.".to_string())))?;

        b1[3] = parsed_into_bytes.0;
        b1[2] = parsed_into_bytes.1;
        b1[1] = parsed_into_bytes.2;
        b1[0] = parsed_into_bytes.3;

        b1[7] = parsed_into_bytes.4;
        b1[6] = parsed_into_bytes.5;
        b1[5] = parsed_into_bytes.6;
        b1[4] = parsed_into_bytes.7;

        b1[11] = parsed_into_bytes.8;
        b1[10] = parsed_into_bytes.9;
        b1[9] = parsed_into_bytes.10;
        b1[8] = parsed_into_bytes.11;

        b1[15] = parsed_into_bytes.12;
        b1[14] = parsed_into_bytes.13;
        b1[13] = parsed_into_bytes.14;
        b1[12] = parsed_into_bytes.15;
        // endregion: mixing bytes for the handshake

        let _amount = tcp_stream.write(&b1)?;

        let mut b2: [u8; 16] = [0; 16];
        let _amount = tcp_stream.read(&mut b2)?;

        // Preparing pid,gid,uid
        let mut pid_uid_gid: [u8; 12] = [0; 12];
        let pid = std::process::id();
        // convert to LittleEndian
        let mut pid_le = pid.to_le_bytes();
        pid_uid_gid[0..4].swap_with_slice(&mut pid_le);

        // region: extractMSysGitUID
        let vec_byte_out = std::process::Command::new(r#"C:\Program Files\Git\usr\bin\bash.exe"#)
            .arg("-c")
            .arg("ps")
            .output()?
            .stdout;
        let string_output = String::from_utf8_lossy(&vec_byte_out);

        let capture_uid = regex::Regex::new(r#"(?m)^\s+\d+\s+\d+\s+\d+\s+\d+\s+\?\s+(\d+)"#)
            .map_err(|_| {
                Error::GitBashErrorMessage("Format of 'bash.exe -c ps' is incorrect.".to_string())
            })?;
        let first_capture = capture_uid.captures(&string_output).ok_or_else(|| {
            Error::GitBashErrorMessage("Format of 'bash.exe -c ps' is incorrect.".to_string())
        })?;
        let first_capture_str = first_capture
            .get(1)
            .ok_or_else(|| {
                Error::GitBashErrorMessage("Format of 'bash.exe -c ps' is incorrect.".to_string())
            })?
            .as_str();
        let uid: u32 = first_capture_str.parse().map_err(|_| {
            Error::GitBashErrorMessage("Format of 'bash.exe -c ps' is incorrect.".to_string())
        })?;
        // endregion: extractMSysGitUID

        let mut uid_le = uid.to_le_bytes();
        pid_uid_gid[4..8].swap_with_slice(&mut uid_le);

        // for cygwin's AF_UNIX -> AF_INET, pid = gid"
        let gid = pid;
        let mut gid_le = gid.to_le_bytes();
        pid_uid_gid[8..12].swap_with_slice(&mut gid_le);

        let _amount = tcp_stream.write(&pid_uid_gid)?;

        let mut b3: [u8; 16] = [0; 16];
        let _amount = tcp_stream.read(&mut b3)?;

        let socket = Box::new(tcp_stream);
        Ok(Client { socket })
    }
}

fn unexpected_response(message: ReadMessage) -> Error {
    let error = format!("Agent responded with unexpected message '{:?}'", message);
    Error::InvalidMessage(error)
}
