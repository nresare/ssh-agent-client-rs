use std::env;
use std::path::Path;
use ssh_agent_client_rs::{Client, Result};

fn main() -> Result<()> {
    let path = env::var("SSH_AUTH_SOCK").expect("Missing env variable");
    let mut client = Client::connect(Path::new(&path[..]))?;
    let result = client.list_identities()?;
    println!("Got {} identities: {}", result.len(), result.get(0).unwrap().comment);
    Ok(())
}