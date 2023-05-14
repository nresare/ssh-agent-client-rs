# ssh-agent-client-rs

`ssh-agent-client-rs` is a pure rust client library for interacting with an ssh-agent using the protocol defined in 
[draft-miller-ssh-agent-04](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04)

It was inspired by [russh-agent](https://crates.io/crates/russh-agent) but the projects does not share any code.
In particular this client only exposes a synchronous API which simplifies both the implementation and interface.

## Usage

The example code in examples should be pretty easy to follow.
The basic idea is to create a `Client` instance and call its public methods to interact with the ssh-agent.

## Future plans

This project is in early development. This is a roughly ordered todo-list:

* Implement the api to sign data using the agent

## License

Licensed under either of
* Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)
  at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
