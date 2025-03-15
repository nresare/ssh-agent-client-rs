# ssh-agent-client-rs

[![build](https://img.shields.io/github/actions/workflow/status/nresare/ssh-agent-client-rs/rust.yml?label=checks&logo=github&style=for-the-badge)](https://github.com/nresare/ssh-agent-client-rs/actions/workflows/rust.yml)
[![crates.io](https://img.shields.io/crates/v/ssh-agent-client-rs?color=fc8d62&logo=rust&style=for-the-badge)](https://crates.io/crates/ssh-agent-client-rs)

`ssh-agent-client-rs` is a pure rust client library for interacting with an ssh-agent using the protocol defined in 
[draft-miller-ssh-agent-04](https://datatracker.ietf.org/doc/html/draft-miller-ssh-agent-04)

The aim with the design of this library is to provide an easy-to-use and well tested 
library that can be used to perform the most common tasks interacting with the `ssh-agent`.
The API will always be synchronous, as that corresponds to most use cases, and unless 
I get very bored at some point, it will probably not be a complete implementation of the
protocol. However, contributions are more than welcome.

It was inspired by [russh-agent](https://crates.io/crates/russh-agent) but the projects does not share any code.
In particular this client only exposes a synchronous API which simplifies both the implementation and interface.

## Implemented and tested features

This client implements the most of the features described in the protocol specification, including the ability
to instruct an ssh-agent to
* add identities, the term the specification uses for a key pair, given a private key
* list identities
* remove an identity given a specific public key
* remove all identities
* sign an arbitrary message

The following features have not yet been implemented
* adding identities with constraints
* the dedicated message to add smartcard keys using the `SSH_AGENTC_ADD_SMARTCARD_KEY` message. 
  However, in practice at least `resident` type smartcard keys from a device implementing `FIDO2`
  such as Yubikey series 5 is added using the regular message to add an identity, `SSH_AGENTC_ADD_IDENTITY`

## Usage

The example code in examples should be pretty easy to follow.
The basic idea is to create a `Client` instance and call its public methods to interact with the ssh-agent.

## Windows support

Support for communicating with the `openssh-ssh-agent` shipped with Windows 11 is implemented using
named pipes and the `interprocess` crate. To try the various example binaries, first set the `SSH_AUTH_SOCK`
variable as follows:
```cmd
> set SSH_AUTH_SOCK=\\.\pipe\openssh-ssh-agent
> cargo run --example list
```

If you are using the ssh-agent shipped with [git for windows](https://gitforwindows.org/) you might need to
use the Unix socket emulation implementation available from https://github.com/bestia-dev/ssh-agent-client-rs-win-git-bash

## License

Licensed under either of
* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
* [MIT license](http://opensource.org/licenses/MIT)
  at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.
