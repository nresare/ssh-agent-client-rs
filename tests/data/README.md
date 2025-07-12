## How I generated the certs and cert keys

1. Re-using the id_ed25519 keypair as a CA key
2. Generated a cert key with `ssh-keygen -N "" -t ed25519 -f id_ed25519_for_cert`
3. Generated the cert from the pubkey with `ssh-keygen -s id_ed25519 -I for-test-user -V +1000w -n test id_ed25519_for_cert.pub`
