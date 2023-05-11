#!/bin/bash

# This script details how the test files were created. The ssh-keygen, ssh-add
# used are the ones shipping with macOS, socat is installed through Homebrew.

ALGORITHMS="rsa dsa ecdsa ed25519"

for algo in $ALGORITHMS;
do
   ssh-keygen -q -t "$algo" -N "" -C "test@$algo" -f id_"$algo"
   rm -f /tmp/sock
   socat UNIX-LISTEN:/tmp/sock OPEN:ssh-add_"$algo".bin,creat &
   sleep 1
   SSH_AUTH_SOCK=/tmp/sock ssh-add id_"$algo"
done

