#!/bin/sh
# Start sshd and FRR, then stay in the foreground.
set -e
ssh-keygen -A >/dev/null
/usr/sbin/sshd
/usr/lib/frr/frrinit.sh start
exec sleep infinity
