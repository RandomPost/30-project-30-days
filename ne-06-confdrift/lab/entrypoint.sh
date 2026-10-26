#!/bin/sh
# Start sshd and FRR, then stay in the foreground.
set -e
ssh-keygen -A >/dev/null
chmod 644 /etc/frr/vtysh.conf 2>/dev/null || true  # let the ssh user run vtysh without a warning
/usr/sbin/sshd
/usr/lib/frr/frrinit.sh start
exec sleep infinity
