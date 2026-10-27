#!/bin/sh
# Start sshd, lldpd and FRR, then stay in the foreground.
set -e
ssh-keygen -A >/dev/null
chmod 644 /etc/frr/vtysh.conf 2>/dev/null || true  # let the ssh user run vtysh without a warning
/usr/sbin/sshd
# only the lab links (not eth0), and advertise the management address
lldpd -I 'eth[1-9]*' -m '172.20.30.*'
/usr/lib/frr/frrinit.sh start
exec sleep infinity
