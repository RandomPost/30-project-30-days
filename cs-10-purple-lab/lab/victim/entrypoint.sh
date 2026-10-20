#!/bin/bash
# LAB ONLY: start rsyslog, cron and sshd in the foreground.
# sshd runs without -e on purpose: -e would send its log to stderr instead of syslog (auth.log).
set -e
mkdir -p /logs /run/sshd /var/spool/rsyslog
ssh-keygen -A >/dev/null
rm -f /run/rsyslogd.pid
rsyslogd
for _ in $(seq 1 50); do [ -S /dev/log ] && break; sleep 0.1; done
cron
exec /usr/sbin/sshd -D
