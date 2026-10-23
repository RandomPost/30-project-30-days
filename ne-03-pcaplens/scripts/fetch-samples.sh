#!/usr/bin/env bash
# Download public sample captures from the Wireshark test suite (GPL-2.0 project, so they
# are fetched here rather than committed). Re-runnable; skips files already present.
set -euo pipefail
cd "$(dirname "$0")/.."
BASE="https://gitlab.com/wireshark/wireshark/-/raw/master/test/captures"
mkdir -p samples/public
for f in dns-mdns.pcap dns_port.pcap http.pcap http-ooo.pcap retrans-tls.pcap \
         tcp-rst-diagnostic.pcap arp.pcap icmp_ascii.pcapng; do
  [ -s "samples/public/$f" ] || curl -fsSL --retry 3 -o "samples/public/$f" "$BASE/$f"
  echo "ok $f ($(stat -c %s "samples/public/$f") bytes)"
done
