# pcaplens

Analyses a pcap or pcapng capture with Scapy and writes a self-contained HTML report: top talkers
by bytes and packets, a protocol breakdown, DNS queries and NXDOMAIN rates, TCP retransmissions and
resets, and findings for port scans, ping sweeps and DNS tunneling.

```bash
pip install -e '.[dev]'
pytest                                            # 47 tests

pcaplens analyze samples/mixed.pcap -o report.html          # open report.html in a browser
pcaplens analyze capture.pcap.gz -o r.html --json r.json --fail-on high   # exit 1 on a high finding
pcaplens make-samples out/                        # crafted benign, scan, sweep, tunnel, mixed pcaps
scripts/fetch-samples.sh                          # public Wireshark test captures into samples/public/
```

The report has no JavaScript and makes no network requests; charts are inline SVG and follow light or
dark mode. Open [docs/sample-report.html](docs/sample-report.html) to see one (generated from `samples/mixed.pcap`).

## What it flags

| Finding | Rule (defaults, all adjustable in `detect.Thresholds`) |
|---|---|
| `port-scan` | one source sends bare SYN (or FIN, NULL or Xmas) probes to at least 20 distinct host:port targets within 60 s, and no more than half of them get a SYN-ACK. Described as a port scan of one host, a host sweep on one port, or a block scan, with how many probes were answered and which ports turned out open |
| `ping-sweep` | ICMP/ICMPv6 echo requests to at least 20 hosts within 60 s |
| `dns-tunnel` | at least 10 unique names under one registered domain, 60% or more with a label of 20+ characters, Shannon entropy of 3.3 bits/char or more and few hyphens (hex data scores about 4, base32 about 4.4, ordinary names 2.5 to 3.2) |
| `dns-nxdomain` | a client with at least 20 NXDOMAIN responses making up half or more of its answers (DGA malware or a broken resolver) |
| `tcp-retrans` | at least 20 retransmissions making up 5% or more of TCP packets (low severity) |

TCP accounting: a retransmission is a segment whose sequence number was already seen in that direction
with the same or smaller length; a new segment below the highest sequence seen is counted as out of order
instead. Sequence wraparound is not handled.

## Tested on

- Crafted captures from `pcaplens make-samples`: a benign mix, an `nmap -sS`-style scan (200 ports, 3 open), a
  60-host sweep on port 445 and a base32 DNS tunnel. Each is flagged, and the benign one is clean.
- Eight public captures from the Wireshark test suite (DNS, mDNS, HTTP, TCP reset, retransmission, ICMP):
  parsed without errors and no false findings. None of them contains a scan, so scan detection itself is only
  proven on synthetic traffic.

## Limits and caveats

- Scapy is pure Python and slow: about 5,000 packets per second when reading on the sandbox machine (measured on a 12,000-packet file), so multi-gigabyte captures take a while.
  Packets are streamed, but `analyze` keeps one small record per packet for the detectors.
- Scan and tunnel rules are heuristics. A vulnerability scanner you run yourself looks like a scan; CDNs that use random-looking
  hostnames can look like a tunnel; a scan whose probes are all answered by SYN-ACK (every port open) is skipped.
- IPv6 extension headers are skipped, but fragments are not reassembled. DNS over TCP, DoH and DoT are not parsed.
- Capture link types Scapy cannot decode (for example Frame Relay) come through as unanalysable packets.
- Protocol labels come from well-known ports, not payload inspection.
- The report was checked in Chromium at 1000 px wide only.

## Layout

`pcaplens/reader.py` (packets to records), `analyze.py` (statistics), `detect.py` (findings), `report.py` (HTML and SVG),
`samples.py` (crafted captures), `cli.py`; `PLAN.md` has the Scapy vs pyshark comparison and design.
