# NE-03 plan: pcaplens

Goal: `pcaplens analyze capture.pcap -o report.html` reports top talkers (bytes and packets), a
protocol breakdown, DNS queries and NXDOMAIN rates, TCP retransmissions and resets, and flags port
scans and DNS tunneling. Done when the HTML report correctly flags a scan in a sample capture.

## Scapy or pyshark?

| | Scapy | pyshark |
|---|---|---|
| Dependency | pure Python, `pip install scapy` | a wrapper that shells out to `tshark` (Wireshark), which is not installed here and is not pip-installable |
| Dissection | enough for Ethernet, IP, IPv6, TCP, UDP, ICMP, ARP, DNS | far broader (full Wireshark dissectors, reassembly) |
| Building test captures | can craft and write packets, so tests need no binary fixtures | read-only |
| Speed on big files | slow (pure Python), streaming `PcapReader` keeps memory flat | faster dissection but one tshark process and XML/JSON parsing |
| Failure mode | none external | breaks if tshark is missing or the wrong version |

Decision: **Scapy**. Everything asked for sits at L2 to L4 plus DNS, which Scapy handles, and being
able to craft and write pcaps lets the tests use small generated captures. The cost is speed, so
the reader streams packets and reduces each to a small record immediately.

## Design

1. `reader.py`: stream a pcap/pcapng (also `.gz`) and reduce each packet to a `Pkt` record (time,
   length, addresses, L4 protocol, ports, TCP flags/seq/payload length, DNS fields, ICMP type).
2. `analyze.py`: pure functions over `Pkt` iterables: talkers, protocols, DNS stats, TCP health,
   timeline. One pass, no Scapy objects retained.
3. `detect.py`: heuristics over the same records, each returning `Finding(kind, severity, subject,
   summary, evidence)`:
   - port scan: one source sending bare SYNs (or FIN/NULL/Xmas probes) to many distinct ports on a host
     (vertical) or one port on many hosts (sweep) inside a time window, with how many probes were answered
   - ICMP ping sweep
   - DNS tunneling: many unique, long, high-entropy subdomains under one parent domain
4. `report.py`: one self-contained HTML file (inline CSS and SVG charts, no JavaScript or CDN).
5. `samples.py` + `cli.py`: `analyze`, `make-samples` (crafted benign, scan, tunnel captures). Public captures
   come from the Wireshark test suite via `scripts/fetch-samples.sh` (not committed: GPL project).

## Heuristic thresholds (all configurable)

- scan: at least 20 distinct (host, port) targets from one source within 60 s of bare SYNs
- tunnel: at least 10 unique queries under one domain, at least 60% of them with a subdomain label of 20+
  characters and Shannon entropy of 3.3 bits/char or more (hex data tops out near 4, base32 near 5, ordinary
  hostnames sit around 2.5 to 3.2)
- retransmission: a data segment (or SYN) whose sequence range was already seen in that direction

## Tasks

- [x] compare Scapy and pyshark, pick one
- [x] reader and `Pkt`
- [x] analyses + tests on crafted captures
- [x] detections + tests (scan, sweep, tunnel, and no false positives on benign and public captures)
- [x] HTML report, check it visually
- [x] CLI, README, CLAUDE.md, push
