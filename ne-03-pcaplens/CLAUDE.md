# pcaplens

Python CLI that analyses pcap/pcapng files with Scapy and writes a self-contained HTML report.

## Layout
- `pcaplens/models.py`: `Pkt`, `Dns`, `Finding`; plain records, no Scapy objects
- `pcaplens/reader.py`: streams a capture, reduces each packet to a `Pkt` (only module that touches Scapy packets besides `samples.py`)
- `pcaplens/analyze.py`: talkers, protocols, DNS and TCP statistics; pure
- `pcaplens/detect.py`: scan, sweep, DNS tunnel, NXDOMAIN and retransmission findings; `Thresholds` holds every cutoff
- `pcaplens/report.py`: HTML + inline SVG; escapes every string that comes from a capture
- `pcaplens/samples.py`: deterministic crafted captures used by tests and demos
- `samples/mixed.pcap` is committed; `samples/public/` is downloaded by `scripts/fetch-samples.sh` and gitignored
- `tests/`: pytest; `conftest.py` builds the crafted captures once per session

## Commands
- Install: `pip install -e '.[dev]'`
- Test: `python3 -m pytest`
- Format: `python3 -m black --target-version py310 .`
- Try it: `pcaplens analyze samples/mixed.pcap -o /tmp/r.html`

## Conventions
- Type hints; `from __future__ import annotations`; black, 88 cols
- Detectors take `Pkt` records and thresholds, never Scapy objects, so they can be tested with hand-built records
- Anything from a capture is untrusted: escape it in the report (a test injects `<script>`)
- Every new detection needs a positive test, a "looks similar but is benign" test, and a run over the public captures
- Do not treat a real-capture pass as proof of scan detection: none of the public captures contains a scan
- Scapy 2.6+ returns lists for DNS `qd`; keep `reader._dns` working with both shapes
