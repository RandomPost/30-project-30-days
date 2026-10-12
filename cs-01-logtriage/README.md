# logtriage

Parses Linux auth logs (`auth.log` or `journalctl -o short-iso` exports), groups failed
SSH logins by source IP and username, and flags likely brute-force sources.

```bash
pip install -e .
logtriage generate sample.log               # synthetic data, no real logs needed
logtriage analyze sample.log --year 2026    # ranked table
logtriage analyze sample.log -n 10 -w 30 --json report.json
```

A source is flagged when it has **more than N failures (`-n`, default 5) inside any
sliding window of W seconds (`-w`, default 60)**. Exit code is 1 if anything is flagged,
so it can gate scripts. Syslog lines have no year, so pass `--year` (default: current).

Tests: `pytest`.
