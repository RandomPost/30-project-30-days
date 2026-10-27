"""The contract every vendor parser module follows.

A parser module (frr.py, eos.py, ios.py) defines:

    VENDOR: str                      # "frr" | "eos" | "ios"
    NEIGHBOR_COMMAND: str            # one command that prints all neighbours with detail
    HOSTNAME_COMMAND: str            # one command whose output parse_hostname() reads
    def parse_neighbors(text: str) -> list[Neighbor]
    def parse_hostname(text: str) -> str

Rules:
- Pure functions: take the raw command output, return plain data, never raise on an
  empty "no neighbours" output (return []). Raise ValueError only for output that is
  clearly not from this command at all.
- Strip domain suffixes from names (sw1.example.net -> sw1) so the same device has one
  name however it is reported.
- Keep interface names exactly as the vendor prints them (do not abbreviate/expand).
"""
