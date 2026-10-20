"""Offline IP -> country lookup from a CSV of address ranges.

Format (one range per line, IPv4 or IPv6): `start_ip,end_ip,country_code`. This is
the layout of the free DB-IP "IP to Country Lite" CSV, so a real database can be
dropped in with `--geoip`. `data/geoip-sample.csv` is a tiny demo file only.
"""

from __future__ import annotations

import bisect
import csv
import ipaddress
from pathlib import Path

PRIVATE = "private"
UNKNOWN = "??"


class GeoDB:
    def __init__(self, ranges: list[tuple[int, int, int, str]]):
        # (version, start, end, country), sorted so lookups can bisect
        self._ranges = sorted(ranges)
        self._keys = [(v, s) for v, s, _e, _c in self._ranges]

    @classmethod
    def load(cls, path: str | Path) -> "GeoDB":
        ranges = []
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.reader(fh):
                if len(row) < 3 or row[0].lstrip().startswith("#"):
                    continue
                try:
                    start = ipaddress.ip_address(row[0].strip())
                    end = ipaddress.ip_address(row[1].strip())
                except ValueError:
                    continue
                if start.version != end.version or int(end) < int(start):
                    continue
                ranges.append((start.version, int(start), int(end), row[2].strip()))
        return cls(ranges)

    def lookup(self, ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return UNKNOWN
        i = bisect.bisect_right(self._keys, (addr.version, int(addr))) - 1
        if i >= 0:
            v, s, e, country = self._ranges[i]
            if v == addr.version and s <= int(addr) <= e:
                return country
        if addr.is_private or addr.is_loopback or addr.is_link_local:
            return PRIVATE
        return UNKNOWN


COUNTRY_NAMES = {
    "US": "United States",
    "CN": "China",
    "RU": "Russia",
    "DE": "Germany",
    "NL": "Netherlands",
    "BR": "Brazil",
    "IN": "India",
    "KR": "South Korea",
    "VN": "Vietnam",
    "FR": "France",
    "GB": "United Kingdom",
    "UA": "Ukraine",
    "XA": "Sample A",
    "XB": "Sample B",
    "XC": "Sample C",
    PRIVATE: "Private network",
    UNKNOWN: "Unknown",
}


def country_name(code: str) -> str:
    return COUNTRY_NAMES.get(code, code)
