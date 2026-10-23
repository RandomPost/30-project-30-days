"""Heuristic detections. Every threshold is a parameter; every finding carries evidence."""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Iterable

from .analyze import Analysis
from .models import ACK, FIN, PSH, RST, SYN, URG, Finding, Pkt

XMAS = FIN | PSH | URG


@dataclass(frozen=True)
class Thresholds:
    scan_targets: int = 20  # distinct (host, port) probes from one source...
    scan_window: float = 60.0  # ...inside this many seconds
    scan_max_answered: float = 0.5  # a scan is mostly unanswered; browsing is not
    sweep_hosts: int = 20  # ICMP echo to this many hosts in the window
    tunnel_min_queries: int = 10
    tunnel_min_label: int = 20  # characters in the longest subdomain label
    tunnel_min_entropy: float = 3.3  # bits per character
    tunnel_min_fraction: float = 0.6
    tunnel_max_hyphens: float = 0.05  # hyphen share allowed in an "encoded" label
    nx_min_responses: int = 20
    nx_min_rate: float = 0.5
    retrans_min: int = 20
    retrans_min_rate: float = 0.05


def looks_encoded(label: str, t: "Thresholds") -> bool:
    """A long, high-entropy label that is not an ordinary hyphenated hostname.

    Encoded data (hex, base32, base64) is long and dense but rarely contains hyphens,
    whereas names like `eu-west-1-service-api` are long with entropy around 3.5 too.
    """
    if len(label) < t.tunnel_min_label or entropy(label) < t.tunnel_min_entropy:
        return False
    return label.count("-") / len(label) <= t.tunnel_max_hyphens


def entropy(text: str) -> float:
    """Shannon entropy in bits per character."""
    if not text:
        return 0.0
    n = len(text)
    return max(0.0, -sum(c / n * math.log2(c / n) for c in Counter(text).values()))


# Second-level labels that make the registered domain three labels long (example.co.uk).
SECOND_LEVEL = {"co", "com", "org", "net", "gov", "edu", "ac", "or", "ne", "go"}
IGNORED_SUFFIXES = (".local", ".arpa", ".lan", ".home", ".internal")


def split_domain(qname: str) -> tuple[str, str] | None:
    """(registered domain, subdomain part) or None if there is no subdomain."""
    labels = qname.split(".")
    keep = (
        3
        if len(labels) > 2 and len(labels[-1]) == 2 and labels[-2] in SECOND_LEVEL
        else 2
    )
    if len(labels) <= keep:
        return None
    return ".".join(labels[-keep:]), ".".join(labels[:-keep])


def detect_scans(packets: Iterable[Pkt], t: Thresholds) -> list[Finding]:
    probes: dict[str, list[tuple[float, str, int, str]]] = defaultdict(list)
    seen: set[tuple] = set()
    replies: dict[tuple[str, str, int], set[str]] = defaultdict(
        set
    )  # (scanner, host, port)
    echoes: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for p in packets:
        if p.l4 == "tcp" and p.flags is not None:
            if p.flags == SYN:
                kind = "SYN"
            elif p.flags == FIN:
                kind = "FIN"
            elif p.flags == 0:
                kind = "NULL"
            elif p.flags == XMAS:
                kind = "XMAS"
            else:
                kind = ""
            if kind:
                key = (p.src, p.dst, p.dport, kind)
                if key not in seen:  # a retransmitted probe is still one target
                    seen.add(key)
                    probes[p.src].append((p.ts, p.dst, p.dport, kind))
            elif p.flags & SYN and p.flags & ACK:
                replies[(p.dst, p.src, p.sport)].add("open")
            elif p.flags & RST:
                replies[(p.dst, p.src, p.sport)].add("closed")
        elif p.l4 in ("icmp", "icmp6") and p.icmp_type in (8, 128):
            echoes[p.src].append((p.ts, p.dst))
    findings = []
    for src, items in probes.items():
        best = _best_window(items, t.scan_window)
        if len(best) < t.scan_targets:
            continue
        hosts = {h for _, h, _, _ in best}
        ports = {pt for _, _, pt, _ in best}
        states = [replies.get((src, h, pt), ()) for _, h, pt, _ in best]
        answered = sum(1 for st in states if st)
        ratio_open = sum(1 for st in states if "open" in st) / len(best)
        open_ports = sorted(
            {pt for (_, _, pt, _), st in zip(best, states) if "open" in st}
        )
        if ratio_open > t.scan_max_answered:
            continue  # most probes got a SYN-ACK: that is normal client behaviour
        kinds = sorted({k for _, _, _, k in best})
        if len(hosts) == 1:
            shape = f"port scan of {next(iter(hosts))} ({len(ports)} ports)"
        elif len(ports) <= 3:
            shape = f"host sweep on port {','.join(map(str, sorted(ports)))} ({len(hosts)} hosts)"
        else:
            shape = f"scan of {len(hosts)} hosts / {len(ports)} ports"
        duration = best[-1][0] - best[0][0]
        findings.append(
            Finding(
                "port-scan",
                "high" if len(best) >= 5 * t.scan_targets else "medium",
                src,
                f"{src}: {shape}, {'/'.join(kinds)} probes, {len(best)} targets in {duration:.1f}s",
                {
                    "probes": len(best),
                    "hosts": len(hosts),
                    "ports": len(ports),
                    "probe_types": kinds,
                    "duration_s": round(duration, 2),
                    "answered": answered,
                    "open_ports_found": open_ports[:20],
                    "sample_ports": sorted(ports)[:15],
                    "first_seen": best[0][0],
                },
            )
        )
    for src, items in echoes.items():
        best = _best_window([(ts, h, 0, "") for ts, h in items], t.scan_window)
        hosts = {h for _, h, _, _ in best}
        if len(hosts) >= t.sweep_hosts:
            findings.append(
                Finding(
                    "ping-sweep",
                    "medium",
                    src,
                    f"{src}: ICMP echo to {len(hosts)} hosts in "
                    f"{best[-1][0] - best[0][0]:.1f}s",
                    {"hosts": len(hosts), "first_seen": best[0][0]},
                )
            )
    return findings


def _best_window(items, window: float):
    """The items in the `window`-second span holding the most distinct (host, port)."""
    items = sorted(items)
    counts: Counter = Counter()
    best_size, best = 0, (0, -1)
    lo = 0
    for hi, item in enumerate(items):
        counts[(item[1], item[2])] += 1
        while item[0] - items[lo][0] > window:
            k = (items[lo][1], items[lo][2])
            counts[k] -= 1
            if not counts[k]:
                del counts[k]
            lo += 1
        if len(counts) > best_size:
            best_size, best = len(counts), (lo, hi)
    return items[best[0] : best[1] + 1]


def detect_dns(packets: Iterable[Pkt], a: Analysis, t: Thresholds) -> list[Finding]:
    per_domain: dict[str, dict[str, tuple[str, str]]] = defaultdict(dict)
    clients: dict[str, set[str]] = defaultdict(set)
    qtypes: dict[str, Counter] = defaultdict(Counter)
    for p in packets:
        d = p.dns
        if d is None or d.is_response or d.qname.endswith(IGNORED_SUFFIXES):
            continue
        parts = split_domain(d.qname)
        if parts is None:
            continue
        domain, sub = parts
        per_domain[domain][d.qname] = (sub, d.qtype)
        clients[domain].add(p.src)
        qtypes[domain][d.qtype] += 1
    findings = []
    for domain, names in per_domain.items():
        sus = []
        for qname, (sub, _) in names.items():
            if any(looks_encoded(label, t) for label in sub.split(".")):
                sus.append((qname, sub))
        if (
            len(sus) < t.tunnel_min_queries
            or len(sus) / len(names) < t.tunnel_min_fraction
        ):
            continue
        subs = [s for _, s in sus]
        findings.append(
            Finding(
                "dns-tunnel",
                "high" if len(sus) >= 5 * t.tunnel_min_queries else "medium",
                domain,
                f"{domain}: {len(sus)} of {len(names)} unique names look like encoded data "
                f"(avg subdomain {sum(map(len, subs)) / len(subs):.0f} chars, "
                f"{sum(entropy(s.replace('.', '')) for s in subs) / len(subs):.2f} bits/char)",
                {
                    "unique_names": len(names),
                    "suspicious": len(sus),
                    "clients": sorted(clients[domain]),
                    "query_types": dict(qtypes[domain]),
                    "examples": [q for q, _ in sus[:3]],
                },
            )
        )
    d = a.dns
    for client, nx in d.nx_by_client.items():
        total = d.responses_by_client[client]
        if nx >= t.nx_min_responses and nx / total >= t.nx_min_rate:
            findings.append(
                Finding(
                    "dns-nxdomain",
                    "medium",
                    client,
                    f"{client}: {nx} of {total} DNS responses were NXDOMAIN "
                    f"({nx / total:.0%}), typical of DGA malware or a misconfigured resolver",
                    {"nxdomain": nx, "responses": total},
                )
            )
    return findings


def detect_tcp(a: Analysis, t: Thresholds) -> list[Finding]:
    s = a.tcp
    if (
        s.retransmissions >= t.retrans_min
        and s.retransmission_rate >= t.retrans_min_rate
    ):
        top = s.retrans_flows.most_common(3)
        return [
            Finding(
                "tcp-retrans",
                "low",
                "tcp",
                f"{s.retransmissions} retransmissions ({s.retransmission_rate:.1%} of TCP packets)",
                {"worst_flows": top},
            )
        ]
    return []


def detect_all(
    packets: list[Pkt], a: Analysis, t: Thresholds | None = None
) -> list[Finding]:
    t = t or Thresholds()
    found = detect_scans(packets, t) + detect_dns(packets, a, t) + detect_tcp(a, t)
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(found, key=lambda f: (order[f.severity], f.kind, f.subject))
