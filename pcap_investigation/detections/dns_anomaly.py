"""Rule 2 - DNS Anomalies (three simple checks, one finding per host and check).

A. Query flood            - one host sends very many DNS queries in a short time.
B. Suspicious domain names - very long or random-looking subdomains. Malware
                             can hide data inside DNS names ("DNS tunnelling").
C. Many failed lookups    - lots of "name does not exist" (NXDOMAIN) answers,
                             typical of malware trying generated domain names.
"""

from __future__ import annotations

import math
from collections import Counter

import pandas as pd

from ..config import DnsConfig
from ..models import Finding, ScoringSignals, format_duration
from .common import max_count_in_window, plural, sample_frames

RULE = "dns_anomaly"
TITLE = "DNS Anomaly"
NXDOMAIN = 3


def shannon_entropy(text: str) -> float:
    """Average bits of information per character (higher = more random)."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    return -sum(c / total * math.log2(c / total) for c in counts.values())


def parent_domain(name: str) -> str:
    labels = [label for label in name.split(".") if label]
    return ".".join(labels[-2:]) if labels else name


def suspicious_name_reason(name: str, cfg: DnsConfig) -> str | None:
    """Return why a DNS name looks suspicious, or None if it looks normal."""
    if not isinstance(name, str) or not name:
        return None
    labels = [label for label in name.split(".") if label]
    longest = max((len(label) for label in labels), default=0)
    if longest >= cfg.long_label_length:
        return f"label of {longest} characters"
    subdomain = "".join(labels[:-2])
    if len(subdomain) >= cfg.entropy_min_length:
        entropy = shannon_entropy(subdomain)
        if entropy >= cfg.entropy_threshold:
            return f"random-looking (entropy {entropy:.1f})"
    return None


def detect(frame: pd.DataFrame, cfg: DnsConfig) -> list[Finding]:
    queries = frame[(frame["dns_qr"] == 0) & frame["src_ip"].notna()]
    responses = frame[(frame["dns_qr"] == 1) & frame["dst_ip"].notna()]
    findings: list[Finding] = []
    for host, rows in queries.groupby("src_ip", sort=True):
        rows = rows.sort_values("ts")
        flood = _check_query_flood(host, rows, cfg)
        if flood:
            findings.append(flood)
        names = _check_suspicious_names(host, rows, cfg)
        if names:
            findings.append(names)
    for host, rows in responses.groupby("dst_ip", sort=True):
        failed = _check_failed_lookups(host, rows.sort_values("ts"), cfg)
        if failed:
            findings.append(failed)
    return findings


def _servers(rows: pd.DataFrame, column: str = "dst_ip") -> list[str]:
    return rows[column].value_counts().index.tolist()


def _base_finding(host, rows, servers, subtype, **kwargs) -> Finding:
    first, last = float(rows["ts"].min()), float(rows["ts"].max())
    return Finding(
        rule=RULE, title=TITLE, subtype=subtype, src_ip=host,
        dst_ip=servers[0] if len(servers) == 1 else None, targets=servers,
        ports=[53], protocol="DNS", first_seen=first, last_seen=last,
        event_count=int(len(rows)), sample_frames=sample_frames(rows), **kwargs,
    )


def _check_query_flood(host: str, rows: pd.DataFrame, cfg: DnsConfig) -> Finding | None:
    times = rows["ts"].tolist()
    peak, start, end = max_count_in_window(times, cfg.query_flood_window)
    if peak < cfg.query_flood_count:
        return None
    window_rows = rows[(rows["ts"] >= start) & (rows["ts"] <= end)]
    seconds = max(end - start, 0.001)
    rate = peak / seconds
    top_names = window_rows["dns_qname"].value_counts().head(3)
    servers = _servers(window_rows)
    return _base_finding(
        host, window_rows, servers, "Query flood",
        event_label="DNS queries",
        summary=f"High number of DNS queries ({peak:,} in {format_duration(seconds)})",
        what_happened=(f"{host} sent {peak:,} DNS queries in {format_duration(seconds)}. Normal devices "
                       "send a few queries per minute; a flood can come from malware, a misconfigured "
                       "program, or an attempt to overload the DNS server."),
        why_flagged=(f"{peak:,} queries within {format_duration(cfg.query_flood_window)}. The rule flags "
                     f"{cfg.query_flood_count} or more."),
        evidence=[
            f"{peak:,} queries between the first and last query of the peak period ({rate:.1f} per second).",
            f"Distinct names queried in that period: {window_rows['dns_qname'].nunique()}.",
            "Most queried: " + "; ".join(f"{name} ({count}x)" for name, count in top_names.items()) + ".",
            "DNS server(s) used: " + ", ".join(servers[:3]) + ".",
        ],
        recommended_steps=[
            f"Find which process on {host} is sending the queries (endpoint logs, EDR, netstat).",
            "Check whether the queried names belong to known software or update services.",
            "Review DNS server load and logs for the same period.",
        ],
        signals=ScoringSignals(
            ratio=peak / cfg.query_flood_count,
            scale_text=f"{peak:,} queries ({peak / cfg.query_flood_count:.1f}x the threshold of {cfg.query_flood_count})",
            fast=f"{rate:.1f} queries per second" if rate >= 3 else None,
        ),
        metrics={"peak_queries": peak, "queries_per_second": round(rate, 2),
                 "distinct_names": int(window_rows["dns_qname"].nunique())},
    )


def _check_suspicious_names(host: str, rows: pd.DataFrame, cfg: DnsConfig) -> Finding | None:
    reasons = rows["dns_qname"].map(lambda n: suspicious_name_reason(n, cfg))
    flagged = rows[reasons.notna()]
    distinct = flagged["dns_qname"].nunique()
    if distinct < cfg.suspicious_name_min_count:
        return None
    parents = flagged["dns_qname"].map(parent_domain).value_counts()
    top_parent, top_share = parents.index[0], parents.iloc[0] / len(flagged)
    lengths = flagged["dns_qname"].str.len()
    servers = _servers(flagged)
    span = float(flagged["ts"].max() - flagged["ts"].min())
    examples = flagged["dns_qname"].drop_duplicates().head(3).tolist()
    return _base_finding(
        host, flagged, servers, "Suspicious domain names",
        event_label="suspicious DNS queries",
        summary=f"{distinct} long or random-looking DNS names (mostly under {top_parent})",
        what_happened=(f"{host} looked up {distinct} unusual domain names with very long or random-looking "
                       "parts. Normal names are short and readable. Long random subdomains are a known way "
                       "to hide data inside DNS traffic (DNS tunnelling)."),
        why_flagged=(f"{distinct} names had a label of {cfg.long_label_length}+ characters or a random-looking "
                     f"subdomain. The rule flags {cfg.suspicious_name_min_count} or more."),
        evidence=[
            f"{distinct} distinct suspicious names in {plural(len(flagged), 'query', 'queries')} "
            f"over {format_duration(span)}.",
            f"Average name length: {lengths.mean():.0f} characters (longest {lengths.max()}).",
            f"{top_share:.0%} of them are under one parent domain: {top_parent}.",
            "Examples: " + "; ".join(examples) + ".",
            f"Reason for the first example: {reasons[flagged.index[0]]}.",
        ],
        recommended_steps=[
            f"Look up {top_parent} (registration date, reputation, threat intelligence).",
            f"Check {host} for unknown software that could be sending data out through DNS.",
            "Compare the amount of DNS data from this host with other hosts.",
            f"Consider blocking {top_parent} at the DNS resolver while investigating.",
        ],
        signals=ScoringSignals(
            ratio=distinct / cfg.suspicious_name_min_count,
            scale_text=f"{distinct} suspicious names ({distinct / cfg.suspicious_name_min_count:.1f}x the threshold of {cfg.suspicious_name_min_count})",
            persistent=f"Continued for {format_duration(span)}" if span >= 300 else None,
            confirmed=(f"{top_share:.0%} of names under one domain ({top_parent}), consistent with data encoded in subdomains"
                       if top_share >= 0.8 else None),
        ),
        metrics={"suspicious_names": int(distinct), "top_parent_domain": top_parent,
                 "top_parent_share": round(float(top_share), 2),
                 "average_name_length": round(float(lengths.mean()), 1)},
    )


def _check_failed_lookups(host: str, rows: pd.DataFrame, cfg: DnsConfig) -> Finding | None:
    failed = rows[rows["dns_rcode"] == NXDOMAIN]
    total, count = len(rows), len(failed)
    if count < cfg.nxdomain_min_count or count / total < cfg.nxdomain_min_ratio:
        return None
    ratio = count / total
    servers = _servers(failed, column="src_ip")
    span = float(failed["ts"].max() - failed["ts"].min())
    unique_names = failed["dns_qname"].nunique()
    examples = failed["dns_qname"].drop_duplicates().head(4).tolist()
    return _base_finding(
        host, failed, servers, "Many failed lookups",
        event_label="failed DNS lookups",
        summary=f"{count} failed DNS lookups (NXDOMAIN, {ratio:.0%} of answers)",
        what_happened=(f"{host} asked for {unique_names} domain names that do not exist. Malware sometimes "
                       "tries many generated names until one works (a 'domain generation algorithm')."),
        why_flagged=(f"{count} NXDOMAIN answers and {ratio:.0%} of all answers failed. The rule flags "
                     f"{cfg.nxdomain_min_count}+ failures with at least {cfg.nxdomain_min_ratio:.0%} failing."),
        evidence=[
            f"{count} of {total} DNS answers to {host} were NXDOMAIN ({ratio:.0%}).",
            f"{unique_names} different non-existent names over {format_duration(span)}.",
            "Examples: " + "; ".join(examples) + ".",
            "Answered by DNS server(s): " + ", ".join(servers[:3]) + ".",
        ],
        recommended_steps=[
            f"Check {host} for malware or a misconfigured application.",
            "See whether any of the generated names eventually resolved, and to which IP address.",
            f"Look for connections from {host} to any address that did resolve.",
        ],
        signals=ScoringSignals(
            ratio=count / cfg.nxdomain_min_count,
            scale_text=f"{count} failed lookups ({count / cfg.nxdomain_min_count:.1f}x the threshold of {cfg.nxdomain_min_count})",
            persistent=f"Continued for {format_duration(span)}" if span >= 300 else None,
            confirmed=f"{ratio:.0%} of lookups failed" if ratio >= 0.8 else None,
        ),
        metrics={"nxdomain": int(count), "answers": int(total), "failure_ratio": round(ratio, 2),
                 "unique_names": int(unique_names)},
    )
