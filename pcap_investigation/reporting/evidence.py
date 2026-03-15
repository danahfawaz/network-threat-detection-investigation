"""Helpers that turn an AnalysisResult into plain rows for tables and exports."""

from __future__ import annotations

import math

import pandas as pd

from ..models import SEVERITY_ORDER, Finding, format_ts
from ..traffic import hosts_table, ip_scope

PACKET_COLUMNS = ["frame", "time", "source", "destination", "protocol", "src_port", "dst_port",
                  "flags", "length", "info"]


def _clean(value):
    if value is None:
        return None
    if isinstance(value, float) and math.isnan(value):
        return None
    if value is pd.NA:
        return None
    if hasattr(value, "item"):  # numpy / pandas scalar
        return value.item()
    return value


def packet_info(row) -> str:
    if row.get("protocol") == "ARP":
        op = "reply" if row.get("arp_op") == 2 else "request"
        if op == "reply":
            return f"ARP reply: {row.get('arp_psrc')} is at {row.get('arp_hwsrc')}"
        return f"ARP request: who has {row.get('arp_pdst')}? tell {row.get('arp_psrc')}"
    if isinstance(row.get("dns_qname"), str):
        kind = "response" if row.get("dns_qr") == 1 else "query"
        rcode = row.get("dns_rcode")
        status = " (NXDOMAIN)" if kind == "response" and rcode == 3 else ""
        return f"DNS {kind}: {row['dns_qname']}{status}"
    return ""


def packet_rows(frame: pd.DataFrame, frames: list[int]) -> list[dict]:
    """Readable rows for the given packet (frame) numbers."""
    subset = frame[frame["frame"].isin(frames)].sort_values("frame")
    rows = []
    for _, row in subset.iterrows():
        data = row.to_dict()
        rows.append({
            "frame": int(data["frame"]),
            "time": format_ts(float(data["ts"]), with_date=True),
            "source": _clean(data.get("src_ip")) or _clean(data.get("src_mac")) or "",
            "destination": _clean(data.get("dst_ip")) or _clean(data.get("dst_mac")) or "",
            "protocol": _clean(data.get("protocol")) or "",
            "src_port": _clean(data.get("sport")),
            "dst_port": _clean(data.get("dport")),
            "flags": _clean(data.get("tcp_flags_str")) or "",
            "length": int(data["length"]),
            "info": packet_info({k: _clean(v) for k, v in data.items()}),
        })
    return rows


def score_explanation(finding: Finding) -> list[str]:
    return [f"+{factor.points} {factor.label}: {factor.reason}" for factor in finding.score_factors]


def involved_hosts(result) -> list[dict]:
    """Every host named in a finding, with its role and highest severity."""
    hosts: dict[str, dict] = {}

    def add(address, role, finding):
        if not address:
            return
        entry = hosts.setdefault(address, {"host": address, "roles": set(), "findings": [],
                                           "severities": []})
        entry["roles"].add(role)
        if finding.id not in entry["findings"]:
            entry["findings"].append(finding.id)
            entry["severities"].append(finding.severity)

    for finding in result.findings:
        add(finding.source_label, "Source", finding)
        for target in finding.targets:
            add(target, "Target", finding)

    traffic = hosts_table(result.packets).set_index("ip") if len(result.packets) else None
    rows = []
    for address, entry in hosts.items():
        worst = min(entry["severities"], key=SEVERITY_ORDER.index)
        sent = received = None
        if traffic is not None and address in traffic.index:
            sent = int(traffic.loc[address, "packets_sent"])
            received = int(traffic.loc[address, "packets_received"])
        scope = ip_scope(address)
        if scope == "Unknown" and len(address.split(":")) == 6:
            scope = "MAC address"
        rows.append({
            "host": address,
            "scope": scope,
            "role": " & ".join(sorted(entry["roles"])),
            "findings": ", ".join(entry["findings"]),
            "highest_severity": worst,
            "packets_sent": sent,
            "packets_received": received,
        })
    rows.sort(key=lambda r: (SEVERITY_ORDER.index(r["highest_severity"]), r["role"] != "Source & Target",
                             r["role"] != "Source", r["host"]))
    return rows


def recommended_next_steps(result, limit: int = 6) -> list[str]:
    """Investigation steps from the most serious findings first, without duplicates."""
    steps: list[str] = []
    for finding in sorted(result.findings, key=lambda f: -f.score):
        for step in finding.recommended_steps[:2]:
            text = f"[{finding.id}] {step}"
            if step not in {s.split('] ', 1)[1] for s in steps}:
                steps.append(text)
            if len(steps) >= limit:
                return steps
    return steps
