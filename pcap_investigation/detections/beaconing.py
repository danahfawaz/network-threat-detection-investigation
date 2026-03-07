"""Rule 5 - Periodic / Beacon-Like Connections.

Malware often "checks in" with its control server on a timer - for example
every 60 seconds. People do not browse on a timer, so very regular gaps
between connections to the same server are suspicious.

For each (source, destination, port) we list when each new connection
started, measure the gaps, and flag the flow when:
  * there are at least ``min_connections`` connections,
  * the typical (median) gap is between ``min_interval`` and ``max_interval``,
  * at least ``min_regular_fraction`` of gaps are within +/- ``tolerance`` of it.
"""

from __future__ import annotations

import statistics

import pandas as pd

from ..config import BeaconConfig
from ..models import Finding, ScoringSignals, format_bytes, format_duration
from ..normalize import syn_only
from ..traffic import ip_scope, is_unicast, service_name
from .common import sample_frames

RULE = "beaconing"
TITLE = "Beacon-Like Connections"


def connection_starts(frame: pd.DataFrame, cfg: BeaconConfig) -> pd.DataFrame:
    """One row per new connection: TCP SYNs, and UDP packets after a quiet gap."""
    tcp = frame[syn_only(frame) & frame["src_ip"].notna()] \
        .sort_values("ts").drop_duplicates(["src_ip", "dst_ip", "sport", "dport"])
    udp = frame[(frame["protocol"] == "UDP") & frame["src_ip"].notna()].sort_values("ts")
    gaps = udp.groupby(["src_ip", "dst_ip", "dport"])["ts"].diff()
    udp_starts = udp[gaps.isna() | (gaps > cfg.udp_session_gap)]
    starts = pd.concat([tcp, udp_starts])
    starts = starts[~starts["dport"].isin(cfg.ignore_ports)]
    unicast = starts["dst_ip"].map(is_unicast).astype(bool)
    return starts.loc[unicast]


def regularity(times: list[float], tolerance: float) -> tuple[float, float, float]:
    """Return (median gap, share of regular gaps, relative spread of gaps)."""
    gaps = [b - a for a, b in zip(times, times[1:])]
    median = statistics.median(gaps)
    if median <= 0:
        return median, 0.0, float("inf")
    regular = sum(1 for g in gaps if abs(g - median) <= tolerance * median) / len(gaps)
    spread = statistics.pstdev(gaps) / median
    return median, regular, spread


def detect(frame: pd.DataFrame, cfg: BeaconConfig) -> list[Finding]:
    starts = connection_starts(frame, cfg)
    findings = []
    for (src, dst, dport, protocol), rows in starts.groupby(["src_ip", "dst_ip", "dport", "protocol"], sort=True):
        if len(rows) < cfg.min_connections:
            continue
        rows = rows.sort_values("ts")
        times = rows["ts"].tolist()
        median, regular, spread = regularity(times, cfg.tolerance)
        if not (cfg.min_interval <= median <= cfg.max_interval) or regular < cfg.min_regular_fraction:
            continue
        findings.append(_build(frame, rows, src, dst, int(dport), protocol, median, regular, spread, cfg))
    return findings


def _build(frame, rows, src, dst, dport, protocol, median, regular, spread, cfg) -> Finding:
    times = rows["ts"].tolist()
    gaps = [b - a for a, b in zip(times, times[1:])]
    count = len(times)
    first, last = times[0], times[-1]
    span = last - first
    flow = frame[(frame["src_ip"] == src) & (frame["dst_ip"] == dst) & (frame["dport"] == dport)]
    avg_bytes = flow["length"].sum() / count
    name = service_name(dport)
    target = f"{dst}:{dport}" + (f" ({name})" if name else "")
    external = ip_scope(dst) == "External"

    return Finding(
        rule=RULE, title=TITLE, subtype="Periodic connections", src_ip=src, dst_ip=dst, targets=[dst],
        ports=[dport], protocol=protocol, first_seen=first, last_seen=last,
        event_count=count, event_label="connections",
        summary=f"{count} connections every ~{format_duration(median)} to {target}",
        what_happened=(f"{src} connected to {target} {count} times, about every {format_duration(median)}, "
                       f"for {format_duration(span)}. People do not browse on a timer; regular check-ins like "
                       "this are typical of malware contacting its control server (beaconing). Some "
                       "legitimate software (update checks, monitoring agents) also does this."),
        why_flagged=(f"{regular:.0%} of the gaps were within +/-{cfg.tolerance:.0%} of {format_duration(median)}. "
                     f"The rule flags {cfg.min_connections}+ connections with at least "
                     f"{cfg.min_regular_fraction:.0%} regular gaps."),
        evidence=[
            f"{count} connections from {src} to {target} between first and last seen ({format_duration(span)}).",
            f"Typical gap: {format_duration(median)} (shortest {format_duration(min(gaps))}, "
            f"longest {format_duration(max(gaps))}).",
            f"{regular:.0%} of gaps within +/-{cfg.tolerance:.0%} of the typical gap; "
            f"timing varies by about {spread:.0%}.",
            f"Average data per connection (client to server): {format_bytes(avg_bytes)}"
            + (" - small, check-in sized." if avg_bytes < 2048 else "."),
            ("Destination is outside the local network." if external else "Destination is inside the local network."),
        ],
        recommended_steps=[
            f"Check {dst} against threat intelligence and look up who owns it.",
            f"Find the process on {src} that makes these connections (EDR, netstat, Sysmon network events).",
            "Check if known software (updater, monitoring agent) explains the timer.",
            f"If unexplained, isolate {src} and look for persistence (scheduled tasks, services, startup items).",
        ],
        signals=ScoringSignals(
            ratio=count / cfg.min_connections,
            scale_text=f"{count} connections ({count / cfg.min_connections:.1f}x the threshold of {cfg.min_connections})",
            sensitive=f"Destination {dst} is an external address" if external else None,
            persistent=f"Kept going for {format_duration(span)}" if span >= 300 else None,
            confirmed=(f"Very regular timing: gaps vary by only {spread:.0%}" if spread <= 0.05 else None),
        ),
        sample_frames=sample_frames(rows),
        metrics={"connections": count, "median_interval_seconds": round(median, 2),
                 "regular_fraction": round(regular, 2), "timing_spread": round(spread, 3),
                 "average_bytes_per_connection": round(float(avg_bytes), 1)},
    )
