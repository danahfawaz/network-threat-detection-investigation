"""Rule 1 - Port Scan / SYN Scan.

Idea: a scanner sends connection requests (TCP SYN without ACK) to many
different ports or hosts in a short time, to find which services are open.

Flag when one source sends SYNs to at least ``min_targets`` different
(destination, port) pairs within ``window_seconds``.
"""

from __future__ import annotations

import pandas as pd

from ..config import ConnectionAttemptConfig, PortScanConfig
from ..models import Finding, ScoringSignals, format_duration
from ..normalize import syn_only
from ..traffic import port_label
from .common import classify_syn_answers, max_distinct_in_window, plural, sample_frames

RULE = "port_scan"
TITLE = "Port Scan"
SENSITIVE_PORTS = set(ConnectionAttemptConfig().login_ports)
# Shown first in explanations: the ports an attacker most wants to find.
_PORT_PRIORITY = [22, 3389, 445, 23, 5900, 3306, 1433, 5432, 21, 25, 110, 143]


def detect(frame: pd.DataFrame, cfg: PortScanConfig) -> list[Finding]:
    syns = frame[syn_only(frame) & frame["src_ip"].notna()]
    findings = []
    for src, rows in syns.groupby("src_ip", sort=True):
        rows = rows.sort_values("ts")
        times = rows["ts"].tolist()
        keys = list(zip(rows["dst_ip"], rows["dport"]))
        peak, peak_start, peak_end = max_distinct_in_window(times, keys, cfg.window_seconds)
        if peak < cfg.min_targets:
            continue
        findings.append(_build_finding(frame, rows, src, peak, peak_start, peak_end, cfg))
    return findings


def _scan_episode(rows: pd.DataFrame, cfg: PortScanConfig, peak_start: float, peak_end: float) -> pd.DataFrame:
    """SYNs that belong to the scan: the peak window extended while probes keep
    arriving less than one window apart."""
    times = rows["ts"]
    start, end = peak_start, peak_end
    before = rows[times < start]
    for ts in reversed(before["ts"].tolist()):
        if start - ts > cfg.window_seconds / 4:
            break
        start = ts
    after = rows[times > end]
    for ts in after["ts"].tolist():
        if ts - end > cfg.window_seconds / 4:
            break
        end = ts
    return rows[(times >= start) & (times <= end)]


def _build_finding(frame, rows, src, peak, peak_start, peak_end, cfg) -> Finding:
    episode = _scan_episode(rows, cfg, peak_start, peak_end)
    answers = classify_syn_answers(frame, episode)
    targets = sorted(episode["dst_ip"].unique().tolist())
    ports = sorted(int(p) for p in episode["dport"].unique())
    pairs = episode[["dst_ip", "dport"]].drop_duplicates()
    open_pairs = episode[answers == "open"][["dst_ip", "dport"]].drop_duplicates()
    open_ports = sorted(int(p) for p in open_pairs["dport"].unique())
    closed = int((answers == "closed").sum())
    no_answer = int((answers == "none").sum())
    first, last = float(episode["ts"].min()), float(episode["ts"].max())
    duration = last - first
    rate = len(episode) / duration if duration > 0 else float(len(episode))
    sensitive_hit = sorted(SENSITIVE_PORTS.intersection(ports),
                           key=lambda p: _PORT_PRIORITY.index(p) if p in _PORT_PRIORITY else 99)

    target_text = targets[0] if len(targets) == 1 else plural(len(targets), "host")
    summary = (f"SYN scan of {plural(len(pairs), 'port')} on {target_text}"
               if len(targets) == 1 else
               f"SYN scan of {plural(len(pairs), 'host/port pair')} across {target_text}")

    evidence = [
        f"{plural(len(episode), 'connection request')} (SYN) sent in {format_duration(duration)} "
        f"(about {rate:.1f} per second).",
        f"{plural(len(pairs), 'different target')} contacted: {plural(len(ports), 'port')} on "
        f"{plural(len(targets), 'host')}.",
        f"Peak: {peak} different targets within {format_duration(peak_end - peak_start)} "
        f"(threshold: {cfg.min_targets} within {format_duration(cfg.window_seconds)}).",
        f"Answers: {plural(len(open_pairs), 'port')} accepted (SYN-ACK), {closed} refused (RST), "
        f"{no_answer} with no answer.",
    ]
    if open_ports:
        evidence.append("Open ports found: " + ", ".join(port_label(p) for p in open_ports) + ".")
    evidence.append("Ports probed: " + ", ".join(str(p) for p in ports[:40])
                    + (" ..." if len(ports) > 40 else "") + ".")

    signals = ScoringSignals(
        ratio=len(pairs) / cfg.min_targets,
        scale_text=f"{len(pairs)} targets ({len(pairs) / cfg.min_targets:.1f}x the threshold of {cfg.min_targets})",
        fast=(f"{len(episode)} probes in {format_duration(duration)}" if duration <= 10 else None),
        sensitive=("Probed remote-access / admin ports: " + ", ".join(port_label(p) for p in sensitive_hit[:5])
                   if sensitive_hit else
                   (f"{len(targets)} hosts targeted" if len(targets) >= 5 else None)),
        persistent=(f"Scanning lasted {format_duration(duration)}" if duration >= 300 else None),
        confirmed=(f"{len(open_ports)} open ports discovered ({', '.join(str(p) for p in open_ports[:6])})"
                   if open_ports else None),
    )

    return Finding(
        rule=RULE,
        title=TITLE,
        subtype="SYN scan",
        src_ip=src,
        dst_ip=targets[0] if len(targets) == 1 else None,
        targets=targets,
        ports=ports,
        protocol="TCP",
        first_seen=first,
        last_seen=last,
        event_count=int(len(episode)),
        event_label="connection requests",
        summary=summary,
        what_happened=(f"{src} sent connection requests to {plural(len(ports), 'port')} on "
                       f"{target_text} within {format_duration(duration)}. This is how scanning tools "
                       "check which services are running before an attack."),
        why_flagged=(f"{peak} different host/port targets were contacted within "
                     f"{format_duration(cfg.window_seconds)}. The rule flags {cfg.min_targets} or more."),
        evidence=evidence,
        recommended_steps=[
            f"Identify the device using {src} (DHCP leases, switch port, asset list) and whether scanning is authorized.",
            "Check whether the open ports found should be reachable from this host.",
            f"Look for follow-up connections from {src} to the open ports after the scan.",
            "If the scan is not authorized, isolate the device and review its other activity.",
        ],
        signals=signals,
        sample_frames=sample_frames(episode),
        metrics={"targets": len(targets), "ports": len(ports), "pairs": int(len(pairs)),
                 "peak_targets_in_window": peak, "open_ports": open_ports,
                 "refused": closed, "no_answer": no_answer, "probes_per_second": round(rate, 2)},
    )
