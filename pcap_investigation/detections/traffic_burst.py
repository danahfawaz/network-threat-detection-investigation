"""Rule 4 - Traffic Burst / High-Volume Traffic.

For each host, find the busiest ``window_seconds`` period. Flag it when the
host sent at least ``min_packets`` packets in that window AND that is at least
``min_ratio`` times the host's normal rate (its rate outside the window).

Comparing with the host's own normal rate avoids flagging servers that are
always busy; the absolute minimum avoids flagging tiny spikes on quiet hosts.
"""

from __future__ import annotations

import pandas as pd

from ..config import TrafficBurstConfig
from ..models import Finding, ScoringSignals, format_bytes, format_duration
from ..traffic import ip_scope, is_unicast, port_label
from .common import max_count_in_window, plural, sample_frames

RULE = "traffic_burst"
TITLE = "Traffic Burst"


def _high_rate_period(times: list[float], window: float, minimum: int) -> tuple[float, float]:
    """First and last moment the trailing-window packet count was >= minimum."""
    left, first_hit, last_hit = 0, None, None
    for right, ts in enumerate(times):
        while ts - times[left] > window:
            left += 1
        if right - left + 1 >= minimum:
            if first_hit is None:
                first_hit = times[left]
            last_hit = ts
    return first_hit, last_hit


def detect(frame: pd.DataFrame, cfg: TrafficBurstConfig) -> list[Finding]:
    ip_rows = frame[frame["src_ip"].notna()]
    capture_start, capture_end = float(frame["ts"].min()), float(frame["ts"].max())
    findings = []
    for host, rows in ip_rows.groupby("src_ip", sort=True):
        if len(rows) < cfg.min_packets or not is_unicast(host):
            continue
        rows = rows.sort_values("ts")
        times = rows["ts"].tolist()
        peak, start, end = max_count_in_window(times, cfg.window_seconds)
        if peak < cfg.min_packets:
            continue
        # Normal rate = the host's rate during the rest of the capture.
        outside_seconds = (capture_end - capture_start) - cfg.window_seconds
        if outside_seconds < 2 * cfg.window_seconds:
            continue  # capture too short to know what "normal" is
        outside_packets = len(rows) - peak
        normal_per_window = outside_packets / outside_seconds * cfg.window_seconds
        times_normal = peak / normal_per_window if normal_per_window > 0 else float("inf")
        if times_normal < cfg.min_ratio:
            continue
        findings.append(_build(frame, rows, host, peak, start, end, normal_per_window, times_normal, cfg))
    return findings


def _build(frame, rows, host, peak, start, end, normal_per_window, times_normal, cfg) -> Finding:
    burst = rows[(rows["ts"] >= start) & (rows["ts"] <= end)]
    seconds = max(end - start, 0.001)
    sent_bytes = int(burst["length"].sum())
    by_dst = burst.groupby("dst_ip").agg(packets=("frame", "size"), bytes=("length", "sum")) \
                  .sort_values("packets", ascending=False)
    top_dst = by_dst.index[0]
    share = by_dst.iloc[0]["packets"] / len(burst)
    ports = burst["dport"].dropna().astype(int).value_counts()
    received = frame[(frame["src_ip"] == top_dst) & (frame["dst_ip"] == host)
                     & (frame["ts"] >= start) & (frame["ts"] <= end)]
    received_bytes = int(received["length"].sum())
    to_top_bytes = int(by_dst.iloc[0]["bytes"])
    upload_heavy = to_top_bytes >= 10 * max(received_bytes, 1)
    period_start, period_end = _high_rate_period(rows["ts"].tolist(), cfg.window_seconds, cfg.min_packets)
    sustained = (period_end - period_start) if period_start is not None else seconds
    protocol = burst["protocol"].mode().iloc[0]
    times_text = "far above" if times_normal == float("inf") else f"{times_normal:.0f}x"

    normal_text = (f"{normal_per_window:.0f} packets per {format_duration(cfg.window_seconds)}"
                   if normal_per_window > 0 else "no other traffic")
    evidence = [
        f"{peak:,} packets ({format_bytes(sent_bytes)}) sent in {format_duration(seconds)} "
        f"- about {peak / seconds:,.0f} packets per second.",
        f"Normal rate for this host: {normal_text} (burst is {times_text} that).",
        f"Main destination: {top_dst} ({share:.0%} of burst packets, {format_bytes(to_top_bytes)}).",
        f"Data received back from {top_dst} in the same time: {format_bytes(received_bytes)}.",
    ]
    if len(ports):
        evidence.append("Destination ports: " + ", ".join(
            f"{port_label(p)} ({c:,})" for p, c in ports.head(3).items()) + ".")
    if len(by_dst) > 1:
        evidence.append(f"Burst went to {plural(len(by_dst), 'destination')} in total.")

    external = ip_scope(top_dst) == "External"
    return Finding(
        rule=RULE, title=TITLE, subtype="High-volume burst", src_ip=host,
        dst_ip=top_dst if len(by_dst) == 1 or share >= 0.8 else None,
        targets=by_dst.index.tolist(), ports=[int(p) for p in ports.index[:5]], protocol=protocol,
        first_seen=float(burst["ts"].min()), last_seen=float(burst["ts"].max()),
        event_count=int(peak), event_label="packets",
        summary=f"Traffic spike: {peak:,} packets in {format_duration(seconds)} ({times_text} normal)",
        what_happened=(f"{host} suddenly sent {peak:,} packets ({format_bytes(sent_bytes)}) in "
                       f"{format_duration(seconds)}, mostly to {top_dst}. That is {times_text} its normal "
                       "rate. A sudden burst can be a large upload (possible data theft), a flood attack, "
                       "or a legitimate backup or update."),
        why_flagged=(f"{peak:,} packets within {format_duration(cfg.window_seconds)} and {times_text} the "
                     f"host's normal rate. The rule flags {cfg.min_packets:,}+ packets that are at least "
                     f"{cfg.min_ratio:.0f}x normal."),
        evidence=evidence,
        recommended_steps=[
            f"Identify what {host} was doing at that time (backup, update, file transfer?).",
            f"Check who owns {top_dst} and whether this host should send data there.",
            "Review firewall/proxy logs for the transferred volume and any file names.",
            "If it was not an expected transfer, treat it as possible data exfiltration.",
        ],
        signals=ScoringSignals(
            ratio=peak / cfg.min_packets,
            scale_text=f"{peak:,} packets ({peak / cfg.min_packets:.1f}x the threshold of {cfg.min_packets:,})",
            fast=f"{peak:,} packets in {format_duration(seconds)}" if seconds <= 30 else None,
            sensitive=f"Most of the burst went to an external address ({top_dst})" if external else None,
            persistent=f"High rate lasted {format_duration(sustained)}" if sustained >= 60 else None,
            confirmed=(f"One-way transfer: sent {format_bytes(to_top_bytes)}, received {format_bytes(received_bytes)}"
                       if upload_heavy else None),
        ),
        sample_frames=sample_frames(burst),
        metrics={"peak_packets": int(peak), "bytes": sent_bytes, "seconds": round(seconds, 2),
                 "normal_packets_per_window": round(normal_per_window, 1),
                 "times_normal": None if times_normal == float("inf") else round(times_normal, 1),
                 "main_destination": top_dst, "received_bytes": received_bytes},
    )
