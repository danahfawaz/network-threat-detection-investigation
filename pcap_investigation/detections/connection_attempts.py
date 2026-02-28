"""Rule 3 - Repeated Suspicious Connection Attempts.

Looks at every (source, destination, destination port) pair and counts new
TCP connection attempts (SYN). It flags three easy-to-explain patterns:

* Possible password guessing  - many connections to a remote-login service
                                (SSH, RDP, SMB, Telnet, databases ...).
* Repeated failed connections - many attempts to any port, and most of them
                                were refused or never answered.
* Connections to a watchlist port - a few attempts are enough when the port is
                                one commonly used by backdoors (e.g. 4444).
"""

from __future__ import annotations

import pandas as pd

from ..config import ConnectionAttemptConfig
from ..models import Finding, ScoringSignals, format_duration
from ..normalize import syn_only
from ..traffic import ip_scope, service_name
from .common import classify_syn_answers, max_count_in_window, plural, sample_frames

RULE = "connection_attempts"
TITLE = "Repeated Connection Attempts"


def detect(frame: pd.DataFrame, cfg: ConnectionAttemptConfig) -> list[Finding]:
    syns = frame[syn_only(frame) & frame["src_ip"].notna()]
    # A retransmitted SYN reuses the same source port: count it once.
    attempts = syns.sort_values("ts").drop_duplicates(["src_ip", "dst_ip", "sport", "dport"])
    findings = []
    for (src, dst, dport), rows in attempts.groupby(["src_ip", "dst_ip", "dport"], sort=True):
        finding = _evaluate(frame, rows, src, dst, int(dport), cfg)
        if finding:
            findings.append(finding)
    return findings


def _session_stats(frame: pd.DataFrame, rows: pd.DataFrame, src: str, dst: str, dport: int) -> tuple[float, float]:
    """Average packets and duration per connection (both directions)."""
    sports = set(rows["sport"].dropna().astype(int))
    tcp = frame[frame["protocol"] == "TCP"]
    forward = tcp[(tcp["src_ip"] == src) & (tcp["dst_ip"] == dst) & (tcp["dport"] == dport)
                  & tcp["sport"].isin(sports)]
    backward = tcp[(tcp["src_ip"] == dst) & (tcp["dst_ip"] == src) & (tcp["sport"] == dport)
                   & tcp["dport"].isin(sports)]
    both = pd.concat([forward.assign(conn=forward["sport"]), backward.assign(conn=backward["dport"])])
    per_conn = both.groupby("conn").agg(packets=("frame", "size"), start=("ts", "min"), end=("ts", "max"))
    return float(per_conn["packets"].mean()), float((per_conn["end"] - per_conn["start"]).mean())


def _evaluate(frame, rows, src, dst, dport, cfg) -> Finding | None:
    total = len(rows)
    times = rows["ts"].tolist()
    peak, peak_start, peak_end = max_count_in_window(times, cfg.window_seconds)
    answers = classify_syn_answers(frame, rows)
    accepted = int((answers == "open").sum())
    refused = int((answers == "closed").sum())
    no_answer = int((answers == "none").sum())
    fail_ratio = (refused + no_answer) / total

    if dport in cfg.watchlist_ports and total >= cfg.watchlist_min_attempts:
        subtype, threshold, measured = "Connections to a watchlist port", cfg.watchlist_min_attempts, total
    elif dport in cfg.login_ports and peak >= cfg.min_attempts:
        subtype, threshold, measured = "Possible password guessing", cfg.min_attempts, peak
    elif peak >= cfg.min_attempts and fail_ratio >= cfg.failure_ratio:
        subtype, threshold, measured = "Repeated failed connections", cfg.min_attempts, peak
    else:
        return None

    first, last = float(rows["ts"].min()), float(rows["ts"].max())
    span = last - first
    avg_gap = span / (total - 1) if total > 1 else 0.0
    name = service_name(dport)
    service = f"{name} (port {dport})" if name else f"port {dport}"
    avg_packets, avg_seconds = _session_stats(frame, rows, src, dst, dport)
    outcome = (f"{accepted} accepted, {refused} refused (RST), {no_answer} with no answer")

    if subtype == "Possible password guessing":
        summary = f"{total} connections to {service} in {format_duration(span)}"
        what = (f"{src} opened {total} separate connections to the {service} service on {dst} in "
                f"{format_duration(span)}. Many short connections to a login service in a short time "
                "is the typical pattern of password guessing (brute force).")
        why = (f"{peak} attempts within {format_duration(cfg.window_seconds)} to a remote-login port. "
               f"The rule flags {cfg.min_attempts} or more.")
        steps = [
            f"Check the authentication logs on {dst} for failed and successful logins from {src}.",
            "If any login succeeded, treat the account as compromised: reset the password and review its activity.",
            f"Block or rate-limit {src} and consider key-based authentication / MFA for {service}.",
        ]
    elif subtype == "Repeated failed connections":
        summary = f"{total} failed connection attempts to {service} ({fail_ratio:.0%} failed)"
        what = (f"{src} kept trying to connect to port {dport} on {dst}, and {fail_ratio:.0%} of the attempts "
                "were refused or never answered. This can be a misconfigured program, or a tool searching "
                "for a service that is not there.")
        why = (f"{peak} attempts within {format_duration(cfg.window_seconds)} and {fail_ratio:.0%} failed. "
               f"The rule flags {cfg.min_attempts}+ attempts with at least {cfg.failure_ratio:.0%} failing.")
        steps = [
            f"Identify the program on {src} making these connections.",
            f"Check whether {dst}:{dport} is a legitimate service that is down or misconfigured.",
            f"If no legitimate reason exists, investigate {src} for malware.",
        ]
    else:
        summary = f"Connection to watchlist port {dport} ({total} attempts)"
        what = (f"{src} tried to connect to port {dport} on {dst} {total} times. Port {dport} is not used by "
                "common legitimate services but is a default for remote-access backdoors and attack tools.")
        why = (f"{total} attempts to a port on the watchlist ({', '.join(map(str, cfg.watchlist_ports))}). "
               f"The rule flags {cfg.watchlist_min_attempts} or more.")
        steps = [
            f"Find the process on {src} that opened these connections.",
            f"Check {dst} against threat intelligence and firewall/proxy logs.",
            f"Scan {src} for malware; isolate it if the process cannot be explained.",
        ]

    evidence = [
        f"{plural(total, 'connection attempt')} from {src} to {service} on {dst} "
        f"over {format_duration(span)}" + (f" (about one every {avg_gap:.1f} sec)." if total > 1 else "."),
        f"Peak: {peak} attempts within {format_duration(peak_end - peak_start)}.",
        f"Outcome: {outcome}.",
    ]
    if accepted:
        evidence.append(f"Connections were short: about {avg_packets:.0f} packets and "
                        f"{format_duration(avg_seconds)} each.")
    if ip_scope(src) == "External":
        evidence.append(f"{src} is outside the local network.")

    if subtype == "Connections to a watchlist port":
        sensitive = f"Port {dport} is commonly used by backdoors and attack tools"
    elif dport in cfg.login_ports:
        sensitive = f"{service} is a remote-login / admin service"
    else:
        sensitive = None
    confirmed = None
    if accepted and subtype == "Possible password guessing":
        confirmed = f"The service accepted {accepted} connections, so the login attempts reached it"
    elif accepted and subtype == "Connections to a watchlist port":
        confirmed = f"The remote side accepted {accepted} connection(s)"

    return Finding(
        rule=RULE, title=TITLE, subtype=subtype, src_ip=src, dst_ip=dst, targets=[dst],
        ports=[dport], protocol="TCP", first_seen=first, last_seen=last,
        event_count=total, event_label="connection attempts", summary=summary,
        what_happened=what, why_flagged=why, evidence=evidence, recommended_steps=steps,
        signals=ScoringSignals(
            ratio=measured / threshold,
            scale_text=f"{measured} attempts ({measured / threshold:.1f}x the threshold of {threshold})",
            fast=(f"One attempt every {avg_gap:.1f} sec" if total > 1 and avg_gap <= 5 else None),
            sensitive=sensitive,
            persistent=f"Continued for {format_duration(span)}" if span >= 300 else None,
            confirmed=confirmed,
        ),
        sample_frames=sample_frames(rows),
        metrics={"attempts": total, "peak_in_window": peak, "accepted": accepted, "refused": refused,
                 "no_answer": no_answer, "failure_ratio": round(fail_ratio, 2),
                 "average_gap_seconds": round(avg_gap, 2)},
    )
