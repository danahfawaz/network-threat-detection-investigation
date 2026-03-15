"""Self-contained HTML investigation report.

Everything in the report comes from the AnalysisResult of the analyzed
capture. Jinja2 autoescaping is on, because packet contents (DNS names,
for example) are attacker-controlled and must never become HTML.
"""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from ..models import format_bytes, format_duration, format_ts
from ..scoring import BASE_POINTS, SEVERITY_BANDS
from ..traffic import timeline
from .evidence import involved_hosts, packet_rows, recommended_next_steps, score_explanation

TEMPLATES = Path(__file__).parent / "templates"

SEVERITY_COLORS = {"Critical": "#9e2b3e", "High": "#c8566a", "Medium": "#b9803f", "Low": "#8c817e",
                   "None": "#6f8f74"}

RULE_DESCRIPTIONS = {
    "port_scan": lambda c: f"One source sends SYNs to {c.port_scan.min_targets}+ different host/port targets "
                           f"within {c.port_scan.window_seconds:g} s.",
    "dns_anomaly": lambda c: (f"Query flood: {c.dns.query_flood_count}+ queries in {c.dns.query_flood_window:g} s. "
                              f"Suspicious names: {c.dns.suspicious_name_min_count}+ names with a "
                              f"{c.dns.long_label_length}+ character label or entropy >= {c.dns.entropy_threshold}. "
                              f"Failed lookups: {c.dns.nxdomain_min_count}+ NXDOMAIN and >= "
                              f"{c.dns.nxdomain_min_ratio:.0%} of answers."),
    "connection_attempts": lambda c: (f"{c.connection_attempts.min_attempts}+ attempts in "
                                      f"{c.connection_attempts.window_seconds:g} s to a login port, or with >= "
                                      f"{c.connection_attempts.failure_ratio:.0%} failing; "
                                      f"{c.connection_attempts.watchlist_min_attempts}+ attempts to a watchlist port."),
    "traffic_burst": lambda c: (f"{c.traffic_burst.min_packets:,}+ packets from one host in "
                                f"{c.traffic_burst.window_seconds:g} s and >= {c.traffic_burst.min_ratio:g}x its normal rate."),
    "beaconing": lambda c: (f"{c.beaconing.min_connections}+ connections to one destination, typical gap "
                            f"{c.beaconing.min_interval:g}-{c.beaconing.max_interval:g} s, >= "
                            f"{c.beaconing.min_regular_fraction:.0%} of gaps within +/-{c.beaconing.tolerance:.0%}."),
    "arp_spoofing": lambda c: f"One IP address announced by {c.arp.min_macs}+ MAC addresses in ARP traffic.",
}


def _timeline_svg_data(result, width: int = 760, height: int = 120) -> dict:
    """Bar positions for a small inline SVG chart (no JavaScript needed)."""
    table, bin_size = timeline(result.packets)
    peak = max(int(table["packets"].max()), 1)
    count = len(table)
    bar_width = width / max(count, 1)
    bars = [{"x": round(i * bar_width, 2), "w": round(max(bar_width - 1, 1), 2),
             "h": round(packets / peak * (height - 10), 2), "y": round(height - packets / peak * (height - 10), 2),
             "label": f"{format_ts(start)}: {packets} packets"}
            for i, (start, packets) in enumerate(zip(table["bin_start"], table["packets"]))]
    start, end = result.summary.first_ts, result.summary.first_ts + count * bin_size
    span = max(end - start, 1e-9)
    marks = []
    for f in result.findings:
        x1 = (f.first_seen - start) / span * width
        x2 = max((f.last_seen - start) / span * width, x1 + 3)
        marks.append({"x": round(x1, 2), "w": round(x2 - x1, 2), "id": f.id,
                      "color": SEVERITY_COLORS[f.severity], "label": f"{f.id} {f.title}"})
    return {"bars": bars, "marks": marks, "width": width, "height": height, "peak": peak,
            "bin": format_duration(bin_size), "start": format_ts(start), "end": format_ts(end)}


def build_context(result) -> dict:
    findings = []
    for f in result.findings:
        findings.append({
            "f": f,
            "first": format_ts(f.first_seen, with_date=True),
            "last": format_ts(f.last_seen, with_date=True),
            "duration": format_duration(f.duration),
            "score_lines": score_explanation(f),
            "packets": packet_rows(result.packets, f.sample_frames),
            "color": SEVERITY_COLORS[f.severity],
            "ports": ", ".join(str(p) for p in f.ports) or "-",
        })
    summary = result.summary
    events = sorted(
        [(f.first_seen, f"{f.id} {f.title} started", f.source_label, f.severity) for f in result.findings]
        + [(f.last_seen, f"{f.id} {f.title} last seen", f.source_label, f.severity)
           for f in result.findings if f.last_seen > f.first_seen],
        key=lambda e: e[0])
    return {
        "result": result,
        "capture": result.capture,
        "summary": summary,
        "findings": findings,
        "counts": result.severity_counts,
        "colors": SEVERITY_COLORS,
        "overall_color": SEVERITY_COLORS.get(result.overall_severity, "#6f8f74"),
        "file_size": format_bytes(result.capture.file_size),
        "total_bytes": format_bytes(summary.total_bytes),
        "duration": format_duration(summary.duration),
        "first_packet": format_ts(summary.first_ts, with_date=True),
        "last_packet": format_ts(summary.last_ts, with_date=True),
        "protocols": sorted(summary.protocol_counts.items(), key=lambda kv: -kv[1]),
        "hosts": involved_hosts(result),
        "next_steps": recommended_next_steps(result),
        "events": [{"time": format_ts(t, with_date=True), "text": text, "host": host, "severity": sev,
                    "color": SEVERITY_COLORS[sev]} for t, text, host, sev in events],
        "chart": _timeline_svg_data(result),
        "rules": [{"key": key, "description": RULE_DESCRIPTIONS[key](result.config), "base": BASE_POINTS[key]}
                  for key in result.config.enabled_rules],
        "bands": SEVERITY_BANDS,
        "executive_summary": executive_summary(result),
    }


def executive_summary(result) -> str:
    s = result.summary
    base = (f"The capture {result.capture.file_name} contains {s.total_packets:,} packets "
            f"({format_bytes(s.total_bytes)}) between {s.unique_hosts} IP addresses over "
            f"{format_duration(s.duration)}. ")
    if not result.findings:
        return base + "No suspicious activity detected by the enabled rules."
    counts = result.severity_counts
    parts = [f"{n} {sev.lower()}" for sev, n in counts.items() if n]
    top = max(result.findings, key=lambda f: f.score)
    sources = sorted({f.source_label for f in result.findings})
    return (base + f"{len(result.findings)} suspicious behaviors were detected ({', '.join(parts)}), involving "
            f"{len(sources)} source(s). The most serious is {top.title.lower()} from {top.source_label} "
            f"(risk {top.score}/100). Overall capture risk: {result.overall_score}/100 "
            f"({result.overall_severity}).")


def render_report(result) -> str:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=True,
                      trim_blocks=True, lstrip_blocks=True)
    return env.get_template("report.html.j2").render(**build_context(result))
