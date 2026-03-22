"""Plotly charts styled to match the dashboard."""

from __future__ import annotations

from datetime import datetime, timezone

import pandas as pd
import plotly.graph_objects as go

from app.theme import FAINT, GRID, MUTED, NORMAL_TRAFFIC, RULE_COLORS, RULE_ORDER, SEVERITY, TEXT
from pcap_investigation.models import format_duration, format_ts
from pcap_investigation.pipeline import RULE_TITLES
from pcap_investigation.reporting.evidence import finding_packet_mask
from pcap_investigation.traffic import choose_bin_size

SHORT_NAMES = {"port_scan": "Port Scan", "dns_anomaly": "DNS Anomaly", "connection_attempts": "Repeated Connections",
               "traffic_burst": "Traffic Burst", "beaconing": "Beaconing", "arp_spoofing": "ARP Spoofing"}

FONT = dict(family="Inter, -apple-system, Segoe UI, Roboto, sans-serif", color=MUTED, size=12)
CHART_CONFIG = {"displayModeBar": False, "responsive": True}


def _base_layout(height: int, **extra) -> dict:
    layout = dict(height=height, margin=dict(l=8, r=8, t=8, b=8), paper_bgcolor="rgba(0,0,0,0)",
                  plot_bgcolor="rgba(0,0,0,0)", font=FONT, showlegend=False,
                  hoverlabel=dict(bgcolor="#2B2124", bordercolor="#4A3A3E", font=dict(color=TEXT, size=12)))
    layout.update(extra)
    return layout


def severity_donut(counts: dict[str, int], total: int) -> go.Figure:
    labels = [name for name in ["Critical", "High", "Medium", "Low"] if counts.get(name)]
    values = [counts[name] for name in labels]
    fig = go.Figure(go.Pie(
        labels=labels, values=values, hole=0.68, sort=False, direction="clockwise",
        marker=dict(colors=[SEVERITY[n] for n in labels], line=dict(color="#21191B", width=3)),
        textinfo="none", hovertemplate="%{label}: %{value} finding(s)<extra></extra>",
    ))
    fig.update_layout(**_base_layout(190, annotations=[
        dict(text=f"<b style='font-size:26px;color:{TEXT}'>{total}</b><br>"
                  f"<span style='font-size:12px;color:{MUTED}'>{'Threat' if total == 1 else 'Threats'}</span>",
             x=0.5, y=0.5, showarrow=False)]))
    return fig


def _to_datetime(seconds: pd.Series) -> pd.Series:
    return pd.to_datetime(seconds, unit="s", utc=True)


def traffic_timeline(result, height: int = 248) -> go.Figure:
    """Packets per time bin: normal traffic plus traffic that belongs to each detection type."""
    frame = result.packets
    first = float(frame["ts"].min())
    duration = float(frame["ts"].max()) - first
    size = choose_bin_size(duration, target_bins=70)
    bins = ((frame["ts"] - first) // size).astype(int)
    n_bins = int(bins.max()) + 1
    x = _to_datetime(pd.Series(first + (pd.RangeIndex(n_bins) * size)))

    flagged = pd.Series(False, index=frame.index)
    per_rule: dict[str, pd.Series] = {}
    for finding in result.findings:
        mask = finding_packet_mask(frame, finding) & ~flagged
        flagged |= mask
        counts = bins[mask].value_counts().reindex(range(n_bins), fill_value=0)
        per_rule[finding.rule] = per_rule.get(finding.rule, 0) + counts

    normal = bins[~flagged].value_counts().reindex(range(n_bins), fill_value=0)
    fig = go.Figure()
    fig.add_bar(x=x, y=normal.values, name="Normal", marker_color=NORMAL_TRAFFIC,
                hovertemplate="%{x|%H:%M:%S}<br>Normal traffic: %{y:,} packets<extra></extra>")
    for rule in RULE_ORDER:
        if rule in per_rule:
            fig.add_bar(x=x, y=per_rule[rule].values, name=SHORT_NAMES[rule], marker_color=RULE_COLORS[rule],
                        hovertemplate=f"%{{x|%H:%M:%S}}<br>{RULE_TITLES[rule]}: %{{y:,}} packets<extra></extra>")
    fig.update_layout(**_base_layout(
        height, barmode="stack", bargap=0.25, showlegend=True,
        legend=dict(orientation="h", yanchor="top", y=-0.16, x=0, font=dict(size=10.5, color=MUTED),
                    itemclick=False, itemdoubleclick=False, itemwidth=30, tracegroupgap=0,
                    traceorder="normal"),
        margin=dict(l=8, r=8, t=6, b=4),
        xaxis=dict(showgrid=False, linecolor=GRID, tickformat="%H:%M", tickfont=dict(color=FAINT)),
        yaxis=dict(gridcolor=GRID, zeroline=False, tickfont=dict(color=FAINT),
                   title=dict(text=f"Packets / {format_duration(size)}", font=dict(size=11, color=FAINT))),
    ))
    return fig


def findings_gantt(result, height: int | None = None) -> go.Figure:
    """One horizontal bar per finding, from first to last seen, colored by severity."""
    findings = list(reversed(result.findings))
    height = height or max(180, 46 * len(findings) + 60)
    fig = go.Figure()
    min_width = max((result.summary.duration or 1) * 0.006, 0.5)
    for f in findings:
        start = datetime.fromtimestamp(f.first_seen, tz=timezone.utc)
        width_ms = max(f.last_seen - f.first_seen, min_width) * 1000
        fig.add_bar(
            y=[f"{f.id}  {f.title}"], x=[width_ms], base=[start], orientation="h",
            marker=dict(color=SEVERITY[f.severity], line=dict(width=0)),
            hovertemplate=(f"<b>{f.id} {f.title}</b><br>{format_ts(f.first_seen)} - {format_ts(f.last_seen)} UTC"
                           f"<br>{f.severity}, risk {f.score}/100<extra></extra>"),
        )
    fig.update_layout(**_base_layout(
        height, barmode="overlay", bargap=0.45,
        xaxis=dict(type="date", gridcolor=GRID, tickformat="%H:%M:%S", tickfont=dict(color=FAINT),
                   range=[datetime.fromtimestamp(result.summary.first_ts, tz=timezone.utc),
                          datetime.fromtimestamp(result.summary.last_ts, tz=timezone.utc)]),
        yaxis=dict(tickfont=dict(color=TEXT, size=12), automargin=True),
    ))
    return fig


def protocol_bars(protocol_counts: dict[str, int], height: int = 220) -> go.Figure:
    items = sorted(protocol_counts.items(), key=lambda kv: kv[1])
    fig = go.Figure(go.Bar(
        x=[v for _, v in items], y=[k for k, _ in items], orientation="h",
        marker=dict(color="#B96D78"), hovertemplate="%{y}: %{x:,} packets<extra></extra>",
    ))
    fig.update_layout(**_base_layout(height, bargap=0.4,
                                     xaxis=dict(gridcolor=GRID, tickfont=dict(color=FAINT)),
                                     yaxis=dict(tickfont=dict(color=TEXT), automargin=True)))
    return fig
