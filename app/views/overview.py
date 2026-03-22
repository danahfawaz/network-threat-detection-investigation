"""Overview - what was analyzed, and the analysis summary."""

from __future__ import annotations

import streamlit as st

from app import charts
from app.components import badge, esc, notice, panel_title, render
from pcap_investigation.models import format_bytes, format_duration, format_ts
from pcap_investigation.reporting.html_report import executive_summary


def page(result) -> None:
    capture, s = result.capture, result.summary
    with st.container(key="panel-exec", border=True):
        render(panel_title("Analysis Summary"))
        render(f'<div class="exec-row"><div class="exec-score">{result.overall_score}<span>/100</span></div>'
               f'<div>{badge(result.overall_severity if result.findings else "None")}'
               f'<div class="muted small">Overall capture risk</div></div></div>'
               f'<p class="exec-text">{esc(executive_summary(result))}</p>'
               '<div class="muted small">How the overall score was reached: '
               + esc("; ".join(result.overall_reasons)) + "</div>")
        for note in result.notes:
            notice(note, "warn")

    left, right = st.columns([1.25, 1], gap="small")
    with left, st.container(key="panel-capture", border=True):
        render(panel_title("Capture File"))
        rows = [
            ("File name", esc(capture.file_name)),
            ("SHA-256", f'<span class="mono wrap">{capture.sha256}</span>'),
            ("Format / size", f"{capture.file_format.upper()} &middot; {format_bytes(capture.file_size)}"),
            ("Packets analyzed", f"{s.total_packets:,} ({format_bytes(s.total_bytes)})"
             + (" &middot; cut at the packet limit" if capture.truncated else "")),
            ("First packet", format_ts(s.first_ts, with_date=True)),
            ("Last packet", format_ts(s.last_ts, with_date=True)),
            ("Duration", format_duration(s.duration)),
            ("IP addresses", f"{s.unique_hosts} ({s.internal_hosts} internal, {s.external_hosts} external)"),
            ("Analyzed at", esc(result.analyzed_at)),
        ]
        render('<table class="kv">' + "".join(f"<tr><td>{k}</td><td>{v}</td></tr>" for k, v in rows) + "</table>")
        render('<div class="muted small">The SHA-256 hash identifies this exact file. Record it with your notes '
               'so the analysis can be tied to the evidence later.</div>')
    with right, st.container(key="panel-protocols", border=True):
        render(panel_title("Protocols"))
        st.plotly_chart(charts.protocol_bars(s.protocol_counts), config=charts.CHART_CONFIG, width="stretch",
                        key="protocols")
