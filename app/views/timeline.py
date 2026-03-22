"""Threat Timeline - what happened, in order."""

from __future__ import annotations

import streamlit as st

from app import charts
from app.components import badge, esc, panel_title, render
from app.theme import RULE_COLORS
from app.views.detail import show_finding_dialog
from pcap_investigation.models import format_duration, format_ts


def page(result) -> None:
    with st.container(key="panel-traffic-full", border=True):
        render(panel_title("Traffic Over Time"))
        st.plotly_chart(charts.traffic_timeline(result, height=260), config=charts.CHART_CONFIG,
                        width="stretch", key="timeline-full")

    with st.container(key="panel-gantt", border=True):
        render(panel_title("When Each Finding Was Active"))
        if not result.findings:
            render('<div class="empty-note">No suspicious activity detected by the enabled rules.</div>')
            return
        st.plotly_chart(charts.findings_gantt(result), config=charts.CHART_CONFIG, width="stretch", key="gantt")

    with st.container(key="panel-events", border=True):
        render(panel_title("Event Sequence"))
        for f in result.findings:
            with st.container(key=f"event-{f.id}"):
                text, action = st.columns([6, 1], vertical_alignment="center")
                with text:
                    render(f'<div class="event"><div class="event-time mono">{format_ts(f.first_seen)}'
                           f'<span class="muted"> &rarr; {format_ts(f.last_seen)}</span></div>'
                           f'<div class="event-body"><span class="dot" style="background:{RULE_COLORS[f.rule]}"></span>'
                           f'<b>{esc(f.id)} {esc(f.title)}</b> &middot; <span class="mono">{esc(f.source_label)}</span>'
                           f' &rarr; <span class="mono">{esc(f.destination_label)}</span> {badge(f.severity)}'
                           f'<div class="muted small">{esc(f.summary)} &middot; lasted {format_duration(f.duration)}</div>'
                           '</div></div>')
                with action:
                    if st.button("View", key=f"tl-view-{f.id}", icon=":material/visibility:"):
                        show_finding_dialog(f.id)
