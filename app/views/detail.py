"""Focused investigation view for one finding (opens as a dialog)."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.components import badge, esc, render
from app.theme import RULE_COLORS, SEVERITY
from pcap_investigation.models import format_duration, format_ts
from pcap_investigation.reporting.evidence import packet_rows


def finding_body(result, finding) -> None:
    color = SEVERITY[finding.severity]
    subtype = f'<span class="detail-subtype">{esc(finding.subtype)}</span>' if finding.subtype else ""
    render(
        f'<div class="detail-head"><div><div class="detail-id">{esc(finding.id)}</div>'
        f'<div class="detail-title"><span class="dot" style="background:{RULE_COLORS[finding.rule]}"></span>'
        f'{esc(finding.title)} {subtype}</div></div>'
        f'<div class="detail-score"><div class="detail-score-num" style="color:{color}">{finding.score}'
        f'<span>/100</span></div>{badge(finding.severity)}</div></div>'
    )

    left, right = st.columns([1.45, 1], gap="medium")
    with left:
        render(f'<div class="detail-label">What happened</div><div class="detail-text">{esc(finding.what_happened)}</div>'
               f'<div class="detail-label">Why it was flagged</div><div class="detail-text">{esc(finding.why_flagged)}</div>'
               '<div class="detail-label">Evidence</div><ul class="evidence">'
               + "".join(f"<li>{esc(line)}</li>" for line in finding.evidence) + "</ul>")
    with right:
        ports = ", ".join(str(p) for p in finding.ports[:12]) + (" ..." if len(finding.ports) > 12 else "")
        facts = [
            ("Source", finding.source_label), ("Destination", finding.destination_label),
            ("Ports", ports or "-"), ("Protocol", finding.protocol),
            ("First seen", format_ts(finding.first_seen, with_date=True)),
            ("Last seen", format_ts(finding.last_seen, with_date=True)),
            ("Duration", format_duration(finding.duration)),
            ("Count", f"{finding.event_count:,} {finding.event_label}"),
        ]
        render('<div class="facts">' + "".join(
            f'<div class="fact"><div class="fact-k">{k}</div><div class="fact-v">{esc(v)}</div></div>'
            for k, v in facts) + "</div>")
        rows = "".join(
            f'<div class="factor"><span class="factor-pts">+{f.points}</span>'
            f'<span class="factor-label">{esc(f.label)}</span><span class="factor-reason">{esc(f.reason)}</span></div>'
            for f in finding.score_factors)
        render(f'<div class="detail-label">Why this risk score ({finding.score}/100)</div>'
               f'<div class="factors">{rows}<div class="factor total"><span class="factor-pts">{finding.score}</span>'
               f'<span class="factor-label">Total</span><span class="factor-reason">'
               f'{"capped at 100" if sum(f.points for f in finding.score_factors) > 100 else "sum of the points above"}'
               f'</span></div></div>')

    render('<div class="detail-label">Sample packets</div>')
    packets = pd.DataFrame(packet_rows(result.packets, finding.sample_frames))
    if not packets.empty:
        packets["time"] = packets["time"].str.slice(11, 19)
        st.dataframe(packets.rename(columns={"frame": "#", "src_port": "src port", "dst_port": "dst port"}),
                     hide_index=True, width="stretch")
    render('<div class="detail-label">Recommended next steps</div><ol class="steps">'
           + "".join(f"<li>{esc(step)}</li>" for step in finding.recommended_steps) + "</ol>")


@st.dialog("Investigation detail", width="large")
def show_finding_dialog(finding_id: str) -> None:
    result = st.session_state.result
    finding = result.finding(finding_id) if result else None
    if finding is None:
        st.write("This finding is no longer available.")
        return
    finding_body(result, finding)
