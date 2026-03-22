"""Upload & Analyze - the main dashboard (follows the approved reference layout)."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import streamlit as st

from app import charts
from app.components import (
    badge,
    bar_list,
    empty_state,
    esc,
    icon,
    notice,
    panel_title,
    render,
    severity_legend,
    stat_card,
)
from app.state import PendingFile, analyze_pending, clear_pending, sample_files
from app.theme import DUSTY_ROSE, RULE_COLORS, RULE_ORDER, SEVERITY_BADGE
from app.views.detail import show_finding_dialog
from pcap_investigation.models import format_bytes, format_duration, format_ts
from pcap_investigation.pipeline import RULE_TITLES
from pcap_investigation.reporting.exports import alerts_csv, evidence_json
from pcap_investigation.reporting.html_report import render_report


# -- top area: upload ------------------------------------------------------------

def _load_sample(path: Path) -> None:
    st.session_state.pending = PendingFile(path.name, path.read_bytes())


def upload_bar() -> None:
    with st.container(key="upload-bar"):
        c1, c2, c3, c4 = st.columns([2.15, 2.45, 2.45, 1.25], vertical_alignment="center", gap="medium")
        with c1:
            render(f'<div class="upload-intro"><div class="icon-tile big">{icon("file", 30)}</div>'
                   '<div><div class="upload-title">Upload PCAP File</div>'
                   '<div class="upload-sub">Select a .pcap or .pcapng file to analyze</div></div></div>')
            with st.popover("Use a sample capture", icon=":material/science:", type="tertiary"):
                st.caption("Synthetic captures included with the project (fictional traffic).")
                for path in sample_files():
                    if st.button(path.name, key=f"sample-{path.name}", type="tertiary"):
                        _load_sample(path)
                        st.rerun()
        with c2:
            uploaded = st.file_uploader("Upload capture", type=["pcap", "pcapng", "cap"],
                                        label_visibility="collapsed",
                                        key=f"uploader-{st.session_state.uploader_version}")
            if uploaded is not None:
                # Keep the file, then reset the uploader so the drop zone stays
                # empty and ready; the file card shows what was chosen.
                st.session_state.pending = PendingFile(uploaded.name, uploaded.getvalue())
                st.session_state.uploader_version += 1
                st.rerun()
        with c3:
            _file_card()
        with c4:
            pending = st.session_state.pending
            if st.button("Analyze PCAP", type="primary", icon=":material/play_arrow:", key="analyze",
                         disabled=pending is None, width="stretch"):
                with st.spinner("Analyzing capture..."):
                    analyze_pending()
                st.rerun()


def _file_card() -> None:
    pending: PendingFile | None = st.session_state.pending
    if pending is None:
        render(f'<div class="file-card empty">{icon("file", 26)}<div><div class="file-name">No file selected</div>'
               '<div class="file-meta">Choose a capture to begin</div></div></div>')
        return
    status = ('<span class="ok">' + icon("check", 15) + " File loaded successfully</span>"
              if pending.looks_like_capture else
              '<span class="warn">Not a recognised PCAP/PCAPNG file</span>')
    inner, close = st.columns([0.86, 0.14], vertical_alignment="center", gap="small")
    with inner:
        render(f'<div class="file-card"><div class="file-icon">{icon("file", 26)}</div><div class="file-text">'
               f'<div class="file-name" title="{esc(pending.name)}">{esc(pending.name)}</div>'
               f'<div class="file-meta">{format_bytes(pending.size)}</div><div class="file-status">{status}</div>'
               '</div></div>')
    with close:
        if st.button("", icon=":material/close:", key="clear-file", type="tertiary", help="Remove file"):
            clear_pending()
            st.rerun()


# -- summary cards -----------------------------------------------------------------

def summary_cards(result) -> None:
    s = result.summary
    counts = result.severity_counts
    serious = [f"{counts[k]} {k.lower()}" for k in ("Critical", "High") if counts[k]]
    threats_sub = " &middot; ".join(serious) if serious else (
        "No high-risk findings" if result.findings else "No suspicious activity")
    risk_label = {"Critical": "Critical Risk", "High": "High Risk", "Medium": "Medium Risk",
                  "Low": "Low Risk"}.get(result.overall_severity, "No findings")
    risk_badge = (f'<span class="badge outline" style="border-color:{SEVERITY_BADGE.get(result.overall_severity, "#3F4A41")}">'
                  f'{risk_label}</span>')
    cards = [
        stat_card("packets", "Total Packets", f"{s.total_packets:,}", esc(format_bytes(s.total_bytes))),
        stat_card("hosts", "Unique IP Addresses", f"{s.unique_hosts:,}",
                  f"{s.internal_hosts} internal &middot; {s.external_hosts} external"),
        stat_card("alert", "Threats Detected", f"{len(result.findings)}", threats_sub),
        stat_card("shield", "Overall Risk Score",
                  f'{result.overall_score} <span class="of">/ 100</span> {risk_badge}', ""),
        stat_card("clock", "Capture Duration", esc(format_duration(s.duration)),
                  f"{format_ts(s.first_ts)} &ndash; {format_ts(s.last_ts)} UTC"),
    ]
    render('<div class="stat-grid">' + "".join(cards) + "</div>")


# -- threat overview row -------------------------------------------------------------

PANEL_HEIGHT = 268

def overview_row(result) -> None:
    c1, c2, c3 = st.columns([1.02, 1.02, 1.12], gap="small")
    with c1, st.container(key="panel-severity", border=True, height=PANEL_HEIGHT):
        render(panel_title("Threats by Severity"))
        if not result.findings:
            render('<div class="empty-note">No findings to rank.</div>')
        else:
            chart_col, legend_col = st.columns([1, 1], vertical_alignment="center")
            with chart_col:
                st.plotly_chart(charts.severity_donut(result.severity_counts, len(result.findings)),
                                config=charts.CHART_CONFIG, width="stretch", key="donut")
            with legend_col:
                render(severity_legend(result.severity_counts))
    with c2, st.container(key="panel-types", border=True, height=PANEL_HEIGHT):
        render(panel_title("Threat Types Detected"))
        per_rule = defaultdict(list)
        for f in result.findings:
            per_rule[f.rule].append(f)
        rows = [{"label": esc(RULE_TITLES[rule]), "value": len(per_rule[rule]), "color": RULE_COLORS[rule],
                 "title": ", ".join(f.id for f in per_rule[rule])} for rule in RULE_ORDER if per_rule[rule]]
        render(bar_list(rows, label_width="46%") if rows else '<div class="empty-note">None detected.</div>')
    with c3, st.container(key="panel-sources", border=True, height=PANEL_HEIGHT):
        render(panel_title("Top Source IPs", "(by suspicious activity)"))
        per_source = defaultdict(list)
        for f in result.findings:
            per_source[f.source_label].append(f)
        ranked = sorted(per_source.items(), key=lambda kv: (-len(kv[1]), -max(f.score for f in kv[1]), kv[0]))[:5]
        rows = [{"label": esc(src), "value": len(items), "color": DUSTY_ROSE,
                 "title": f"{', '.join(f.id for f in items)} - highest risk {max(f.score for f in items)}"}
                for src, items in ranked]
        render(bar_list(rows, label_width="40%") if rows else '<div class="empty-note">No suspicious sources.</div>')


# -- detected threats table ---------------------------------------------------------------

TABLE_WIDTHS = [0.32, 0.72, 1.55, 1.15, 1.15, 3.1, 0.9, 0.62, 0.75]
TABLE_HEADERS = ["#", "Time", "Type", "Source IP", "Destination IP", "Details", "Severity", "Risk Score", "Action"]


def threats_table(result) -> None:
    with st.container(key="panel-threats", border=True):
        head, sort_col = st.columns([6, 1.1], vertical_alignment="center")
        with head:
            render(panel_title("Detected Threats"))
        if not result.findings:
            render(f'<div class="clean-state">{icon("check", 22)} No suspicious activity detected by the enabled rules.</div>')
            return
        with sort_col:
            st.selectbox("Sort by", ["Sort by time", "Sort by risk"], key="table_sort", label_visibility="collapsed")
        findings = list(result.findings)
        if st.session_state.table_sort == "Sort by risk":
            findings.sort(key=lambda f: (-f.score, f.first_seen))

        header = st.columns(TABLE_WIDTHS, vertical_alignment="center", gap="small")
        for col, text in zip(header, TABLE_HEADERS):
            with col:
                render(f'<div class="th">{text}</div>')
        body = st.container(height=420, border=False) if len(findings) > 9 else st.container(border=False)
        with body:
            for index, f in enumerate(findings, start=1):
                with st.container(key=f"row-{f.id}"):
                    cols = st.columns(TABLE_WIDTHS, vertical_alignment="center", gap="small")
                    cells = [
                        f'<div class="td muted">{index}</div>',
                        f'<div class="td num">{format_ts(f.first_seen)}</div>',
                        f'<div class="td type"><span class="dot" style="background:{RULE_COLORS[f.rule]}"></span>'
                        f'{esc(f.title)}</div>',
                        f'<div class="td num">{esc(f.source_label)}</div>',
                        f'<div class="td num">{esc(f.destination_label)}</div>',
                        f'<div class="td details" title="{esc(f.summary)}">{esc(f.summary)}</div>',
                        f'<div class="td">{badge(f.severity)}</div>',
                        f'<div class="td score">{f.score}</div>',
                    ]
                    for col, cell in zip(cols, cells):
                        with col:
                            render(cell)
                    with cols[-1]:
                        if st.button("View", key=f"view-{f.id}", icon=":material/visibility:", type="secondary"):
                            show_finding_dialog(f.id)


# -- lower analytics -------------------------------------------------------------------

LOWER_HEIGHT = 318


def lower_row(result) -> None:
    c1, c2, c3 = st.columns([1.62, 1.0, 1.1], gap="small")
    with c1, st.container(key="panel-timeline", border=True, height=LOWER_HEIGHT):
        render(panel_title("Traffic Timeline"))
        st.plotly_chart(charts.traffic_timeline(result), config=charts.CHART_CONFIG, width="stretch",
                        key="timeline")
    with c2, st.container(key="panel-ports", border=True, height=LOWER_HEIGHT):
        render(panel_title("Top Destination Ports"))
        s = result.summary
        rows = [{"label": esc(p["label"]), "value": p["packets"], "color": DUSTY_ROSE,
                 "title": f"{p['packets']:,} packets to port {p['port']}"} for p in s.top_dst_ports]
        if s.other_ports_packets:
            rows.append({"label": "Others", "value": s.other_ports_packets, "color": "#6B5A5E",
                         "title": "All other destination ports"})
        render(bar_list(rows, label_width="40%"))
    with c3, st.container(key="panel-actions", border=True, height=LOWER_HEIGHT):
        render(panel_title("Investigation Actions"))
        investigation_actions(result)


def _action(icon_name: str, title: str, sub: str) -> None:
    render(f'<div class="action-text">{icon(icon_name, 22)}<div><div class="action-title">{title}</div>'
           f'<div class="action-sub">{sub}</div></div></div>')


def investigation_actions(result) -> None:
    stem = Path(result.capture.file_name).stem
    actions = [
        ("search", "View Detailed Analysis", "Evidence for the top finding", None),
        ("report", "Export Investigation Report", "Full HTML report",
         (render_report, f"{stem}_investigation_report.html", "text/html")),
        ("table", "Export Alerts (CSV)", "Download detection results",
         (alerts_csv, f"{stem}_alerts.csv", "text/csv")),
        ("braces", "Export Evidence (JSON)", "Download raw evidence",
         (evidence_json, f"{stem}_evidence.json", "application/json")),
    ]
    for index, (icon_name, title, sub, export) in enumerate(actions):
        with st.container(key=f"action-{index}"):
            text_col, button_col = st.columns([0.64, 0.36], vertical_alignment="center", gap="small")
            with text_col:
                _action(icon_name, title, sub)
            with button_col:
                if export is None:
                    top = max(result.findings, key=lambda f: f.score) if result.findings else None
                    if st.button("Open", key="action-detail", icon=":material/chevron_right:", icon_position="right",
                                 disabled=top is None, width="stretch"):
                        show_finding_dialog(top.id)
                else:
                    build, file_name, mime = export
                    st.download_button("Save", data=build(result), file_name=file_name, mime=mime,
                                       key=f"download-{index}", icon=":material/download:", width="stretch")


# -- page ----------------------------------------------------------------------------------

def page() -> None:
    upload_bar()
    if st.session_state.error:
        notice(st.session_state.error, "error")
    result = st.session_state.result
    if result is None:
        empty_state("No capture analyzed yet",
                    "Upload a .pcap or .pcapng file and click Analyze PCAP, or try one of the sample captures.")
        return
    for note in result.notes:
        notice(note, "warn")
    summary_cards(result)
    overview_row(result)
    threats_table(result)
    lower_row(result)
