"""Reports - exports and a preview of the HTML investigation report."""

from __future__ import annotations

from pathlib import Path

import streamlit as st
import streamlit.components.v1 as components

from app.components import icon, panel_title, render
from pcap_investigation.reporting.exports import alerts_csv, evidence_json
from pcap_investigation.reporting.html_report import render_report


def page(result) -> None:
    stem = Path(result.capture.file_name).stem
    report_html = render_report(result)
    exports = [
        ("report", "Investigation Report (HTML)",
         "Summary, capture hash, timeline, findings with evidence and score explanation, involved hosts "
         "and next steps. Opens in any browser.",
         report_html, f"{stem}_investigation_report.html", "text/html"),
        ("table", "Alerts (CSV)",
         "One row per finding: time, type, source, destination, severity, risk score and evidence.",
         alerts_csv(result), f"{stem}_alerts.csv", "text/csv"),
        ("braces", "Evidence (JSON)",
         "Machine-readable findings with sample packets, metrics and the thresholds used.",
         evidence_json(result), f"{stem}_evidence.json", "application/json"),
    ]
    cols = st.columns(3, gap="small")
    for index, (col, (icon_name, title, text, data, file_name, mime)) in enumerate(zip(cols, exports)):
        with col, st.container(key=f"export-card-{index}", border=True):
            render(f'<div class="export-card"><div class="icon-tile">{icon(icon_name, 24)}</div>'
                   f'<div class="action-title">{title}</div><div class="action-sub">{text}</div></div>')
            st.download_button(f"Download {file_name.rsplit('.', 1)[1].upper()}", data=data, file_name=file_name,
                               mime=mime, icon=":material/download:", key=f"report-dl-{index}", width="stretch",
                               type="primary" if index == 0 else "secondary")

    with st.container(key="panel-report-preview", border=True):
        render(panel_title("Report Preview"))
        components.html(report_html, height=760, scrolling=True)
