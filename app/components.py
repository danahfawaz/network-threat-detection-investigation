"""Small HTML building blocks for the dashboard.

Every value that can come from a capture (IP addresses, DNS names, ...) goes
through ``esc()`` before it is placed in HTML, so packet data cannot inject
markup into the page.
"""

from __future__ import annotations

import html
from pathlib import Path

import streamlit as st

from app.theme import SEVERITY, SEVERITY_BADGE

CSS_FILE = Path(__file__).with_name("style.css")

# Simple outline icons (24x24, stroke = currentColor).
_ICON_PATHS = {
    "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'
            '<path d="M9 13h6M9 17h4"/>',
    "packets": '<ellipse cx="12" cy="5.5" rx="7" ry="2.5"/><path d="M5 5.5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6"/>'
               '<path d="M5 11.5v6c0 1.4 3.1 2.5 7 2.5s7-1.1 7-2.5v-6"/>',
    "hosts": '<circle cx="9" cy="8" r="3.2"/><path d="M3.5 19c.6-3.2 2.8-5 5.5-5s4.9 1.8 5.5 5"/>'
             '<circle cx="17" cy="9" r="2.4"/><path d="M15.8 14.2c2.3.2 4.1 1.8 4.7 4.8"/>',
    "alert": '<path d="M12 3.5 2.8 19.5h18.4z"/><path d="M12 10v4.5"/><circle cx="12" cy="17" r=".6" fill="currentColor"/>',
    "shield": '<path d="M12 3 5 6v5.5c0 4.4 3 7.9 7 9.5 4-1.6 7-5.1 7-9.5V6z"/><path d="M12 8.5v6M9.5 12.3 12 14.8l2.5-2.5"/>',
    "clock": '<circle cx="12" cy="12" r="8.5"/><path d="M12 7.5V12l3 2"/>',
    "report": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/>'
              '<path d="M8.5 17v-3M12 17v-5M15.5 17v-2"/>',
    "table": '<rect x="4" y="4.5" width="16" height="15" rx="2"/><path d="M4 9.5h16M4 14.5h16M10 9.5v10"/>',
    "braces": '<path d="M9 4.5c-2 0-2.5 1-2.5 2.5v2.5c0 1.2-.8 2-2 2.5 1.2.5 2 1.3 2 2.5V17c0 1.5.5 2.5 2.5 2.5"/>'
              '<path d="M15 4.5c2 0 2.5 1 2.5 2.5v2.5c0 1.2.8 2 2 2.5-1.2.5-2 1.3-2 2.5V17c0 1.5-.5 2.5-2.5 2.5"/>',
    "search": '<circle cx="11" cy="11" r="6"/><path d="m15.5 15.5 4 4"/><path d="M8.5 11h5"/>',
    "check": '<circle cx="12" cy="12" r="8.5"/><path d="m8.5 12.3 2.4 2.4 4.6-4.9"/>',
}


def esc(value) -> str:
    return html.escape("" if value is None else str(value))


def icon(name: str, size: int = 22) -> str:
    return (f'<svg class="ico" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" '
            f'stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" '
            f'aria-hidden="true">{_ICON_PATHS[name]}</svg>')


def render(markup: str) -> None:
    st.markdown(markup, unsafe_allow_html=True)


def inject_css() -> None:
    render(f"<style>{CSS_FILE.read_text()}</style>")


def badge(severity: str) -> str:
    color = SEVERITY_BADGE.get(severity, SEVERITY_BADGE["None"])
    return f'<span class="badge" style="background:{color}">{esc(severity)}</span>'


def stat_card(icon_name: str, label: str, value: str, sub: str = "") -> str:
    return (f'<div class="stat-card"><div class="icon-tile">{icon(icon_name, 26)}</div>'
            f'<div class="stat-body"><div class="stat-label">{label}</div>'
            f'<div class="stat-value">{value}</div><div class="stat-sub">{sub}</div></div></div>')


def panel_title(text: str, hint: str = "") -> str:
    hint_html = f' <span class="panel-hint">{hint}</span>' if hint else ""
    return f'<div class="panel-title">{esc(text)}{hint_html}</div>'


def bar_list(rows: list[dict], label_width: str = "38%") -> str:
    """Horizontal bars: rows of {label, value, color, title}. Lengths are relative to the max."""
    if not rows:
        return '<div class="empty-note">Nothing to show.</div>'
    peak = max(r["value"] for r in rows) or 1
    items = []
    for r in rows:
        width = max(r["value"] / peak * 100, 2)
        display = r.get("display") or f"{r['value']:,}"
        tooltip = esc(r.get("title", ""))
        items.append(
            f'<div class="bar-row" title="{tooltip}">'
            f'<div class="bar-label" style="width:{label_width}">{r["label"]}</div>'
            f'<div class="bar-track"><div class="bar-fill" style="width:{width:.1f}%;background:{r["color"]}"></div></div>'
            f'<div class="bar-value">{esc(display)}</div></div>')
    return '<div class="bar-list">' + "".join(items) + "</div>"


def severity_legend(counts: dict[str, int]) -> str:
    rows = []
    for name in ["Critical", "High", "Medium", "Low"]:
        rows.append(f'<div class="legend-row"><span class="dot" style="background:{SEVERITY[name]}"></span>'
                    f'<span class="legend-name">{name}</span><span class="legend-count">{counts.get(name, 0)}</span></div>')
    return '<div class="sev-legend">' + "".join(rows) + "</div>"


def notice(text: str, kind: str = "info") -> None:
    render(f'<div class="notice notice-{kind}">{esc(text)}</div>')


def empty_state(title: str, text: str) -> None:
    render(f'<div class="empty-state">{icon("file", 34)}<div class="empty-title">{esc(title)}</div>'
           f'<div class="empty-text">{esc(text)}</div></div>')
