"""Settings - detection rules and thresholds for this session."""

from __future__ import annotations

import copy

import streamlit as st

from app.components import panel_title, render
from app.state import reanalyze_with_config
from pcap_investigation.config import RULE_KEYS, DetectionConfig
from pcap_investigation.pipeline import RULE_TITLES


def page() -> None:
    current: DetectionConfig = st.session_state.config
    render('<div class="muted small settings-intro">Changes apply to this browser session only. The defaults are '
           'documented in docs/detection-rules.md and pcap_investigation/config.py.</div>')

    with st.form("settings"):
        cfg = copy.deepcopy(current)
        with st.container(key="panel-rules", border=True):
            render(panel_title("Enabled Rules"))
            cols = st.columns(3)
            enabled = []
            for i, key in enumerate(RULE_KEYS):
                with cols[i % 3]:
                    if st.checkbox(RULE_TITLES[key], value=key in current.enabled_rules, key=f"rule-{key}"):
                        enabled.append(key)
            cfg.enabled_rules = tuple(enabled)

        c1, c2 = st.columns(2, gap="small")
        with c1:
            with st.container(key="panel-set-scan", border=True):
                render(panel_title("Port Scan"))
                cfg.port_scan.min_targets = st.number_input("Different host/port targets", 2, 10_000,
                                                            current.port_scan.min_targets)
                cfg.port_scan.window_seconds = st.number_input("Time window (seconds)", 1.0, 3600.0,
                                                               current.port_scan.window_seconds)
            with st.container(key="panel-set-conn", border=True):
                render(panel_title("Repeated Connection Attempts"))
                a = current.connection_attempts
                cfg.connection_attempts.min_attempts = st.number_input("Attempts", 2, 10_000, a.min_attempts)
                cfg.connection_attempts.window_seconds = st.number_input("Time window (seconds) ", 1.0, 3600.0,
                                                                         a.window_seconds)
                cfg.connection_attempts.failure_ratio = st.slider("Failed share (any port)", 0.1, 1.0,
                                                                  a.failure_ratio, 0.05)
                cfg.connection_attempts.watchlist_min_attempts = st.number_input("Attempts to a watchlist port",
                                                                                 1, 1000, a.watchlist_min_attempts)
            with st.container(key="panel-set-arp", border=True):
                render(panel_title("ARP Spoofing"))
                cfg.arp.min_macs = st.number_input("MAC addresses for one IP", 2, 20, current.arp.min_macs)
        with c2:
            with st.container(key="panel-set-dns", border=True):
                render(panel_title("DNS Anomalies"))
                d = current.dns
                cfg.dns.query_flood_count = st.number_input("Query flood: queries", 10, 100_000, d.query_flood_count)
                cfg.dns.query_flood_window = st.number_input("Query flood: window (seconds)", 1.0, 3600.0,
                                                             d.query_flood_window)
                cfg.dns.long_label_length = st.number_input("Suspicious name: label length", 10, 63, d.long_label_length)
                cfg.dns.entropy_threshold = st.number_input("Suspicious name: entropy", 2.0, 6.0, d.entropy_threshold,
                                                            0.1)
                cfg.dns.suspicious_name_min_count = st.number_input("Suspicious names needed", 1, 1000,
                                                                    d.suspicious_name_min_count)
                cfg.dns.nxdomain_min_count = st.number_input("Failed lookups needed", 1, 10_000, d.nxdomain_min_count)
            with st.container(key="panel-set-burst", border=True):
                render(panel_title("Traffic Burst"))
                b = current.traffic_burst
                cfg.traffic_burst.min_packets = st.number_input("Packets in the window", 10, 10_000_000, b.min_packets)
                cfg.traffic_burst.window_seconds = st.number_input("Window (seconds)", 1.0, 600.0, b.window_seconds)
                cfg.traffic_burst.min_ratio = st.number_input("Times the host's normal rate", 1.0, 1000.0, b.min_ratio)
            with st.container(key="panel-set-beacon", border=True):
                render(panel_title("Beacon-Like Connections"))
                bc = current.beaconing
                cfg.beaconing.min_connections = st.number_input("Connections", 3, 10_000, bc.min_connections)
                cfg.beaconing.tolerance = st.slider("Timing tolerance (+/-)", 0.01, 0.5, bc.tolerance, 0.01)
                cfg.beaconing.min_interval = st.number_input("Shortest typical gap (seconds)", 1.0, 3600.0,
                                                             bc.min_interval)

        apply_col, reset_col, _ = st.columns([1.3, 1.3, 4])
        with apply_col:
            applied = st.form_submit_button("Apply and re-analyze", type="primary", icon=":material/refresh:")
        with reset_col:
            reset = st.form_submit_button("Reset to defaults", icon=":material/restart_alt:")

    if applied:
        st.session_state.config = cfg
        st.success("Settings saved." + (" The capture was analyzed again." if reanalyze_with_config() else ""))
    if reset:
        st.session_state.config = DetectionConfig()
        for key in list(st.session_state.keys()):
            if str(key).startswith("rule-"):
                del st.session_state[key]
        reanalyze_with_config()
        st.rerun()
