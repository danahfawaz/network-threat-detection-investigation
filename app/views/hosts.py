"""Hosts & Traffic - every IP address and the busiest conversations."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from app.components import panel_title, render
from pcap_investigation.models import SEVERITY_ORDER, format_ts
from pcap_investigation.traffic import conversations_table, hosts_table


def _finding_columns(result, hosts: pd.DataFrame) -> pd.DataFrame:
    linked: dict[str, list] = {}
    for f in result.findings:
        for address in {f.source_label, *f.targets}:
            linked.setdefault(address, []).append(f)
    hosts["findings"] = hosts["ip"].map(lambda ip: ", ".join(f.id for f in linked.get(ip, [])))
    hosts["highest severity"] = hosts["ip"].map(
        lambda ip: min((f.severity for f in linked.get(ip, [])), key=SEVERITY_ORDER.index, default=""))
    return hosts


def page(result) -> None:
    hosts = _finding_columns(result, hosts_table(result.packets))
    with st.container(key="panel-hosts", border=True):
        title, search = st.columns([3, 1.2], vertical_alignment="center")
        with title:
            render(panel_title("Hosts", f"({len(hosts)} IP addresses)"))
        with search:
            query = st.text_input("Filter", placeholder="Filter by IP address", label_visibility="collapsed",
                                  key="host-filter")
        only_flagged = st.toggle("Only hosts involved in findings", key="hosts-flagged")
        view = hosts
        if query:
            view = view[view["ip"].str.contains(query.strip(), regex=False)]
        if only_flagged:
            view = view[view["findings"] != ""]
        view = view.assign(first_seen=view["first_seen"].map(format_ts), last_seen=view["last_seen"].map(format_ts))
        st.dataframe(
            view, hide_index=True, width="stretch", height=min(38 * (len(view) + 1) + 4, 460),
            column_config={
                "ip": "IP address", "scope": "Scope", "packets_sent": "Packets sent",
                "packets_received": "Packets received",
                "bytes_sent": st.column_config.NumberColumn("Bytes sent", format="%d"),
                "bytes_received": st.column_config.NumberColumn("Bytes received", format="%d"),
                "peers": "Peers", "first_seen": "First seen (UTC)", "last_seen": "Last seen (UTC)",
                "findings": "Findings", "highest severity": "Highest severity",
            })

    with st.container(key="panel-conversations", border=True):
        render(panel_title("Top Conversations", "(source to destination, by packets)"))
        conv = conversations_table(result.packets)
        conv = conv.assign(first_seen=conv["first_seen"].map(format_ts), last_seen=conv["last_seen"].map(format_ts))
        st.dataframe(conv, hide_index=True, width="stretch",
                     column_config={"src_ip": "Source", "dst_ip": "Destination", "protocol": "Protocol",
                                    "packets": "Packets", "bytes": "Bytes", "first_seen": "First seen (UTC)",
                                    "last_seen": "Last seen (UTC)"})
