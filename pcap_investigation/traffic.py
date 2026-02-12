"""Capture-wide traffic statistics used by the dashboard and the report."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

import pandas as pd

SERVICE_NAMES = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP", 137: "NetBIOS",
    138: "NetBIOS", 139: "NetBIOS", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS",
    5432: "PostgreSQL", 5900: "VNC", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
}


def service_name(port) -> str:
    if port is None or pd.isna(port):
        return ""
    return SERVICE_NAMES.get(int(port), "")


def port_label(port) -> str:
    name = service_name(port)
    return f"{int(port)} ({name})" if name else str(int(port))


# Internal = the private LAN ranges (RFC 1918) plus IPv6 unique-local addresses.
# Everything else that is unicast counts as External. (Python's own is_private
# also includes documentation ranges, which would hide "external" test hosts.)
INTERNAL_NETWORKS = [ipaddress.ip_network(n) for n in
                     ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]


def ip_scope(address: str) -> str:
    """Internal (private LAN), External, Special (multicast, broadcast ...) or Unknown."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return "Unknown"
    if ip.is_multicast or ip.is_unspecified or ip.is_loopback or ip.is_link_local \
            or str(ip) == "255.255.255.255" or str(ip).endswith(".255"):
        return "Special"
    if any(ip in network for network in INTERNAL_NETWORKS):
        return "Internal"
    return "External"


def is_unicast(address) -> bool:
    return isinstance(address, str) and ip_scope(address) in ("Internal", "External")


@dataclass
class TrafficSummary:
    total_packets: int
    total_bytes: int
    first_ts: float
    last_ts: float
    duration: float
    unique_hosts: int
    internal_hosts: int
    external_hosts: int
    ip_packets: int
    protocol_counts: dict[str, int] = field(default_factory=dict)
    top_dst_ports: list[dict] = field(default_factory=list)
    other_ports_packets: int = 0


def summarize(frame: pd.DataFrame, top_ports: int = 6) -> TrafficSummary:
    first_ts = float(frame["ts"].min())
    last_ts = float(frame["ts"].max())
    ip_rows = frame[frame["src_ip"].notna()]
    hosts = pd.unique(pd.concat([ip_rows["src_ip"], ip_rows["dst_ip"]]).dropna())
    scopes = [ip_scope(h) for h in hosts]

    port_rows = frame[frame["protocol"].isin(["TCP", "UDP"]) & frame["dport"].notna()]
    port_counts = port_rows["dport"].astype(int).value_counts()
    top = port_counts.head(top_ports)
    top_list = [{"port": int(p), "service": service_name(p), "label": port_label(p),
                 "packets": int(c)} for p, c in top.items()]

    return TrafficSummary(
        total_packets=int(len(frame)),
        total_bytes=int(frame["length"].sum()),
        first_ts=first_ts,
        last_ts=last_ts,
        duration=max(0.0, last_ts - first_ts),
        unique_hosts=int(len(hosts)),
        internal_hosts=scopes.count("Internal"),
        external_hosts=scopes.count("External"),
        ip_packets=int(len(ip_rows)),
        protocol_counts={str(k): int(v) for k, v in frame["protocol"].value_counts().items()},
        top_dst_ports=top_list,
        other_ports_packets=int(port_counts.iloc[top_ports:].sum()) if len(port_counts) > top_ports else 0,
    )


def hosts_table(frame: pd.DataFrame) -> pd.DataFrame:
    """One row per IP address with sent/received counts and activity window."""
    ip_rows = frame[frame["src_ip"].notna()]
    if ip_rows.empty:
        return pd.DataFrame(columns=["ip", "scope", "packets_sent", "packets_received",
                                     "bytes_sent", "bytes_received", "peers",
                                     "first_seen", "last_seen"])
    sent = ip_rows.groupby("src_ip").agg(packets_sent=("frame", "size"), bytes_sent=("length", "sum"),
                                         first_s=("ts", "min"), last_s=("ts", "max"),
                                         peers_out=("dst_ip", "nunique"))
    received = ip_rows.groupby("dst_ip").agg(packets_received=("frame", "size"),
                                             bytes_received=("length", "sum"),
                                             first_r=("ts", "min"), last_r=("ts", "max"),
                                             peers_in=("src_ip", "nunique"))
    table = sent.join(received, how="outer")
    table.index.name = "ip"
    table = table.reset_index()
    for column in ["packets_sent", "bytes_sent", "packets_received", "bytes_received",
                   "peers_out", "peers_in"]:
        table[column] = table[column].fillna(0).astype(int)
    table["first_seen"] = table[["first_s", "first_r"]].min(axis=1)
    table["last_seen"] = table[["last_s", "last_r"]].max(axis=1)
    table["peers"] = table[["peers_out", "peers_in"]].max(axis=1)
    table["scope"] = table["ip"].map(ip_scope)
    table["total_packets"] = table["packets_sent"] + table["packets_received"]
    table = table.sort_values("total_packets", ascending=False).reset_index(drop=True)
    return table[["ip", "scope", "packets_sent", "packets_received", "bytes_sent",
                  "bytes_received", "peers", "first_seen", "last_seen"]]


def conversations_table(frame: pd.DataFrame, limit: int = 25) -> pd.DataFrame:
    """Top source -> destination pairs by packets."""
    ip_rows = frame[frame["src_ip"].notna()]
    if ip_rows.empty:
        return pd.DataFrame(columns=["src_ip", "dst_ip", "protocol", "packets", "bytes",
                                     "first_seen", "last_seen"])
    table = (ip_rows.groupby(["src_ip", "dst_ip", "protocol"])
             .agg(packets=("frame", "size"), bytes=("length", "sum"),
                  first_seen=("ts", "min"), last_seen=("ts", "max"))
             .reset_index()
             .sort_values("packets", ascending=False)
             .head(limit)
             .reset_index(drop=True))
    return table


_BIN_SIZES = [1, 2, 5, 10, 15, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 21600, 43200, 86400]


def choose_bin_size(duration: float, target_bins: int = 80) -> int:
    for size in _BIN_SIZES:
        if duration / size <= target_bins:
            return size
    return _BIN_SIZES[-1]


def timeline(frame: pd.DataFrame, bin_seconds: int | None = None) -> tuple[pd.DataFrame, int]:
    """Packets per time bin. Returns (table with bin_start/packets, bin size)."""
    first = float(frame["ts"].min())
    duration = float(frame["ts"].max()) - first
    size = bin_seconds or choose_bin_size(duration)
    bins = ((frame["ts"] - first) // size).astype(int)
    counts = bins.value_counts().sort_index()
    full = pd.Series(0, index=range(int(bins.max()) + 1))
    full.loc[counts.index] = counts.values
    table = pd.DataFrame({"bin_start": first + full.index * size, "packets": full.values})
    return table, size
