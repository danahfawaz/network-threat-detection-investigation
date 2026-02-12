"""Turn Scapy packets into one flat pandas table.

Every later step (statistics, detections, dashboard) works on this table, so
it is the single place that knows about Scapy layers. One row = one packet.
"""

from __future__ import annotations

import pandas as pd

# TCP flag bits
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10

COLUMNS = [
    "frame", "ts", "length", "src_mac", "dst_mac",
    "ip_version", "src_ip", "dst_ip", "protocol",
    "sport", "dport", "tcp_flags", "tcp_flags_str",
    "dns_id", "dns_qr", "dns_qname", "dns_qtype", "dns_rcode",
    "arp_op", "arp_psrc", "arp_hwsrc", "arp_pdst",
]

INT_COLUMNS = ["ip_version", "sport", "dport", "tcp_flags", "dns_id", "dns_qr",
               "dns_qtype", "dns_rcode", "arp_op"]


def _decode_name(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="replace")
    value = str(value)
    return value[:-1] if value.endswith(".") else value


def _dns_fields(dns) -> dict:
    fields = {"dns_id": dns.id, "dns_qr": int(dns.qr), "dns_rcode": int(dns.rcode)}
    questions = dns.qd
    try:
        first = questions[0] if questions else None
    except (IndexError, TypeError):
        first = None
    if first is not None:
        fields["dns_qname"] = _decode_name(getattr(first, "qname", None))
        fields["dns_qtype"] = getattr(first, "qtype", None)
    return fields


def packet_to_row(frame: int, packet) -> dict:
    """Extract the fields we need from one Scapy packet. Missing fields stay None."""
    from scapy.layers.dns import DNS
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether

    row: dict = {"frame": frame, "ts": float(packet.time), "length": len(packet)}

    ether = packet.getlayer(Ether)
    if ether is not None:
        row["src_mac"], row["dst_mac"] = ether.src, ether.dst

    arp = packet.getlayer(ARP)
    if arp is not None:
        row.update(protocol="ARP", arp_op=int(arp.op), arp_psrc=arp.psrc,
                   arp_hwsrc=arp.hwsrc, arp_pdst=arp.pdst)
        return row

    ip = packet.getlayer(IP)
    ip6 = packet.getlayer(IPv6) if ip is None else None
    if ip is None and ip6 is None:
        row["protocol"] = "Non-IP"
        return row

    if ip is not None:
        row.update(ip_version=4, src_ip=ip.src, dst_ip=ip.dst)
    else:
        row.update(ip_version=6, src_ip=ip6.src, dst_ip=ip6.dst)

    tcp = packet.getlayer(TCP)
    udp = packet.getlayer(UDP) if tcp is None else None
    if tcp is not None:
        flags = int(tcp.flags)
        row.update(protocol="TCP", sport=tcp.sport, dport=tcp.dport,
                   tcp_flags=flags, tcp_flags_str=str(tcp.flags))
    elif udp is not None:
        row.update(protocol="UDP", sport=udp.sport, dport=udp.dport)
    elif packet.getlayer(ICMP) is not None:
        row["protocol"] = "ICMP"
    elif ip6 is not None and packet.lastlayer().name.startswith("ICMPv6"):
        row["protocol"] = "ICMPv6"
    else:
        row["protocol"] = "IP-Other"

    if (tcp is not None or udp is not None) and 53 in (row.get("sport"), row.get("dport")):
        dns = packet.getlayer(DNS)
        if dns is not None:
            try:
                row.update(_dns_fields(dns))
            except Exception:  # malformed DNS payload: keep the transport fields
                pass
    return row


def normalize_packets(packets) -> pd.DataFrame:
    """Return a DataFrame with one row per packet and the columns in COLUMNS."""
    rows = []
    for frame, packet in enumerate(packets, start=1):
        try:
            rows.append(packet_to_row(frame, packet))
        except Exception:  # never let one odd packet stop the analysis
            rows.append({"frame": frame, "ts": float(getattr(packet, "time", 0.0)),
                         "length": len(bytes(packet)), "protocol": "Unparsed"})

    frame = pd.DataFrame(rows, columns=COLUMNS)
    for column in INT_COLUMNS:
        frame[column] = pd.to_numeric(frame[column], errors="coerce").astype("Int64")
    frame["ts"] = frame["ts"].astype(float)
    frame["length"] = frame["length"].astype(int)
    frame = frame.sort_values(["ts", "frame"], kind="stable").reset_index(drop=True)
    return frame


def has_flags(series: pd.Series, flags: int) -> pd.Series:
    """True where all given TCP flag bits are set (False for non-TCP rows)."""
    return ((series.fillna(0).astype(int) & flags) == flags)


def syn_only(frame: pd.DataFrame) -> pd.Series:
    """Connection requests: SYN set, ACK not set."""
    flags = frame["tcp_flags"]
    return (frame["protocol"] == "TCP") & has_flags(flags, SYN) & ~has_flags(flags, ACK)
