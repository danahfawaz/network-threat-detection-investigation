import pandas as pd
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from pcap_investigation.normalize import normalize_packets, syn_only
from pcap_investigation.traffic import (
    choose_bin_size,
    conversations_table,
    hosts_table,
    ip_scope,
    port_label,
    summarize,
    timeline,
)
from tests.conftest import BASE_TIME, stamp


def _mixed_packets():
    return stamp([
        Ether(src="02:00:00:00:00:01") / IP(src="192.168.10.5", dst="203.0.113.7") / TCP(sport=40000, dport=443, flags="S"),
        Ether() / IP(src="203.0.113.7", dst="192.168.10.5") / TCP(sport=443, dport=40000, flags="SA"),
        Ether() / IP(src="192.168.10.5", dst="192.168.10.1") / UDP(sport=5000, dport=53) / DNS(id=7, rd=1, qd=DNSQR(qname="portal.example.com")),
        Ether() / IP(src="192.168.10.1", dst="192.168.10.5") / UDP(sport=53, dport=5000) / DNS(id=7, qr=1, rcode=3, qd=DNSQR(qname="missing.example.com")),
        Ether() / IP(src="192.168.10.5", dst="192.168.10.1") / ICMP(),
        Ether() / ARP(op=2, psrc="192.168.10.1", hwsrc="02:00:00:00:00:fe", pdst="192.168.10.5"),
        Ether() / IPv6(src="fd00::1", dst="fd00::2") / UDP(sport=1000, dport=2000),
        Ether(type=0x88B5) / Raw(b"vendor frame"),
    ], step=1.0)


def test_normalize_extracts_core_fields():
    df = normalize_packets(_mixed_packets())
    assert list(df["frame"]) == list(range(1, 9))
    assert list(df["protocol"]) == ["TCP", "TCP", "UDP", "UDP", "ICMP", "ARP", "UDP", "Non-IP"]

    first = df.iloc[0]
    assert first["src_ip"] == "192.168.10.5" and first["dst_ip"] == "203.0.113.7"
    assert first["sport"] == 40000 and first["dport"] == 443
    assert first["tcp_flags_str"] == "S"
    assert first["src_mac"] == "02:00:00:00:00:01"
    assert first["ts"] == BASE_TIME


def test_normalize_extracts_dns_fields():
    df = normalize_packets(_mixed_packets())
    query, response = df.iloc[2], df.iloc[3]
    assert query["dns_qr"] == 0 and query["dns_qname"] == "portal.example.com"
    assert response["dns_qr"] == 1 and response["dns_rcode"] == 3
    assert response["dns_qname"] == "missing.example.com"


def test_normalize_extracts_arp_and_ipv6():
    df = normalize_packets(_mixed_packets())
    arp = df.iloc[5]
    assert arp["arp_op"] == 2 and arp["arp_psrc"] == "192.168.10.1"
    assert arp["arp_hwsrc"] == "02:00:00:00:00:fe"
    assert pd.isna(arp["src_ip"])
    ipv6 = df.iloc[6]
    assert ipv6["ip_version"] == 6 and ipv6["src_ip"] == "fd00::1"


def test_non_ip_frame_has_missing_ip_fields():
    df = normalize_packets(_mixed_packets())
    row = df.iloc[7]
    assert pd.isna(row["src_ip"]) and pd.isna(row["dport"])


def test_rows_sorted_by_time_even_if_capture_is_not():
    packets = _mixed_packets()[:3]
    packets[0].time = BASE_TIME + 100
    df = normalize_packets(packets)
    assert list(df["frame"]) == [2, 3, 1]


def test_syn_only_mask():
    df = normalize_packets(_mixed_packets())
    assert list(syn_only(df)) == [True] + [False] * 7


def test_summary_counts():
    summary = summarize(normalize_packets(_mixed_packets()))
    assert summary.total_packets == 8
    assert summary.duration == 7.0
    # 192.168.10.5, 203.0.113.7, 192.168.10.1, fd00::1, fd00::2
    assert summary.unique_hosts == 5
    assert summary.external_hosts == 1
    assert summary.protocol_counts["TCP"] == 2
    assert summary.top_dst_ports[0]["packets"] >= 1


def test_top_ports_ignore_replies_to_client_ports():
    summary = summarize(normalize_packets(_mixed_packets()))
    ports = [p["port"] for p in summary.top_dst_ports]
    assert 443 in ports and 53 in ports
    assert 40000 not in ports and 5000 not in ports  # client-side reply ports


def test_hosts_table_counts_sent_and_received():
    hosts = hosts_table(normalize_packets(_mixed_packets())).set_index("ip")
    assert hosts.loc["192.168.10.5", "packets_sent"] == 3
    assert hosts.loc["192.168.10.5", "packets_received"] == 2
    assert hosts.loc["203.0.113.7", "scope"] == "External"


def test_conversations_table():
    conv = conversations_table(normalize_packets(_mixed_packets()))
    assert {"src_ip", "dst_ip", "protocol", "packets"} <= set(conv.columns)
    assert conv["packets"].sum() == 6  # every IPv4/IPv6 packet


def test_timeline_bins_cover_capture():
    df = normalize_packets(_mixed_packets())
    table, size = timeline(df, bin_seconds=2)
    assert size == 2
    assert table["packets"].sum() == 8
    assert len(table) == 4


def test_helpers():
    assert ip_scope("10.1.2.3") == "Internal"
    assert ip_scope("8.8.8.8") == "External"
    assert ip_scope("224.0.0.251") == "Special"
    assert ip_scope("not-an-ip") == "Unknown"
    assert port_label(22) == "22 (SSH)"
    assert port_label(4444) == "4444"
    assert choose_bin_size(60) == 1
    assert choose_bin_size(3600) == 60
