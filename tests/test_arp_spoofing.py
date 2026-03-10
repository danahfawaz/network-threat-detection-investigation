from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from pcap_investigation.config import ArpConfig
from pcap_investigation.detections import arp_spoofing
from pcap_investigation.normalize import normalize_packets
from tests.conftest import BASE_TIME

GATEWAY, GATEWAY_MAC = "192.168.1.1", "02:00:00:00:00:01"
VICTIM, VICTIM_MAC = "192.168.1.20", "02:00:00:00:00:20"
ROGUE_MAC = "02:00:00:00:00:66"


def arp(op, psrc, hwsrc, pdst, ts):
    pkt = Ether(src=hwsrc) / ARP(op=op, psrc=psrc, hwsrc=hwsrc, pdst=pdst)
    pkt.time = ts
    return pkt


def normal_arp():
    return [arp(1, VICTIM, VICTIM_MAC, GATEWAY, BASE_TIME),
            arp(2, GATEWAY, GATEWAY_MAC, VICTIM, BASE_TIME + 0.001)]


def spoofed_replies(count=5, start=BASE_TIME + 10):
    return [arp(2, GATEWAY, ROGUE_MAC, VICTIM, start + i * 2) for i in range(count)]


def internet_traffic():
    # victim sends traffic to the internet through the gateway MAC
    pkt = Ether(src=VICTIM_MAC, dst=GATEWAY_MAC) / IP(src=VICTIM, dst="198.51.100.10") / TCP(dport=443)
    pkt.time = BASE_TIME + 1
    return [pkt]


def run(packets, **cfg):
    return arp_spoofing.detect(normalize_packets(packets), ArpConfig(**cfg))


def test_consistent_arp_is_clean():
    assert run(normal_arp() * 3 + internet_traffic()) == []


def test_ip_claimed_by_second_mac_is_flagged():
    findings = run(normal_arp() + internet_traffic() + spoofed_replies())
    assert len(findings) == 1
    finding = findings[0]
    assert finding.metrics["claimed_ip"] == GATEWAY
    assert finding.metrics["original_mac"] == GATEWAY_MAC
    assert finding.metrics["suspect_macs"] == [ROGUE_MAC]
    assert finding.src_mac == ROGUE_MAC and finding.source_label == ROGUE_MAC
    assert finding.targets == [VICTIM]
    assert finding.metrics["unsolicited_replies"] == 5
    assert finding.signals.sensitive  # gateway identified from internet traffic
    assert finding.signals.confirmed  # unsolicited replies


def test_suspect_mac_is_linked_to_its_ip():
    rogue_ip = Ether(src=ROGUE_MAC) / IP(src="192.168.1.66", dst=VICTIM) / TCP(dport=80)
    rogue_ip.time = BASE_TIME + 5
    finding = run(normal_arp() + spoofed_replies() + [rogue_ip])[0]
    assert finding.src_ip == "192.168.1.66"


def test_solicited_reply_is_not_counted_as_unsolicited():
    request = arp(1, VICTIM, VICTIM_MAC, GATEWAY, BASE_TIME + 9.5)
    finding = run(normal_arp() + [request] + spoofed_replies(count=1))[0]
    assert finding.metrics["unsolicited_replies"] == 0
    assert finding.signals.confirmed is None


def test_arp_probes_from_0_0_0_0_are_ignored():
    probes = [arp(1, "0.0.0.0", f"02:00:00:00:01:{i:02x}", "192.168.1.99", BASE_TIME + i) for i in range(3)]
    assert run(probes) == []
