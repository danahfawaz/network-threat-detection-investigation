from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pcap_investigation.config import PortScanConfig
from pcap_investigation.detections import port_scan
from pcap_investigation.normalize import normalize_packets
from tests.conftest import BASE_TIME

SCANNER, TARGET = "192.168.1.20", "192.168.1.50"


def _scan(port_count, step=0.2, open_ports=(), target=TARGET, start=BASE_TIME):
    packets = []
    for i in range(port_count):
        port = 1000 + i if i >= 2 else (22, 80)[i]
        syn = Ether() / IP(src=SCANNER, dst=target) / TCP(sport=40000 + i, dport=port, flags="S")
        syn.time = start + i * step
        packets.append(syn)
        flags = "SA" if port in open_ports else "RA"
        reply = Ether() / IP(src=target, dst=SCANNER) / TCP(sport=port, dport=40000 + i, flags=flags)
        reply.time = syn.time + 0.001
        packets.append(reply)
    return packets


def test_below_threshold_is_not_flagged():
    df = normalize_packets(_scan(14))
    assert port_scan.detect(df, PortScanConfig(min_targets=15)) == []


def test_at_threshold_is_flagged():
    df = normalize_packets(_scan(15))
    findings = port_scan.detect(df, PortScanConfig(min_targets=15))
    assert len(findings) == 1
    assert findings[0].src_ip == SCANNER and findings[0].dst_ip == TARGET


def test_slow_scan_outside_window_is_not_flagged():
    # 20 ports but one every 10 s -> at most 7 in any 60 s window
    df = normalize_packets(_scan(20, step=10.0))
    assert port_scan.detect(df, PortScanConfig(min_targets=15, window_seconds=60)) == []


def test_evidence_counts_open_and_closed_ports():
    df = normalize_packets(_scan(31, step=0.2, open_ports=(22, 80)))
    finding = port_scan.detect(df, PortScanConfig())[0]
    assert finding.metrics["ports"] == 31
    assert finding.metrics["open_ports"] == [22, 80]
    assert finding.metrics["refused"] == 29
    assert finding.event_count == 31
    assert finding.first_seen == BASE_TIME
    assert any("Open ports found: 22 (SSH), 80 (HTTP)" in line for line in finding.evidence)
    assert "31 ports" in finding.summary


def test_scoring_signals_reflect_behavior():
    df = normalize_packets(_scan(31, step=0.2, open_ports=(22,)))
    signals = port_scan.detect(df, PortScanConfig())[0].signals
    assert round(signals.ratio, 2) == round(31 / 15, 2)
    assert signals.fast is not None          # 31 probes in 6 s
    assert "22 (SSH)" in signals.sensitive    # admin port probed
    assert signals.confirmed is not None      # an open port answered
    assert signals.persistent is None


def test_horizontal_sweep_counts_hosts():
    packets = []
    for i in range(16):
        pkt = Ether() / IP(src=SCANNER, dst=f"192.168.1.{100 + i}") / TCP(sport=50000 + i, dport=445, flags="S")
        pkt.time = BASE_TIME + i * 0.5
        packets.append(pkt)
    finding = port_scan.detect(normalize_packets(packets), PortScanConfig())[0]
    assert finding.dst_ip is None
    assert len(finding.targets) == 16
    assert finding.destination_label == "16 hosts"


def test_normal_handshakes_are_not_scans():
    # A client opening 30 normal connections to one web server port is not a scan.
    packets = []
    for i in range(30):
        pkt = Ether() / IP(src=SCANNER, dst=TARGET) / TCP(sport=41000 + i, dport=443, flags="S")
        pkt.time = BASE_TIME + i
        packets.append(pkt)
    assert port_scan.detect(normalize_packets(packets), PortScanConfig()) == []
