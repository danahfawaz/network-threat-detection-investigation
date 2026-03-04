from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from pcap_investigation.config import TrafficBurstConfig
from pcap_investigation.detections import traffic_burst
from pcap_investigation.normalize import normalize_packets
from tests.conftest import BASE_TIME

HOST, REMOTE = "192.168.1.20", "203.0.113.80"


def flow(count, start, seconds, src=HOST, dst=REMOTE):
    packets = []
    step = seconds / count
    for i in range(count):
        pkt = Ether() / IP(src=src, dst=dst) / UDP(sport=40000, dport=443)
        pkt.time = start + i * step
        packets.append(pkt)
    return packets


def background(seconds=300, every=5.0, src=HOST):
    return flow(int(seconds / every), BASE_TIME, seconds, src=src, dst="198.51.100.10")


def run(packets, **cfg):
    return traffic_burst.detect(normalize_packets(packets), TrafficBurstConfig(**cfg))


def test_burst_is_flagged_with_evidence():
    findings = run(background() + flow(1500, BASE_TIME + 100, 5))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.src_ip == HOST and finding.dst_ip == REMOTE
    assert finding.metrics["peak_packets"] >= 1500
    assert finding.metrics["times_normal"] >= 10
    assert finding.signals.fast and finding.signals.sensitive  # quick, to an external address
    assert finding.signals.confirmed  # nothing came back: one-way


def test_below_minimum_packets_is_not_flagged():
    assert run(background() + flow(900, BASE_TIME + 100, 5)) == []


def test_always_busy_host_is_not_flagged():
    # 120 packets every 10 s for 5 minutes: above the (lowered) minimum in every
    # window, but that is normal for this host, so it is not a burst.
    busy = flow(3600, BASE_TIME, 300)
    assert run(busy, min_packets=100) == []


def test_capture_too_short_for_a_baseline():
    assert run(flow(1500, BASE_TIME, 5)) == []


def test_ratio_threshold_is_configurable():
    packets = background(every=0.1) + flow(1500, BASE_TIME + 100, 5)  # normal = 100 per 10 s
    assert run(packets, min_ratio=10.0) != []   # ~16x normal
    assert run(packets, min_ratio=20.0) == []
