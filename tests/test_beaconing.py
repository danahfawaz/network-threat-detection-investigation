import random

from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from pcap_investigation.config import BeaconConfig
from pcap_investigation.detections import beaconing
from pcap_investigation.detections.beaconing import regularity
from pcap_investigation.normalize import normalize_packets
from tests.conftest import BASE_TIME

HOST, SERVER = "192.168.1.25", "203.0.113.10"


def tcp_connections(times, dport=8443, dst=SERVER):
    packets = []
    for i, ts in enumerate(times):
        pkt = Ether() / IP(src=HOST, dst=dst) / TCP(sport=50000 + i, dport=dport, flags="S")
        pkt.time = ts
        packets.append(pkt)
    return packets


def periodic(count, interval=60.0, jitter=0.0, seed=1):
    rng = random.Random(seed)
    times, t = [], BASE_TIME
    for _ in range(count):
        times.append(t)
        t += interval * (1 + rng.uniform(-jitter, jitter))
    return times


def run(packets, **cfg):
    return beaconing.detect(normalize_packets(packets), BeaconConfig(**cfg))


def test_regularity_helper():
    median, regular, spread = regularity([0, 60, 120, 180, 240], 0.15)
    assert median == 60 and regular == 1.0 and spread == 0.0


def test_regular_beacon_is_flagged():
    findings = run(tcp_connections(periodic(12, 60, jitter=0.04)))
    assert len(findings) == 1
    finding = findings[0]
    assert (finding.src_ip, finding.dst_ip, finding.ports) == (HOST, SERVER, [8443])
    assert 55 <= finding.metrics["median_interval_seconds"] <= 65
    assert finding.signals.sensitive        # external destination
    assert finding.signals.persistent       # 11 minutes
    assert finding.signals.confirmed        # very regular


def test_too_few_connections():
    assert run(tcp_connections(periodic(7, 60))) == []
    assert len(run(tcp_connections(periodic(8, 60)))) == 1


def test_irregular_connections_are_not_beacons():
    rng = random.Random(7)
    times, t = [], BASE_TIME
    for _ in range(20):
        times.append(t)
        t += rng.expovariate(1 / 40.0) + 1  # human-like random gaps
    assert run(tcp_connections(times)) == []


def test_interval_limits():
    assert run(tcp_connections(periodic(12, 2.0))) == []          # too fast (below 10 s)
    assert run(tcp_connections(periodic(12, 2.0)), min_interval=1.0) != []


def test_jitter_tolerance():
    times = periodic(12, 60, jitter=0.3, seed=3)
    assert run(tcp_connections(times), tolerance=0.15) == []
    assert run(tcp_connections(times), tolerance=0.35) != []


def test_udp_sessions_and_ignored_ports():
    packets = []
    for i, ts in enumerate(periodic(10, 30)):
        for j in range(3):  # each UDP "session" is a few packets close together
            pkt = Ether() / IP(src=HOST, dst=SERVER) / UDP(sport=40000, dport=9999)
            pkt.time = ts + j * 0.05
            packets.append(pkt)
    findings = run(packets)
    assert len(findings) == 1 and findings[0].event_count == 10 and findings[0].protocol == "UDP"
    # NTP (123) is periodic by design and ignored
    ntp = [p.copy() for p in packets]
    for p in ntp:
        p[UDP].dport = 123
    assert run(ntp) == []
