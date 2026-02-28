from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether

from pcap_investigation.config import ConnectionAttemptConfig
from pcap_investigation.detections import connection_attempts
from pcap_investigation.normalize import normalize_packets
from tests.conftest import BASE_TIME

ATTACKER, SERVER = "203.0.113.45", "192.168.1.40"


def attempts(count, dport=22, answer="accept", step=2.0, src=ATTACKER, dst=SERVER, start=BASE_TIME):
    packets = []
    for i in range(count):
        sport = 50000 + i
        ts = start + i * step
        syn = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags="S")
        syn.time = ts
        packets.append(syn)
        if answer == "accept":
            reply = Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="SA")
        elif answer == "refuse":
            reply = Ether() / IP(src=dst, dst=src) / TCP(sport=dport, dport=sport, flags="RA")
        else:
            continue
        reply.time = ts + 0.01
        packets.append(reply)
    return packets


def run(packets, **cfg):
    return connection_attempts.detect(normalize_packets(packets), ConnectionAttemptConfig(**cfg))


def test_password_guessing_threshold():
    assert run(attempts(9)) == []
    findings = run(attempts(10))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.subtype == "Possible password guessing"
    assert (finding.src_ip, finding.dst_ip, finding.ports) == (ATTACKER, SERVER, [22])
    assert finding.metrics["accepted"] == 10
    assert "SSH (port 22)" in finding.summary


def test_attempts_outside_window_are_not_counted_together():
    # 12 attempts but one per 15 s -> at most 9 in any 120 s window
    assert run(attempts(12, step=15.0)) == []


def test_many_https_connections_are_normal():
    assert run(attempts(30, dport=443, answer="accept", step=1.0)) == []


def test_repeated_failed_connections_any_port():
    findings = run(attempts(12, dport=8080, answer="refuse"))
    assert [f.subtype for f in findings] == ["Repeated failed connections"]
    assert findings[0].metrics["failure_ratio"] == 1.0


def test_watchlist_port_needs_only_a_few_attempts():
    assert run(attempts(2, dport=4444, answer="none", step=10)) == []
    findings = run(attempts(3, dport=4444, answer="none", step=10))
    assert [f.subtype for f in findings] == ["Connections to a watchlist port"]
    assert findings[0].metrics["no_answer"] == 3


def test_retransmitted_syn_is_counted_once():
    packets = attempts(9)
    retransmit = packets[0].copy()
    retransmit.time = packets[0].time + 1.0
    assert run(packets + [retransmit]) == []


def test_signals_for_brute_force():
    signals = run(attempts(40, step=1.5))[0].signals
    assert signals.ratio == 4.0
    assert signals.fast          # one attempt every 1.5 s
    assert "SSH" in signals.sensitive
    assert signals.confirmed     # service accepted the connections
