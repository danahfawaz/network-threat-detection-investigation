from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from pcap_investigation.config import DnsConfig
from pcap_investigation.detections import dns_anomaly
from pcap_investigation.detections.dns_anomaly import (
    parent_domain,
    shannon_entropy,
    suspicious_name_reason,
)
from pcap_investigation.normalize import normalize_packets
from tests.conftest import BASE_TIME

CLIENT, RESOLVER = "192.168.1.25", "192.168.1.1"


def query(name, ts, client=CLIENT):
    pkt = Ether() / IP(src=client, dst=RESOLVER) / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname=name))
    pkt.time = ts
    return pkt


def answer(name, ts, rcode=0, client=CLIENT):
    pkt = Ether() / IP(src=RESOLVER, dst=client) / UDP(sport=53, dport=50000) / DNS(qr=1, rcode=rcode, qd=DNSQR(qname=name))
    pkt.time = ts
    return pkt


def subtypes(findings):
    return sorted(f.subtype for f in findings)


# -- helpers -----------------------------------------------------------------

def test_entropy_is_higher_for_random_text():
    assert shannon_entropy("aaaaaaaa") == 0
    assert shannon_entropy("k3j9x8q2m4v7z1p5w6r0") > 4.0
    assert shannon_entropy("portal") < 3.0


def test_parent_domain():
    assert parent_domain("a.b.tunnel.example") == "tunnel.example"
    assert parent_domain("example.com") == "example.com"


def test_suspicious_name_reason():
    cfg = DnsConfig()
    assert suspicious_name_reason("portal.example.com", cfg) is None
    assert suspicious_name_reason("www.google-docs.example.com", cfg) is None
    assert "label of 45" in suspicious_name_reason("a" * 45 + ".example.net", cfg)
    assert "random-looking" in suspicious_name_reason("k3j9x8q2m4v7z1p5w6r0q.example.net", cfg)
    assert suspicious_name_reason(None, cfg) is None


# -- check A: query flood ----------------------------------------------------

def test_query_flood_threshold():
    cfg = DnsConfig(query_flood_count=100, query_flood_window=60)
    below = [query("status.example.org", BASE_TIME + i * 0.3) for i in range(99)]
    at = [query("status.example.org", BASE_TIME + i * 0.3) for i in range(100)]
    assert dns_anomaly.detect(normalize_packets(below), cfg) == []
    findings = dns_anomaly.detect(normalize_packets(at), cfg)
    assert subtypes(findings) == ["Query flood"]
    assert findings[0].metrics["peak_queries"] == 100
    assert findings[0].signals.fast  # 100 queries in 30 s


def test_spread_out_queries_are_not_a_flood():
    packets = [query("status.example.org", BASE_TIME + i * 2.0) for i in range(150)]  # 30 per minute
    assert dns_anomaly.detect(normalize_packets(packets), DnsConfig()) == []


# -- check B: suspicious names -----------------------------------------------

def test_suspicious_names_threshold_and_evidence():
    names = [f"{i:02d}{'x7k2' * 11}.sync.tunnel.example" for i in range(5)]
    packets = [query(name, BASE_TIME + i) for i, name in enumerate(names)]
    findings = dns_anomaly.detect(normalize_packets(packets), DnsConfig(suspicious_name_min_count=5))
    assert subtypes(findings) == ["Suspicious domain names"]
    finding = findings[0]
    assert finding.metrics["top_parent_domain"] == "tunnel.example"
    assert finding.signals.confirmed  # all under one parent domain
    assert dns_anomaly.detect(normalize_packets(packets[:4]), DnsConfig(suspicious_name_min_count=5)) == []


def test_repeating_the_same_long_name_counts_once():
    packets = [query("a" * 50 + ".example.net", BASE_TIME + i) for i in range(10)]
    assert dns_anomaly.detect(normalize_packets(packets), DnsConfig()) == []


# -- check C: failed lookups ---------------------------------------------------

def test_failed_lookups_need_count_and_ratio():
    cfg = DnsConfig(nxdomain_min_count=20, nxdomain_min_ratio=0.5)
    failed = [answer(f"q{i}x.test", BASE_TIME + i, rcode=3) for i in range(20)]
    ok_many = [answer("portal.example.com", BASE_TIME + 100 + i) for i in range(30)]
    ok_few = ok_many[:10]

    findings = dns_anomaly.detect(normalize_packets(failed + ok_few), cfg)
    assert subtypes(findings) == ["Many failed lookups"]
    assert findings[0].src_ip == CLIENT
    assert findings[0].metrics["nxdomain"] == 20

    # 20 failures but only 40% of answers failed -> not flagged
    assert dns_anomaly.detect(normalize_packets(failed + ok_many), cfg) == []
    # 19 failures -> not flagged
    assert dns_anomaly.detect(normalize_packets(failed[:19]), cfg) == []


def test_normal_dns_is_clean():
    packets = []
    for i in range(40):
        packets += [query("portal.example.com", BASE_TIME + i * 5), answer("portal.example.com", BASE_TIME + i * 5 + 0.01)]
    assert dns_anomaly.detect(normalize_packets(packets), DnsConfig()) == []
