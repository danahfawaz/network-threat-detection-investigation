"""End-to-end checks: every synthetic sample must give exactly its expected findings."""

import json

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import ARP, Ether

from pcap_investigation.config import DetectionConfig
from pcap_investigation.loader import EmptyCaptureError, UnsupportedFileError
from pcap_investigation.pipeline import analyze_capture
from tests.conftest import BASE_TIME, SAMPLES_DIR

EXPECTED = {k: v for k, v in json.loads((SAMPLES_DIR / "expected_detections.json").read_text()).items()
            if not k.startswith("_")}


def finding_keys(findings):
    return sorted((f.rule, f.source_label, f.subtype if f.rule in ("dns_anomaly", "connection_attempts") else None)
                  for f in findings)


def expected_keys(entries):
    return sorted((e["rule"], e["src"], e.get("subtype")) for e in entries)


@pytest.fixture(scope="module")
def results():
    return {name: analyze_capture(SAMPLES_DIR / name) for name in EXPECTED}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_sample_gives_exactly_the_expected_findings(results, name):
    assert finding_keys(results[name].findings) == expected_keys(EXPECTED[name])


def test_benign_capture_has_no_findings_and_zero_risk(results):
    result = results["benign_traffic.pcap"]
    assert result.findings == []
    assert result.overall_score == 0
    assert result.overall_severity == "None"
    assert "No suspicious activity detected" in result.overall_reasons[0]


def test_mixed_capture_is_ranked_and_explained(results):
    result = results["mixed_investigation.pcap"]
    assert len(result.findings) == 7
    assert [f.id for f in result.findings] == [f"F-{i:02d}" for i in range(1, 8)]
    times = [f.first_seen for f in result.findings]
    assert times == sorted(times)
    for finding in result.findings:
        assert finding.severity in ("Low", "Medium", "High", "Critical")
        assert finding.score == min(100, sum(f.points for f in finding.score_factors))
        assert finding.evidence and finding.what_happened and finding.why_flagged
        assert finding.recommended_steps and finding.sample_frames
    assert result.overall_score >= max(f.score for f in result.findings)
    assert result.overall_severity == "Critical"
    assert sum(result.severity_counts.values()) == 7


def test_capture_facts_are_recorded(results):
    result = results["port_scan.pcap"]
    assert result.capture.file_name == "port_scan.pcap"
    assert len(result.capture.sha256) == 64
    assert result.summary.total_packets == result.capture.packet_count == len(result.packets)
    assert result.summary.duration > 0


def test_disabling_a_rule_removes_its_findings():
    config = DetectionConfig(enabled_rules=("dns_anomaly",))
    result = analyze_capture(SAMPLES_DIR / "mixed_investigation.pcap", config=config)
    assert {f.rule for f in result.findings} == {"dns_anomaly"}


def test_threshold_change_changes_results():
    config = DetectionConfig()
    config.port_scan.min_targets = 50  # the sample scan touches 40 ports
    result = analyze_capture(SAMPLES_DIR / "port_scan.pcap", config=config)
    assert result.findings == []


# -- unusual input ------------------------------------------------------------

def test_capture_without_ip_traffic(write_pcap):
    packets = []
    for i in range(5):
        pkt = Ether() / ARP(op=1, psrc="192.168.1.20", hwsrc="02:00:00:00:00:20", pdst="192.168.1.1")
        pkt.time = BASE_TIME + i
        packets.append(pkt)
    result = analyze_capture(write_pcap(packets))
    assert result.findings == []
    assert any("no IPv4/IPv6 traffic" in note for note in result.notes)
    assert result.summary.unique_hosts == 0


def test_single_packet_capture(write_pcap):
    pkt = Ether() / IP(src="192.168.1.20", dst="192.168.1.1") / TCP(dport=80, flags="S")
    pkt.time = BASE_TIME
    result = analyze_capture(write_pcap([pkt]))
    assert result.summary.total_packets == 1
    assert result.summary.duration == 0
    assert result.findings == []
    assert any("very small" in note for note in result.notes)


def test_bad_inputs_raise_friendly_errors(tmp_path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    with pytest.raises(EmptyCaptureError):
        analyze_capture(empty)
    text = tmp_path / "notes.txt"
    text.write_text("hello")
    with pytest.raises(UnsupportedFileError):
        analyze_capture(text)
