import csv
import io
import json

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether

from pcap_investigation.pipeline import analyze_capture
from pcap_investigation.reporting.evidence import involved_hosts, packet_rows, recommended_next_steps
from pcap_investigation.reporting.exports import CSV_COLUMNS, alerts_csv, evidence_json, safe_cell
from pcap_investigation.reporting.html_report import render_report
from tests.conftest import BASE_TIME, SAMPLES_DIR


@pytest.fixture(scope="module")
def mixed():
    return analyze_capture(SAMPLES_DIR / "mixed_investigation.pcap")


@pytest.fixture(scope="module")
def benign():
    return analyze_capture(SAMPLES_DIR / "benign_traffic.pcap")


# -- HTML report ----------------------------------------------------------------

def test_report_reflects_the_actual_analysis(mixed):
    html = render_report(mixed)
    assert mixed.capture.file_name in html
    assert mixed.capture.sha256 in html
    assert f"{mixed.summary.total_packets:,}" in html
    assert f"{mixed.overall_score}<" in html
    for finding in mixed.findings:
        assert finding.id in html and finding.title in html
        assert f"{finding.score}/100" in html
        assert finding.evidence[0] in html.replace("&#39;", "'")
    for section in ["Summary", "Capture details", "Traffic timeline", "Findings overview",
                    "Detailed findings", "Involved hosts", "Recommended investigation steps", "Method and limits"]:
        assert section in html


def test_report_for_clean_capture(benign):
    html = render_report(benign)
    assert "No suspicious activity detected by the enabled rules." in html
    assert "Detailed findings" not in html


def test_report_escapes_packet_content(write_pcap):
    """DNS names come from the network and must never be rendered as HTML."""
    packets = []
    for i in range(6):
        name = f"<script>alert({i})</script>{'a' * 40}.evil-example.test"
        pkt = Ether() / IP(src="192.168.1.25", dst="192.168.1.1") / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname=name))
        pkt.time = BASE_TIME + i
        packets.append(pkt)
    result = analyze_capture(write_pcap(packets))
    assert result.findings, "the long names should be flagged"
    html = render_report(result)
    assert "<script>alert" not in html
    assert "&lt;script&gt;alert" in html


# -- CSV ------------------------------------------------------------------------------

def test_csv_has_one_row_per_finding(mixed):
    rows = list(csv.DictReader(io.StringIO(alerts_csv(mixed))))
    assert list(rows[0].keys()) == CSV_COLUMNS
    assert len(rows) == len(mixed.findings)
    first = rows[0]
    finding = mixed.findings[0]
    assert first["id"] == finding.id and int(first["risk_score"]) == finding.score
    assert first["source"] == finding.source_label
    assert "Base +" in first["score_explanation"]


def test_csv_for_clean_capture_has_header_only(benign):
    rows = list(csv.reader(io.StringIO(alerts_csv(benign))))
    assert rows == [CSV_COLUMNS]


@pytest.mark.parametrize("value,expected", [("=HYPERLINK(1)", "'=HYPERLINK(1)"), ("+1", "'+1"),
                                            ("-2", "'-2"), ("@SUM", "'@SUM"), ("normal", "normal"),
                                            (None, ""), (42, "42")])
def test_csv_formula_injection_guard(value, expected):
    assert safe_cell(value) == expected


# -- JSON evidence ----------------------------------------------------------------------

def test_json_evidence_is_valid_and_complete(mixed):
    data = json.loads(evidence_json(mixed))
    assert data["capture"]["sha256"] == mixed.capture.sha256
    assert data["overall_risk"]["score"] == mixed.overall_score
    assert len(data["findings"]) == len(mixed.findings)
    finding = data["findings"][0]
    assert finding["sample_packets"] and finding["score_explanation"]
    assert finding["first_seen_utc"].endswith("UTC")
    assert data["detection_config"]["port_scan"]["min_targets"] == 15


# -- shared evidence helpers ---------------------------------------------------------------

def test_packet_rows_are_readable(mixed):
    scan = next(f for f in mixed.findings if f.rule == "port_scan")
    rows = packet_rows(mixed.packets, scan.sample_frames)
    assert len(rows) == len(scan.sample_frames)
    assert rows[0]["source"] == "192.168.10.66" and rows[0]["flags"] == "S"


def test_finding_packet_mask_selects_the_right_packets(mixed):
    from pcap_investigation.reporting.evidence import finding_packet_mask

    scan = next(f for f in mixed.findings if f.rule == "port_scan")
    scan_packets = mixed.packets[finding_packet_mask(mixed.packets, scan)]
    # the 40 SYN probes + the scanner's reset after each of the 4 open ports
    assert len(scan_packets) == scan.event_count + len(scan.metrics["open_ports"])
    assert set(scan_packets["src_ip"]) == {"192.168.10.66"}

    arp = next(f for f in mixed.findings if f.rule == "arp_spoofing")
    arp_packets = mixed.packets[finding_packet_mask(mixed.packets, arp)]
    assert len(arp_packets) == arp.event_count
    assert set(arp_packets["protocol"]) == {"ARP"}


def test_involved_hosts_and_next_steps(mixed):
    hosts = {h["host"]: h for h in involved_hosts(mixed)}
    assert hosts["192.168.10.66"]["role"] == "Source"
    assert hosts["192.168.10.66"]["highest_severity"] == "Critical"
    assert hosts["192.168.10.20"]["role"] == "Source & Target"  # burst source, ARP victim
    steps = recommended_next_steps(mixed)
    assert 0 < len(steps) <= 6
    assert steps[0].startswith("[F-")
