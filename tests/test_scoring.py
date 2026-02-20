import pytest

from pcap_investigation.models import Finding, ScoringSignals
from pcap_investigation.scoring import (
    BASE_POINTS,
    overall_score,
    scale_points,
    score_finding,
    severity_for,
)


def make_finding(rule="port_scan", ratio=1.0, **signal_reasons) -> Finding:
    return Finding(
        rule=rule, title="Test", subtype=None, src_ip="192.168.1.20", dst_ip="192.168.1.50",
        targets=["192.168.1.50"], ports=[22], protocol="TCP", first_seen=0.0, last_seen=1.0,
        event_count=1, event_label="events", summary="", what_happened="", why_flagged="",
        evidence=[], recommended_steps=[],
        signals=ScoringSignals(ratio=ratio, scale_text="scale", **signal_reasons),
    )


@pytest.mark.parametrize("ratio,points", [(1.0, 5), (1.99, 5), (2.0, 10), (3.9, 10),
                                          (4.0, 15), (7.9, 15), (8.0, 20), (50, 20)])
def test_scale_points_tiers(ratio, points):
    assert scale_points(ratio) == points


@pytest.mark.parametrize("score,severity", [(0, "Low"), (39, "Low"), (40, "Medium"), (59, "Medium"),
                                            (60, "High"), (79, "High"), (80, "Critical"), (100, "Critical")])
def test_severity_bands(score, severity):
    assert severity_for(score) == severity


def test_minimum_score_is_base_plus_scale():
    finding = score_finding(make_finding("port_scan", ratio=1.0))
    assert finding.score == BASE_POINTS["port_scan"] + 5
    assert [f.label for f in finding.score_factors] == ["Base", "Scale"]


def test_each_factor_adds_ten_and_is_explained():
    finding = score_finding(make_finding("port_scan", ratio=2.1, fast="31 probes in 8 sec",
                                         sensitive="SSH probed", confirmed="2 open ports"))
    assert finding.score == 40 + 10 + 10 + 10 + 10
    assert finding.severity == "Critical"
    reasons = {f.label: f.reason for f in finding.score_factors}
    assert reasons["Fast"] == "31 probes in 8 sec"
    assert "Persistent" not in reasons
    assert sum(f.points for f in finding.score_factors) == finding.score


def test_score_is_capped_at_100():
    finding = score_finding(make_finding("arp_spoofing", ratio=10, fast="x", sensitive="x",
                                         persistent="x", confirmed="x"))
    assert finding.score == 100


def test_overall_score_no_findings():
    score, severity, reasons = overall_score([])
    assert score == 0 and severity == "None"
    assert "No suspicious activity" in reasons[0]


def test_overall_score_uses_worst_finding_plus_extra_high_findings():
    findings = [
        score_finding(make_finding("port_scan", ratio=2.1, fast="x", sensitive="x", confirmed="x")),  # 80
        score_finding(make_finding("beaconing", ratio=1.5, sensitive="x")),                           # 60
        score_finding(make_finding("traffic_burst", ratio=1.0)),                                      # 35
    ]
    score, severity, reasons = overall_score(findings)
    assert score == 80 + 5  # +5 for the other High finding only
    assert severity == "Critical"
    assert "scored 80" in reasons[0]
