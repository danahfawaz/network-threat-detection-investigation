"""Dashboard tests with Streamlit's built-in AppTest (no browser needed).

They click through the real app: load a sample, analyze it, check what the
page shows, open every sidebar view and try bad input.
"""

import pytest
from streamlit.testing.v1 import AppTest

from app.state import PAGES, PendingFile
from tests.conftest import ROOT, SAMPLES_DIR

APP = str(ROOT / "app" / "streamlit_app.py")


def page_text(at: AppTest) -> str:
    return "\n".join(m.value for m in at.markdown)


def analyzed(sample: str) -> AppTest:
    at = AppTest.from_file(APP, default_timeout=90).run()
    at.button(key=f"sample-{sample}").click().run()
    assert at.session_state.pending.name == sample
    at.button(key="analyze").click().run()
    assert not at.exception
    return at


def test_start_page_shows_upload_and_empty_state():
    at = AppTest.from_file(APP, default_timeout=60).run()
    assert not at.exception
    text = page_text(at)
    assert "Upload PCAP File" in text
    assert "No capture analyzed yet" in text
    assert at.button(key="analyze").disabled


@pytest.fixture(scope="module")
def mixed_app():
    return analyzed("mixed_investigation.pcap")


def test_dashboard_shows_real_numbers(mixed_app):
    result = mixed_app.session_state.result
    text = page_text(mixed_app)
    assert f"{result.summary.total_packets:,}" in text
    assert "Threats Detected" in text and ">7<" in text
    assert f"{result.overall_score} <span" in text
    for finding in result.findings:
        assert finding.source_label in text
        assert mixed_app.button(key=f"view-{finding.id}")  # a View action per row


def test_dashboard_has_reference_sections(mixed_app):
    text = page_text(mixed_app)
    for title in ["Threats by Severity", "Threat Types Detected", "Top Source IPs", "Detected Threats",
                  "Traffic Timeline", "Top Destination Ports", "Investigation Actions",
                  "Export Investigation Report", "Export Alerts (CSV)", "Export Evidence (JSON)"]:
        assert title in text, title


def test_clean_capture_says_nothing_was_found():
    at = analyzed("benign_traffic.pcap")
    assert "No suspicious activity detected by the enabled rules." in page_text(at)
    assert at.session_state.result.findings == []


@pytest.mark.parametrize("page", PAGES[1:])
def test_every_sidebar_view_renders(mixed_app, page):
    mixed_app.button(key=f"nav-{page}").click().run()
    assert not mixed_app.exception
    assert mixed_app.session_state.page == page


def test_views_need_an_analysis_first():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.button(key="nav-Overview").click().run()
    assert "No capture analyzed yet" in page_text(at)


def test_bad_file_shows_a_friendly_error():
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.session_state["pending"] = PendingFile("notes.pcap", b"this is not a capture file")
    at.run()
    at.button(key="analyze").click().run()
    assert not at.exception
    assert at.session_state.result is None
    assert "does not look like a PCAP" in page_text(at)


def test_empty_capture_shows_a_friendly_error():
    header_only = (SAMPLES_DIR / "port_scan.pcap").read_bytes()[:24]
    at = AppTest.from_file(APP, default_timeout=60).run()
    at.session_state["pending"] = PendingFile("empty.pcap", header_only)
    at.run()
    at.button(key="analyze").click().run()
    assert "contains no packets" in page_text(at)


def test_settings_change_is_applied_on_reanalysis(mixed_app):
    mixed_app.button(key="nav-Settings").click().run()
    mixed_app.checkbox(key="rule-port_scan").uncheck()
    mixed_app.button[[b.label for b in mixed_app.button].index("Apply and re-analyze")].click().run()
    assert not mixed_app.exception
    rules = {f.rule for f in mixed_app.session_state.result.findings}
    assert "port_scan" not in rules and "dns_anomaly" in rules
