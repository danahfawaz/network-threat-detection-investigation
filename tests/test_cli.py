from pcap_investigation.cli import main
from tests.conftest import SAMPLES_DIR


def test_cli_prints_findings_and_writes_outputs(tmp_path, capsys):
    html, csv_path = tmp_path / "report.html", tmp_path / "alerts.csv"
    code = main([str(SAMPLES_DIR / "port_scan.pcap"), "--html", str(html), "--csv", str(csv_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Port Scan" in out and "192.168.10.66" in out
    assert html.read_text().startswith("<!DOCTYPE html>")
    assert csv_path.read_text().count("\n") == 2  # header + one finding


def test_cli_clean_capture(capsys):
    assert main([str(SAMPLES_DIR / "benign_traffic.pcap")]) == 0
    assert "No suspicious activity detected" in capsys.readouterr().out


def test_cli_reports_bad_input(tmp_path, capsys):
    bad = tmp_path / "notes.txt"
    bad.write_text("x")
    assert main([str(bad)]) == 2
    assert "not a supported file type" in capsys.readouterr().err
