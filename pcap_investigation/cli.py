"""Command-line use without the dashboard.

    python -m pcap_investigation samples/mixed_investigation.pcap
    python -m pcap_investigation capture.pcapng --html report.html --csv alerts.csv --json evidence.json
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .loader import CaptureError
from .models import format_bytes, format_duration, format_ts
from .pipeline import analyze_capture
from .reporting.exports import alerts_csv, evidence_json
from .reporting.html_report import render_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m pcap_investigation",
                                     description="Analyze a PCAP/PCAPNG capture for suspicious network behavior.")
    parser.add_argument("capture", help="path to a .pcap or .pcapng file")
    parser.add_argument("--html", metavar="FILE", help="write the HTML investigation report")
    parser.add_argument("--csv", metavar="FILE", help="write alerts as CSV")
    parser.add_argument("--json", metavar="FILE", help="write evidence as JSON")
    args = parser.parse_args(argv)

    try:
        result = analyze_capture(args.capture)
    except CaptureError as error:
        print(f"Error: {error}", file=sys.stderr)
        return 2

    s = result.summary
    print(f"Capture : {result.capture.file_name}  (SHA-256 {result.capture.sha256[:16]}...)")
    print(f"Traffic : {s.total_packets:,} packets, {format_bytes(s.total_bytes)}, {s.unique_hosts} IP addresses, "
          f"{format_duration(s.duration)}")
    print(f"Risk    : {result.overall_score}/100 ({result.overall_severity})")
    for note in result.notes:
        print(f"Note    : {note}")
    print()
    if not result.findings:
        print("No suspicious activity detected by the enabled rules.")
    for f in result.findings:
        print(f"{f.id}  {format_ts(f.first_seen)}  {f.severity:<8} {f.score:>3}  {f.title:<29} "
              f"{f.source_label:<17} -> {f.destination_label:<15} {f.summary}")

    outputs = {args.html: render_report, args.csv: alerts_csv, args.json: evidence_json}
    for path, render in outputs.items():
        if path:
            Path(path).write_text(render(result), encoding="utf-8")
            print(f"\nWrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
