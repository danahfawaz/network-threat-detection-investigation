"""The full analysis in one call:

PCAP/PCAPNG -> load & validate -> normalize -> traffic summary
            -> detection rules -> risk scoring -> AnalysisResult
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

from . import __version__
from .config import DetectionConfig
from .detections import (
    arp_spoofing,
    beaconing,
    connection_attempts,
    dns_anomaly,
    port_scan,
    traffic_burst,
)
from .loader import CaptureInfo, load_capture
from .models import Finding
from .normalize import normalize_packets
from .scoring import overall_score, score_finding
from .traffic import TrafficSummary, summarize

RULE_TITLES = {
    "port_scan": "Port Scan",
    "dns_anomaly": "DNS Anomaly",
    "connection_attempts": "Repeated Connection Attempts",
    "traffic_burst": "Traffic Burst",
    "beaconing": "Beacon-Like Connections",
    "arp_spoofing": "ARP Spoofing",
}


@dataclass
class AnalysisResult:
    capture: CaptureInfo
    summary: TrafficSummary
    findings: list[Finding]
    overall_score: int
    overall_severity: str
    overall_reasons: list[str]
    packets: pd.DataFrame
    config: DetectionConfig
    analyzed_at: str
    tool_version: str = __version__
    notes: list[str] = field(default_factory=list)

    def finding(self, finding_id: str) -> Finding | None:
        return next((f for f in self.findings if f.id == finding_id), None)

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        for f in self.findings:
            counts[f.severity] += 1
        return counts


def run_detections(frame: pd.DataFrame, config: DetectionConfig) -> list[Finding]:
    rules = {
        "port_scan": lambda: port_scan.detect(frame, config.port_scan),
        "dns_anomaly": lambda: dns_anomaly.detect(frame, config.dns),
        "connection_attempts": lambda: connection_attempts.detect(frame, config.connection_attempts),
        "traffic_burst": lambda: traffic_burst.detect(frame, config.traffic_burst),
        "beaconing": lambda: beaconing.detect(frame, config.beaconing),
        "arp_spoofing": lambda: arp_spoofing.detect(frame, config.arp),
    }
    findings: list[Finding] = []
    for key, run in rules.items():
        if key in config.enabled_rules:
            findings.extend(run())
    for finding in findings:
        score_finding(finding)
    findings.sort(key=lambda f: (f.first_seen, -f.score))
    for number, finding in enumerate(findings, start=1):
        finding.id = f"F-{number:02d}"
    return findings


def analyze_capture(path: str | Path, display_name: str | None = None,
                    config: DetectionConfig | None = None) -> AnalysisResult:
    """Analyze one capture file. Raises loader.CaptureError for bad input."""
    config = config or DetectionConfig()
    info, packets = load_capture(path, display_name, max_packets=config.max_packets,
                                 max_file_mb=config.max_file_mb)
    frame = normalize_packets(packets)
    del packets
    summary = summarize(frame)

    notes = list(info.warnings)
    if summary.ip_packets == 0:
        notes.append("The capture contains no IPv4/IPv6 traffic, so only ARP-based checks could run.")
    if summary.total_packets < 20:
        notes.append("The capture is very small; behavior-based rules need more traffic to be reliable.")

    findings = run_detections(frame, config)
    score, severity, reasons = overall_score(findings)
    return AnalysisResult(
        capture=info,
        summary=summary,
        findings=findings,
        overall_score=score,
        overall_severity=severity,
        overall_reasons=reasons,
        packets=frame,
        config=config,
        analyzed_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        notes=notes,
    )
