"""CSV alert export and JSON evidence export."""

from __future__ import annotations

import csv
import io
import json

from ..models import format_ts
from .evidence import _clean, packet_rows, score_explanation

CSV_COLUMNS = [
    "id", "first_seen_utc", "last_seen_utc", "detection", "subtype", "severity", "risk_score",
    "source", "destination", "ports", "protocol", "event_count", "event_type", "summary",
    "why_flagged", "evidence", "score_explanation",
]

# Spreadsheet programs run cells that start with these characters as formulas.
# Packet data (e.g. DNS names) is attacker-controlled, so neutralize them.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def safe_cell(value) -> str:
    text = "" if value is None else str(value)
    if text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def alerts_csv(result) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_COLUMNS)
    for f in result.findings:
        writer.writerow([safe_cell(v) for v in [
            f.id, format_ts(f.first_seen, with_date=True), format_ts(f.last_seen, with_date=True),
            f.title, f.subtype or "", f.severity, f.score, f.source_label, f.destination_label,
            " ".join(str(p) for p in f.ports), f.protocol, f.event_count, f.event_label, f.summary,
            f.why_flagged, " | ".join(f.evidence),
            " | ".join(f"{x.label} +{x.points}: {x.reason}" for x in f.score_factors),
        ]])
    return buffer.getvalue()


def _jsonable(value):
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    return _clean(value)


def evidence_json(result) -> str:
    capture = result.capture
    summary = result.summary
    findings = []
    for f in result.findings:
        data = f.to_dict()
        data["score_explanation"] = score_explanation(f)
        data["sample_packets"] = packet_rows(result.packets, f.sample_frames)
        findings.append(data)
    document = {
        "tool": {"name": "Network Threat Detection & Digital Investigation", "version": result.tool_version},
        "analyzed_at": result.analyzed_at,
        "capture": {
            "file_name": capture.file_name, "file_size_bytes": capture.file_size,
            "sha256": capture.sha256, "format": capture.file_format,
            "packets_analyzed": capture.packet_count, "truncated": capture.truncated,
            "first_packet_utc": format_ts(summary.first_ts, with_date=True),
            "last_packet_utc": format_ts(summary.last_ts, with_date=True),
            "duration_seconds": round(summary.duration, 3),
        },
        "traffic_summary": {
            "total_packets": summary.total_packets, "total_bytes": summary.total_bytes,
            "unique_hosts": summary.unique_hosts, "internal_hosts": summary.internal_hosts,
            "external_hosts": summary.external_hosts, "protocols": summary.protocol_counts,
            "top_destination_ports": summary.top_dst_ports,
        },
        "overall_risk": {"score": result.overall_score, "severity": result.overall_severity,
                         "explanation": result.overall_reasons},
        "notes": result.notes,
        "detection_config": result.config.to_dict(),
        "findings": findings,
    }
    return json.dumps(_jsonable(document), indent=2)
