"""Data structures shared by the detections, scoring, dashboard and reports."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


@dataclass
class ScoringSignals:
    """Facts a detection hands to the risk scorer.

    ``ratio`` is how far the activity went past the rule's threshold
    (2.0 = twice the threshold). The other fields are a short reason when the
    factor applies, or None when it does not.
    """

    ratio: float
    scale_text: str
    fast: str | None = None
    sensitive: str | None = None
    persistent: str | None = None
    confirmed: str | None = None


@dataclass
class ScoreFactor:
    points: int
    label: str
    reason: str


@dataclass
class Finding:
    rule: str                     # e.g. "port_scan"
    title: str                    # e.g. "Port Scan"
    subtype: str | None           # e.g. "Query flood" (DNS has three checks)
    src_ip: str | None
    dst_ip: str | None            # one IP, or None when there are several targets
    targets: list[str]
    ports: list[int]
    protocol: str
    first_seen: float
    last_seen: float
    event_count: int
    event_label: str              # what was counted, e.g. "connection requests"
    summary: str                  # one line for the threats table
    what_happened: str            # plain-language description
    why_flagged: str              # which threshold was crossed
    evidence: list[str]
    recommended_steps: list[str]
    signals: ScoringSignals
    sample_frames: list[int] = field(default_factory=list)
    metrics: dict = field(default_factory=dict)
    src_mac: str | None = None    # used when no source IP is known (ARP)
    id: str = ""
    score: int = 0
    severity: str = ""
    score_factors: list[ScoreFactor] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(0.0, self.last_seen - self.first_seen)

    @property
    def source_label(self) -> str:
        return self.src_ip or self.src_mac or "Unknown"

    @property
    def destination_label(self) -> str:
        if self.dst_ip:
            return self.dst_ip
        if len(self.targets) > 1:
            return f"{len(self.targets)} hosts"
        if self.targets:
            return self.targets[0]
        return "-"

    def to_dict(self) -> dict:
        data = asdict(self)
        data["first_seen_utc"] = format_ts(self.first_seen, with_date=True)
        data["last_seen_utc"] = format_ts(self.last_seen, with_date=True)
        data["source"] = self.source_label
        data["destination"] = self.destination_label
        return data


SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def format_ts(ts: float, with_date: bool = False) -> str:
    moment = datetime.fromtimestamp(ts, tz=timezone.utc)
    if with_date:
        return moment.strftime("%Y-%m-%d %H:%M:%S UTC")
    return moment.strftime("%H:%M:%S")


def format_duration(seconds: float) -> str:
    seconds = float(seconds)
    if seconds < 1:
        return f"{seconds * 1000:.0f} ms"
    if seconds < 60:
        return f"{seconds:.1f} sec" if seconds < 10 else f"{seconds:.0f} sec"
    minutes, secs = divmod(int(round(seconds)), 60)
    if minutes < 60:
        return f"{minutes} min {secs} sec" if secs else f"{minutes} min"
    hours, minutes = divmod(minutes, 60)
    return f"{hours} h {minutes} min"


def format_bytes(count: float) -> str:
    count = float(count)
    for unit in ["B", "KB", "MB", "GB"]:
        if count < 1024 or unit == "GB":
            return f"{count:.0f} {unit}" if unit == "B" else f"{count:.1f} {unit}"
        count /= 1024
    return f"{count:.1f} GB"
