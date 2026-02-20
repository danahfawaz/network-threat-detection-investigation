"""Rule-based, explainable risk scoring.

score = base points for the type of behavior
      + scale points (how far past the threshold)
      + 10 if it was fast
      + 10 if it hit a sensitive target
      + 10 if it was persistent
      + 10 if there is confirming evidence
capped at 100.

Severity comes straight from the score, so the two can never disagree:
0-39 Low, 40-59 Medium, 60-79 High, 80-100 Critical.
"""

from __future__ import annotations

from .models import Finding, ScoreFactor

BASE_POINTS = {
    "traffic_burst": 30,
    "dns_anomaly": 35,
    "port_scan": 40,
    "connection_attempts": 40,
    "beaconing": 45,
    "arp_spoofing": 55,
}

BASE_REASONS = {
    "traffic_burst": "A sudden traffic spike can mean data theft or a flood",
    "dns_anomaly": "Unusual DNS use can hide data transfer or malware activity",
    "port_scan": "Port scanning is a common first step before an attack",
    "connection_attempts": "Repeated connection attempts can mean password guessing or a backdoor",
    "beaconing": "Regular check-ins are typical of malware talking to its controller",
    "arp_spoofing": "ARP spoofing lets a device intercept other hosts' traffic",
}

FACTOR_POINTS = 10

SEVERITY_BANDS = [(80, "Critical"), (60, "High"), (40, "Medium"), (0, "Low")]


def scale_points(ratio: float) -> int:
    """1-2x the threshold: +5, 2-4x: +10, 4-8x: +15, 8x or more: +20."""
    if ratio >= 8:
        return 20
    if ratio >= 4:
        return 15
    if ratio >= 2:
        return 10
    return 5


def severity_for(score: int) -> str:
    for minimum, name in SEVERITY_BANDS:
        if score >= minimum:
            return name
    return "Low"


def score_finding(finding: Finding) -> Finding:
    """Fill score, severity and the factor list on a finding (in place)."""
    signals = finding.signals
    factors = [
        ScoreFactor(BASE_POINTS[finding.rule], "Base", BASE_REASONS[finding.rule]),
        ScoreFactor(scale_points(signals.ratio), "Scale", signals.scale_text),
    ]
    for label, reason in (("Fast", signals.fast), ("Sensitive target", signals.sensitive),
                          ("Persistent", signals.persistent), ("Confirmed", signals.confirmed)):
        if reason:
            factors.append(ScoreFactor(FACTOR_POINTS, label, reason))

    finding.score_factors = factors
    finding.score = min(100, sum(f.points for f in factors))
    finding.severity = severity_for(finding.score)
    return finding


def overall_score(findings: list[Finding]) -> tuple[int, str, list[str]]:
    """Capture-level risk: the worst finding, +5 for each other High/Critical one."""
    if not findings:
        return 0, "None", ["No suspicious activity detected by the enabled rules."]
    ranked = sorted(findings, key=lambda f: f.score, reverse=True)
    top = ranked[0]
    extra = [f for f in ranked[1:] if f.severity in ("High", "Critical")]
    score = min(100, top.score + 5 * len(extra))
    reasons = [f"Highest finding: {top.title} from {top.source_label} scored {top.score}"]
    if extra:
        reasons.append(f"+{5 * len(extra)} for {len(extra)} other high or critical finding"
                       f"{'s' if len(extra) != 1 else ''}")
    if score == 100 and top.score + 5 * len(extra) > 100:
        reasons.append("Capped at 100")
    return score, severity_for(score), reasons
