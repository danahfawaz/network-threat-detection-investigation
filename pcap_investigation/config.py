"""Detection thresholds and analysis limits.

Every number a detection rule depends on lives here, so the rules stay easy to
explain and easy to tune. The dashboard's Settings view edits a copy of
``DetectionConfig`` for the current session only.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict


@dataclass
class PortScanConfig:
    # One source must send connection requests (SYN without ACK) to at least
    # this many different (host, port) targets ...
    min_targets: int = 15
    # ... inside this many seconds.
    window_seconds: float = 60.0


@dataclass
class DnsConfig:
    # Check A - query flood
    query_flood_count: int = 100
    query_flood_window: float = 60.0
    # Check B - long or random-looking names (possible tunnelling / DGA)
    long_label_length: int = 40
    entropy_threshold: float = 3.8
    entropy_min_length: int = 20
    suspicious_name_min_count: int = 5
    # Check C - many failed lookups (NXDOMAIN)
    nxdomain_min_count: int = 20
    nxdomain_min_ratio: float = 0.5


@dataclass
class ConnectionAttemptConfig:
    min_attempts: int = 10
    window_seconds: float = 120.0
    # Any port: flag when this share of attempts failed (RST or no answer).
    failure_ratio: float = 0.7
    # Remote-login / admin services where repeated connections suggest
    # password guessing.
    login_ports: tuple[int, ...] = (21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900)
    # Ports often used by backdoors / attack tooling.
    watchlist_ports: tuple[int, ...] = (1337, 4444, 5555, 6666, 6667, 31337)
    watchlist_min_attempts: int = 3


@dataclass
class TrafficBurstConfig:
    window_seconds: float = 10.0
    min_packets: int = 1000
    # The burst must also be this many times the host's average rate.
    min_ratio: float = 10.0


@dataclass
class BeaconConfig:
    min_connections: int = 8
    min_interval: float = 10.0
    max_interval: float = 3600.0
    # A gap is "regular" when it is within +/- this fraction of the median gap.
    tolerance: float = 0.15
    # At least this share of gaps must be regular.
    min_regular_fraction: float = 0.8
    # UDP has no handshake: packets more than this many seconds apart start a
    # new "connection".
    udp_session_gap: float = 1.0


@dataclass
class ArpConfig:
    # One IP address answered for by at least this many MAC addresses.
    min_macs: int = 2


RULE_KEYS = (
    "port_scan",
    "dns_anomaly",
    "connection_attempts",
    "traffic_burst",
    "beaconing",
    "arp_spoofing",
)


@dataclass
class DetectionConfig:
    port_scan: PortScanConfig = field(default_factory=PortScanConfig)
    dns: DnsConfig = field(default_factory=DnsConfig)
    connection_attempts: ConnectionAttemptConfig = field(default_factory=ConnectionAttemptConfig)
    traffic_burst: TrafficBurstConfig = field(default_factory=TrafficBurstConfig)
    beaconing: BeaconConfig = field(default_factory=BeaconConfig)
    arp: ArpConfig = field(default_factory=ArpConfig)
    enabled_rules: tuple[str, ...] = RULE_KEYS
    # Safety limits for very large captures.
    max_packets: int = 500_000
    max_file_mb: int = 200

    def to_dict(self) -> dict:
        return asdict(self)
