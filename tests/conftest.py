"""Shared test helpers."""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

SAMPLES_DIR = ROOT / "samples"
BASE_TIME = 1767261600.0  # 2026-01-01 10:00:00 UTC (fictional capture time)


@pytest.fixture
def write_pcap(tmp_path):
    """Write a list of Scapy packets to a temporary .pcap and return its path."""
    from scapy.utils import wrpcap

    def _write(packets, name: str = "test.pcap") -> Path:
        path = tmp_path / name
        wrpcap(str(path), packets)
        return path

    return _write


def stamp(packets, start: float = BASE_TIME, step: float = 0.1):
    """Give packets increasing timestamps."""
    for index, packet in enumerate(packets):
        packet.time = start + index * step
    return packets
