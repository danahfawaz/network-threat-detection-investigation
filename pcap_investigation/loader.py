"""Load and validate PCAP / PCAPNG files.

The loader checks the file *before* Scapy parses it (extension, size, magic
bytes) so the dashboard can show a clear message instead of a stack trace.
"""

from __future__ import annotations

import hashlib
import logging
import struct
from dataclasses import dataclass, field
from pathlib import Path

SUPPORTED_EXTENSIONS = (".pcap", ".pcapng", ".cap")

# First four bytes of each supported format.
_PCAP_MAGICS = {
    bytes.fromhex("a1b2c3d4"),  # pcap, big-endian, microseconds
    bytes.fromhex("d4c3b2a1"),  # pcap, little-endian, microseconds
    bytes.fromhex("a1b23c4d"),  # pcap, big-endian, nanoseconds
    bytes.fromhex("4d3cb2a1"),  # pcap, little-endian, nanoseconds
}
_PCAPNG_MAGIC = bytes.fromhex("0a0d0d0a")


class CaptureError(Exception):
    """Base error. ``str(error)`` is a message that is safe to show to a user."""


class UnsupportedFileError(CaptureError):
    pass


class EmptyCaptureError(CaptureError):
    pass


class CorruptCaptureError(CaptureError):
    pass


@dataclass
class CaptureInfo:
    """Facts about the analyzed file (the 'what was analyzed?' question)."""

    file_name: str
    file_size: int
    sha256: str
    file_format: str
    packet_count: int = 0
    truncated: bool = False  # stopped early because of max_packets
    warnings: list[str] = field(default_factory=list)


def detect_format(header: bytes) -> str | None:
    """Return 'pcap', 'pcapng' or None from the first bytes of a file."""
    magic = header[:4]
    if magic in _PCAP_MAGICS:
        return "pcap"
    if magic == _PCAPNG_MAGIC:
        return "pcapng"
    return None


def validate_capture_file(path: str | Path, display_name: str | None = None,
                          max_file_mb: int = 200) -> CaptureInfo:
    """Check extension, size and format. Raises a CaptureError on problems."""
    path = Path(path)
    name = display_name or path.name

    if Path(name).suffix.lower() not in SUPPORTED_EXTENSIONS:
        raise UnsupportedFileError(
            f"'{name}' is not a supported file type. Please upload a .pcap or .pcapng capture."
        )
    if not path.exists():
        raise CaptureError(f"File '{name}' was not found.")

    size = path.stat().st_size
    if size == 0:
        raise EmptyCaptureError(f"'{name}' is empty (0 bytes).")
    if size > max_file_mb * 1024 * 1024:
        raise UnsupportedFileError(
            f"'{name}' is larger than the {max_file_mb} MB limit. "
            "Split the capture (for example with editcap) and analyze the parts."
        )

    with path.open("rb") as handle:
        header = handle.read(4)
    file_format = detect_format(header)
    if file_format is None:
        raise UnsupportedFileError(
            f"'{name}' does not look like a PCAP or PCAPNG capture "
            "(the file header is not a known capture format)."
        )

    return CaptureInfo(
        file_name=name,
        file_size=size,
        sha256=sha256_file(path),
        file_format=file_format,
    )


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _ScapyWarningCollector(logging.Handler):
    """Collects Scapy's parser warnings (e.g. 'packet has been truncated')."""

    def __init__(self) -> None:
        super().__init__(level=logging.WARNING)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def read_packets(path: str | Path, info: CaptureInfo, max_packets: int = 500_000) -> list:
    """Read packets with Scapy. Fills packet_count / truncated / warnings in ``info``."""
    from scapy.error import Scapy_Exception
    from scapy.utils import PcapReader

    collector = _ScapyWarningCollector()
    scapy_logger = logging.getLogger("scapy.runtime")
    # Route Scapy's warnings only to our collector while reading (no console noise).
    saved_level, saved_propagate = scapy_logger.level, scapy_logger.propagate
    scapy_logger.setLevel(logging.WARNING)
    scapy_logger.propagate = False
    scapy_logger.addHandler(collector)
    packets: list = []
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if len(packets) >= max_packets:
                    info.truncated = True
                    break
                packets.append(packet)
    except Scapy_Exception as exc:
        raise CorruptCaptureError(
            f"'{info.file_name}' could not be read as a capture file. It may be corrupted. ({exc})"
        ) from exc
    except (EOFError, OSError, ValueError, struct.error) as exc:
        if not packets:
            raise CorruptCaptureError(
                f"'{info.file_name}' appears to be corrupted and no packets could be read."
            ) from exc
        info.warnings.append(
            f"The capture ended unexpectedly after {len(packets)} packets; "
            "the remaining data could not be read."
        )
    finally:
        scapy_logger.removeHandler(collector)
        scapy_logger.setLevel(saved_level)
        scapy_logger.propagate = saved_propagate

    if any("truncated" in message for message in collector.messages):
        info.warnings.append(
            "Some packets in the capture are truncated (incomplete). "
            "They were analyzed with the data available."
        )
    if info.truncated:
        info.warnings.append(
            f"Only the first {max_packets:,} packets were analyzed (size limit)."
        )

    info.packet_count = len(packets)
    if not packets:
        raise EmptyCaptureError(f"'{info.file_name}' is a valid capture but contains no packets.")
    return packets


def load_capture(path: str | Path, display_name: str | None = None,
                 max_packets: int = 500_000, max_file_mb: int = 200) -> tuple[CaptureInfo, list]:
    """Validate and read a capture file. Returns (CaptureInfo, packets)."""
    info = validate_capture_file(path, display_name, max_file_mb=max_file_mb)
    packets = read_packets(path, info, max_packets=max_packets)
    return info, packets
