import hashlib

import pytest
from scapy.layers.inet import IP, TCP
from scapy.layers.l2 import Ether
from scapy.utils import PcapNgWriter

from pcap_investigation.loader import (
    CorruptCaptureError,
    EmptyCaptureError,
    UnsupportedFileError,
    detect_format,
    load_capture,
)
from tests.conftest import stamp


def _packets(count=5):
    return stamp([Ether() / IP(src="192.0.2.10", dst="198.51.100.20") / TCP(dport=80 + i, flags="S")
                  for i in range(count)])


def test_loads_valid_pcap_and_records_file_facts(write_pcap):
    path = write_pcap(_packets(5))
    info, packets = load_capture(path)
    assert len(packets) == 5
    assert info.packet_count == 5
    assert info.file_format == "pcap"
    assert info.file_size == path.stat().st_size
    assert info.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert info.warnings == []


def test_loads_pcapng(tmp_path):
    path = tmp_path / "capture.pcapng"
    writer = PcapNgWriter(str(path))
    for packet in _packets(3):
        writer.write(packet)
    writer.close()
    info, packets = load_capture(path)
    assert info.file_format == "pcapng"
    assert len(packets) == 3


def test_display_name_is_used_for_extension_check(write_pcap):
    path = write_pcap(_packets(2), name="upload.tmp")
    info, _ = load_capture(path, display_name="evidence.pcap")
    assert info.file_name == "evidence.pcap"


@pytest.mark.parametrize("name", ["notes.txt", "capture.json", "capture"])
def test_rejects_unsupported_extension(tmp_path, name):
    path = tmp_path / name
    path.write_bytes(b"anything")
    with pytest.raises(UnsupportedFileError, match="not a supported file type"):
        load_capture(path)


def test_rejects_text_file_renamed_to_pcap(tmp_path):
    path = tmp_path / "fake.pcap"
    path.write_text("this is plain text, not a capture")
    with pytest.raises(UnsupportedFileError, match="does not look like a PCAP"):
        load_capture(path)


def test_rejects_zero_byte_file(tmp_path):
    path = tmp_path / "empty.pcap"
    path.write_bytes(b"")
    with pytest.raises(EmptyCaptureError, match="empty"):
        load_capture(path)


def test_rejects_capture_with_header_but_no_packets(write_pcap, tmp_path):
    full = write_pcap(_packets(1)).read_bytes()
    path = tmp_path / "header_only.pcap"
    path.write_bytes(full[:24])  # global header only
    with pytest.raises(EmptyCaptureError, match="contains no packets"):
        load_capture(path)


def test_rejects_corrupted_header(tmp_path):
    path = tmp_path / "broken.pcap"
    path.write_bytes(bytes.fromhex("d4c3b2a1") + b"\x00" * 6)
    with pytest.raises(CorruptCaptureError):
        load_capture(path)


def test_truncated_capture_is_read_with_warning(write_pcap, tmp_path):
    full = write_pcap(_packets(5)).read_bytes()
    path = tmp_path / "truncated.pcap"
    path.write_bytes(full[:-10])
    info, packets = load_capture(path)
    assert len(packets) >= 4
    assert any("truncated" in w or "ended unexpectedly" in w for w in info.warnings)


def test_rejects_file_over_size_limit(write_pcap):
    path = write_pcap(_packets(2))
    with pytest.raises(UnsupportedFileError, match="larger than"):
        load_capture(path, max_file_mb=0)


def test_max_packets_limit_sets_truncated_flag(write_pcap):
    path = write_pcap(_packets(10))
    info, packets = load_capture(path, max_packets=4)
    assert len(packets) == 4
    assert info.truncated is True
    assert any("first 4 packets" in w for w in info.warnings)


def test_detect_format_magic_bytes():
    assert detect_format(bytes.fromhex("d4c3b2a1")) == "pcap"
    assert detect_format(bytes.fromhex("4d3cb2a1")) == "pcap"
    assert detect_format(bytes.fromhex("0a0d0d0a")) == "pcapng"
    assert detect_format(b"PK\x03\x04") is None
