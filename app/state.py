"""Session state and the analysis call used by the dashboard."""

from __future__ import annotations

import copy
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path

import streamlit as st

from pcap_investigation.config import DetectionConfig
from pcap_investigation.loader import CaptureError, detect_format
from pcap_investigation.pipeline import analyze_capture

SAMPLES_DIR = Path(__file__).resolve().parents[1] / "samples"

PAGES = ["Upload & Analyze", "Overview", "Hosts & Traffic", "Threat Timeline", "Reports", "Settings"]


@dataclass
class PendingFile:
    """A capture chosen by the user but not analyzed yet."""

    name: str
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)

    @property
    def looks_like_capture(self) -> bool:
        return detect_format(self.data[:4]) is not None


def init_state() -> None:
    defaults = {
        "page": PAGES[0],
        "result": None,
        "error": None,
        "pending": None,
        "uploader_version": 0,
        "config": DetectionConfig(),
        "table_sort": "Sort by time",
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def sample_files() -> list[Path]:
    return sorted(SAMPLES_DIR.glob("*.pcap"))


def clear_pending() -> None:
    st.session_state.pending = None
    st.session_state.uploader_version += 1  # gives the uploader a new key = empty


def analyze_pending() -> None:
    """Analyze the pending file and store the result (or a friendly error)."""
    pending: PendingFile | None = st.session_state.pending
    if pending is None:
        return
    st.session_state.error = None
    suffix = Path(pending.name).suffix or ".pcap"
    handle, temp_path = tempfile.mkstemp(suffix=suffix)
    try:
        with os.fdopen(handle, "wb") as temp:
            temp.write(pending.data)
        config = copy.deepcopy(st.session_state.config)
        st.session_state.result = analyze_capture(temp_path, display_name=pending.name, config=config)
    except CaptureError as error:
        st.session_state.result = None
        st.session_state.error = str(error)
    except Exception as error:  # unexpected: never show a stack trace to the user
        st.session_state.result = None
        st.session_state.error = (f"The capture could not be analyzed ({type(error).__name__}). "
                                  "It may be damaged or use an unusual link type.")
    finally:
        try:
            os.remove(temp_path)  # do not keep uploaded captures on disk
        except OSError:
            pass


def reanalyze_with_config() -> bool:
    """Re-run the last analyzed capture with the current settings, if possible."""
    if st.session_state.pending is not None:
        analyze_pending()
        return True
    return False
