"""Network Threat Detection & Digital Investigation - Streamlit dashboard.

Run from the project folder:
    streamlit run app/streamlit_app.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import streamlit as st  # noqa: E402

st.set_page_config(page_title="Network Threat Detection & Digital Investigation", page_icon=None,
                   layout="wide", initial_sidebar_state="expanded")

from app.components import empty_state, inject_css  # noqa: E402
from app.state import PAGES, init_state  # noqa: E402
from app.views import dashboard, hosts, overview, reports, settings, timeline  # noqa: E402

NAV_ICONS = {
    "Upload & Analyze": ":material/upload_file:",
    "Overview": ":material/bar_chart:",
    "Hosts & Traffic": ":material/lan:",
    "Threat Timeline": ":material/schedule:",
    "Reports": ":material/description:",
    "Settings": ":material/settings:",
}


def sidebar() -> None:
    with st.sidebar:
        st.markdown('<div class="nav-spacer"></div>', unsafe_allow_html=True)
        for name in PAGES:
            active = st.session_state.page == name
            if st.button(name, icon=NAV_ICONS[name], key=f"nav-{name}", width="stretch",
                         type="primary" if active else "tertiary"):
                st.session_state.page = name
                st.rerun()


def main() -> None:
    init_state()
    inject_css()
    sidebar()
    page = st.session_state.page
    result = st.session_state.result
    if page == "Upload & Analyze":
        dashboard.page()
    elif page == "Settings":
        settings.page()
    elif result is None:
        empty_state("No capture analyzed yet", "Open Upload & Analyze to choose and analyze a capture first.")
    elif page == "Overview":
        overview.page(result)
    elif page == "Hosts & Traffic":
        hosts.page(result)
    elif page == "Threat Timeline":
        timeline.page(result)
    elif page == "Reports":
        reports.page(result)


main()
