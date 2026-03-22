"""Colors used by the dashboard (CSS, charts and badges share these)."""

BG = "#151112"
PANEL = "#21191B"
PANEL_2 = "#261D1F"
BORDER = "#33272A"
GRID = "#2E2427"
ROSE = "#E77C8E"
DUSTY_ROSE = "#B96D78"
BURGUNDY = "#6F3540"
TEXT = "#EEE8E6"
MUTED = "#AFA4A1"
FAINT = "#7D7270"
NORMAL_TRAFFIC = "#4B3E41"

# Severity = status color (always shown with its label).
SEVERITY = {
    "Critical": "#E0566F",
    "High": "#E98A9B",
    "Medium": "#E3A46C",
    "Low": "#8F8284",
}
# Badge backgrounds (darker, with light text) - like the reference table.
SEVERITY_BADGE = {
    "Critical": "#9B2A3E",
    "High": "#7C2F3C",
    "Medium": "#7A5530",
    "Low": "#4E4446",
    "None": "#3F4A41",
}

# One fixed color per detection type (identity). Checked with a colorblind /
# contrast validator against the panel color; every chart also names the type.
RULE_COLORS = {
    "port_scan": "#D66077",
    "dns_anomaly": "#009A9B",
    "connection_attempts": "#C87F2C",
    "traffic_burst": "#8766BB",
    "beaconing": "#A4932E",
    "arp_spoofing": "#B95A93",
}

RULE_ORDER = list(RULE_COLORS)
