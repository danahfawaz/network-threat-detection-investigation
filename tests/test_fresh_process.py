"""Run the analysis in a brand-new Python process.

The other test files import Scapy layers themselves, which could hide a bug
where the application forgets to load them (packets would stay raw bytes).
"""

import json
import subprocess
import sys

from tests.conftest import ROOT, SAMPLES_DIR

SCRIPT = """
import json, sys
from pcap_investigation.pipeline import analyze_capture
result = analyze_capture(sys.argv[1])
print(json.dumps({"hosts": result.summary.unique_hosts,
                  "rules": sorted({f.rule for f in result.findings})}))
"""


def test_analysis_works_without_preloaded_scapy_layers():
    output = subprocess.run(
        [sys.executable, "-c", SCRIPT, str(SAMPLES_DIR / "mixed_investigation.pcap")],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    data = json.loads(output.strip().splitlines()[-1])
    assert data["hosts"] > 0
    assert data["rules"] == ["arp_spoofing", "beaconing", "connection_attempts", "dns_anomaly",
                             "port_scan", "traffic_burst"]
