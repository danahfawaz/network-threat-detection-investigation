# Synthetic sample captures

These PCAP files are **synthetic**. They were built packet by packet by
[`scripts/generate_samples.py`](../scripts/generate_samples.py) and contain no
real traffic.

| File | What it contains | Expected findings |
|---|---|---|
| `benign_traffic.pcap` | Normal office traffic only (web, DNS, file share, SSH, ARP) | None |
| `port_scan.pcap` | A rogue internal host SYN-scans 40 ports on a web server | Port Scan |
| `dns_anomaly.pcap` | Tunnelling-style DNS names, many failed lookups, a query flood (three hosts) | 3 x DNS Anomaly |
| `repeated_connections.pcap` | SSH password-guessing pattern + repeated attempts to port 4444 | 2 x Repeated Connection Attempts |
| `traffic_burst.pcap` | A quiet workstation uploads 1,800 packets in 6 seconds | Traffic Burst |
| `beaconing.pcap` | A workstation connects to one external server every ~60 seconds | Beacon-Like Connections |
| `arp_spoofing.pcap` | A rogue device claims the gateway's IP address | ARP Spoofing |
| `mixed_investigation.pcap` | **Demo file:** normal traffic plus all of the above | 7 findings |

The exact expected results are in [`expected_detections.json`](expected_detections.json),
and the automated tests check every file against it.

## Why these files are safe to publish

- Internal hosts use the private range `192.168.10.0/24`.
- "Internet" hosts use documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`) that are reserved for examples and never routed.
- Domain names use reserved names (`example.com/.net/.org`, `.test`, `.invalid`, `.example`).
- MAC addresses are locally administered (`02:00:...`).
- Payloads are filler bytes (`SYNTHETIC-TEST-DATA-`). No real content, no credentials.

## Regenerate

```bash
python scripts/generate_samples.py
```

A fixed random seed makes the output identical on every run.
