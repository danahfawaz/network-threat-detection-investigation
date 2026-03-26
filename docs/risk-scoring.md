# Risk Scoring

The goal is a score you can recompute by hand and explain in one sentence:
**"Base points for the type of behavior, plus points for how far it went past the threshold,
plus 10 for each aggravating factor, capped at 100."**

## Finding score

| Factor | Points | Example reason shown in the dashboard |
|---|---|---|
| **Base** | Burst 30 · DNS anomaly 35 · Port scan 40 · Repeated attempts 40 · Beaconing 45 · ARP spoofing 55 | "Port scanning is a common first step before an attack" |
| **Scale** | 1–2× threshold +5 · 2–4× +10 · 4–8× +15 · 8×+ +20 | "40 targets (2.7x the threshold of 15)" |
| **Fast** | +10 | "40 probes in 7.3 sec" |
| **Sensitive target** | +10 | "SSH (port 22) is a remote-login / admin service" |
| **Persistent** | +10 | "Kept going for 10 min 53 sec" |
| **Confirmed** | +10 | "4 open ports discovered (22, 80, 443, 3389)" |

Base points reflect how directly the behavior points to an attack. ARP spoofing has the
highest base because it actively redirects other hosts' traffic; a traffic burst has the
lowest because it is often legitimate.

What counts as *fast*, *sensitive*, *persistent* or *confirmed* is decided by each rule and
always comes with a written reason. Examples:

| Rule | Sensitive target | Confirmed |
|---|---|---|
| Port scan | admin ports probed, or 5+ hosts | open ports answered |
| DNS anomaly | - | 80 %+ of names under one domain / 80 %+ lookups failed |
| Repeated attempts | login or watchlist port | the service accepted the connections |
| Traffic burst | external destination | one-way transfer (sent ≥ 10× received) |
| Beaconing | external destination | timing varies by 5 % or less |
| ARP spoofing | the impersonated IP is the gateway | 3+ unsolicited ARP replies |

## Severity

Severity is taken directly from the score, so the two always agree:

| Score | Severity |
|---|---|
| 80–100 | Critical |
| 60–79 | High |
| 40–59 | Medium |
| 0–39 | Low |

## Overall capture risk

```
overall = highest finding score + 5 × (number of other High or Critical findings), max 100
```

A capture with no findings scores 0 and shows *"No suspicious activity detected by the
enabled rules."*

## Worked example

`repeated_connections.pcap`: 40 SSH connections from 203.0.113.45 in about one minute.

```
+40 Base              Repeated connection attempts can mean password guessing or a backdoor
+15 Scale             40 attempts (4.0x the threshold of 10)
+10 Fast              One attempt every 1.5 sec
+10 Sensitive target  SSH (port 22) is a remote-login / admin service
+10 Confirmed         The service accepted 40 connections, so the login attempts reached it
= 85 / 100  →  Critical
```
