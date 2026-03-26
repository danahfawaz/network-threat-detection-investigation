# Detection Rules

Six rules, each small enough to explain in a minute. Default thresholds are in
[`pcap_investigation/config.py`](../pcap_investigation/config.py).

---

## 1. Port Scan / SYN Scan

**Idea:** before attacking, tools like Nmap send connection requests (TCP SYN) to many ports to
see which services answer.

**Logic:** take every SYN packet without ACK. For each source, slide a time window over its
SYNs and count how many *different* (destination, port) pairs it contacted. This catches
both scanning many ports on one host and sweeping one port across many hosts.

| Setting | Default |
|---|---|
| `min_targets` | 15 different host/port pairs |
| `window_seconds` | 60 |

**Evidence:** probes and rate, ports and hosts, answers (SYN-ACK = open, RST = closed, none),
open ports found, list of probed ports.

**Not flagged:** a client opening many normal connections to the *same* service.

---

## 2. DNS Anomalies

Three checks, one finding per host and check.

| Check | What it means | Default |
|---|---|---|
| **Query flood** | Very many queries from one host in a short time | 100+ queries in 60 s |
| **Suspicious domain names** | Labels of 40+ characters, or a long random-looking subdomain (Shannon entropy ≥ 3.8 over 20+ characters). Data can be hidden inside DNS names ("DNS tunnelling") | 5+ distinct names |
| **Many failed lookups** | Lots of NXDOMAIN ("does not exist") answers, typical of malware trying generated domains | 20+ NXDOMAIN and ≥ 50 % of answers |

**Evidence:** counts and rates, example names, the shared parent domain, failure ratio,
DNS servers used.

---

## 3. Repeated Suspicious Connection Attempts

**Idea:** count new TCP connections per (source, destination, port). Retransmitted SYNs (same
source port) count once.

| Pattern | Flagged when |
|---|---|
| **Possible password guessing** | 10+ attempts within 120 s to a remote-login / admin port (21, 22, 23, 25, 110, 143, 445, 1433, 3306, 3389, 5432, 5900) |
| **Repeated failed connections** | 10+ attempts within 120 s to any port and ≥ 70 % refused or unanswered |
| **Connections to a watchlist port** | 3+ attempts to a port commonly used by backdoors (1337, 4444, 5555, 6666, 6667, 31337) |

**Evidence:** attempts and spacing, outcome (accepted / refused / no answer), typical connection
length, whether the source is external.

**Not flagged:** many successful HTTPS connections (normal browsing).

---

## 4. Traffic Burst / High-Volume Traffic

**Idea:** a host suddenly sends far more than usual: a large upload, a flood, or a backup.

**Logic:** for each host, find its busiest window. Flag it when the window has at least
`min_packets` packets **and** is at least `min_ratio` times the host's normal rate (its rate
during the rest of the capture).

| Setting | Default |
|---|---|
| `window_seconds` | 10 |
| `min_packets` | 1,000 |
| `min_ratio` | 10× normal |

The capture must be long enough to know what "normal" is (at least 3 windows).

**Evidence:** packets and bytes, rate, normal rate, main destination, data received back
(one-way transfers are highlighted).

---

## 5. Periodic / Beacon-Like Connections

**Idea:** malware often checks in with its control server on a timer. People do not browse on
a timer.

**Logic:** list when each new connection started per (source, destination, port): TCP SYNs,
and UDP packets after a quiet gap. Measure the gaps.

| Setting | Default |
|---|---|
| `min_connections` | 8 |
| `min_interval` / `max_interval` | 10 s / 3600 s (typical gap) |
| `tolerance` | ±15 % of the typical gap |
| `min_regular_fraction` | 80 % of gaps must be regular |
| `ignore_ports` | 53, 123, 5353, 1900 (periodic by design) |

**Evidence:** connections, typical gap with shortest/longest, regularity, data per connection,
whether the destination is external.

---

## 6. ARP Spoofing

**Idea:** ARP maps IP addresses to MAC addresses on a LAN. If a second device claims an IP that
belongs to someone else (often the gateway), traffic can be redirected through it
(man-in-the-middle).

**Logic:** from ARP packets, collect which MAC addresses announced each IP. Flag an IP with
`min_macs` (default 2) or more MAC addresses.

**Evidence:** original vs. new MAC, unsolicited replies (sent when no one asked), hosts that
received them, the IP address the new MAC normally uses, and whether the impersonated IP is
the default gateway (worked out from which MAC carries internet-bound traffic).

**Possible benign causes** (mentioned in the finding): replaced network card, router failover.
