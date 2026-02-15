"""Generate the synthetic PCAP samples in samples/.

All traffic is fictional and built packet by packet with Scapy:
  * internal hosts use the private range 192.168.10.0/24
  * "internet" hosts use documentation ranges (192.0.2.0/24, 198.51.100.0/24,
    203.0.113.0/24) that are never routed on the real internet
  * domain names use reserved names (example.com/.net/.org, .test, .invalid, .example)
  * MAC addresses are locally administered (02:00:...)
  * payloads are filler bytes - no real content, no credentials

A fixed random seed makes every run produce identical files, so the expected
results in samples/expected_detections.json stay valid.

Usage:
    python scripts/generate_samples.py            # writes into samples/
    python scripts/generate_samples.py --out DIR
"""

from __future__ import annotations

import argparse
import json
import random
import string
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

BASE_TIME = 1771059600.0  # 2026-02-14 09:00:00 UTC (fictional)
GATEWAY = "192.168.10.1"   # router + local DNS resolver
GATEWAY_MAC = "02:00:00:0a:00:01"
WORKSTATIONS = ["192.168.10.20", "192.168.10.21", "192.168.10.25", "192.168.10.35"]
FILE_SERVER = "192.168.10.30"
SSH_SERVER = "192.168.10.40"
WEB_SERVER = "192.168.10.50"
ROGUE_HOST = "192.168.10.66"
ROGUE_MAC = "02:00:00:0a:00:42"  # same MAC the rogue host uses for its IP traffic
EXTERNAL_WEB = ["198.51.100.10", "198.51.100.11", "192.0.2.80"]
NORMAL_DOMAINS = ["portal.example.com", "mail.example.com", "cdn.example.net",
                  "docs.example.org", "updates.example.net", "intranet.corp.test"]
FILLER = b"SYNTHETIC-TEST-DATA-"


def mac_for(ip: str) -> str:
    """Internal hosts get their own MAC; everything else is reached via the gateway."""
    if ip.startswith("192.168.10."):
        last = int(ip.rsplit(".", 1)[1])
        return "02:00:00:0a:00:%02x" % last
    return GATEWAY_MAC


def payload(size: int) -> bytes:
    return (FILLER * (size // len(FILLER) + 1))[:size]


class Capture:
    """Collects timestamped packets and writes them sorted by time."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)
        self.packets = []

    def add(self, ts: float, packet) -> None:
        packet.time = ts
        self.packets.append(packet)

    def frame(self, src: str, dst: str):
        return Ether(src=mac_for(src), dst=mac_for(dst)) / IP(src=src, dst=dst)

    def ephemeral_port(self) -> int:
        return self.rng.randint(49152, 65000)

    # -- building blocks -------------------------------------------------
    def tcp_session(self, start: float, client: str, server: str, dport: int,
                    data_packets: int = 4, size: int = 400, rtt: float = 0.02) -> float:
        """Full TCP connection: handshake, a little data, FIN. Returns end time."""
        sport = self.ephemeral_port()
        cseq, sseq = self.rng.randint(1, 2**31), self.rng.randint(1, 2**31)
        t = start
        self.add(t, self.frame(client, server) / TCP(sport=sport, dport=dport, flags="S", seq=cseq))
        t += rtt
        self.add(t, self.frame(server, client) / TCP(sport=dport, dport=sport, flags="SA", seq=sseq, ack=cseq + 1))
        t += rtt / 2
        self.add(t, self.frame(client, server) / TCP(sport=sport, dport=dport, flags="A", seq=cseq + 1, ack=sseq + 1))
        for i in range(data_packets):
            t += self.rng.uniform(0.005, 0.05)
            if i % 2 == 0:
                pkt = self.frame(client, server) / TCP(sport=sport, dport=dport, flags="PA") / Raw(payload(size // 4))
            else:
                pkt = self.frame(server, client) / TCP(sport=dport, dport=sport, flags="PA") / Raw(payload(size))
            self.add(t, pkt)
        t += rtt
        self.add(t, self.frame(client, server) / TCP(sport=sport, dport=dport, flags="FA"))
        t += rtt
        self.add(t, self.frame(server, client) / TCP(sport=dport, dport=sport, flags="FA"))
        t += rtt / 2
        self.add(t, self.frame(client, server) / TCP(sport=sport, dport=dport, flags="A"))
        return t

    def syn_probe(self, ts: float, src: str, dst: str, dport: int, answer: str) -> None:
        """One connection request. answer: 'open' (SYN-ACK), 'closed' (RST) or 'none'."""
        sport = self.ephemeral_port()
        self.add(ts, self.frame(src, dst) / TCP(sport=sport, dport=dport, flags="S"))
        if answer == "open":
            self.add(ts + 0.002, self.frame(dst, src) / TCP(sport=dport, dport=sport, flags="SA"))
            self.add(ts + 0.003, self.frame(src, dst) / TCP(sport=sport, dport=dport, flags="R"))
        elif answer == "closed":
            self.add(ts + 0.002, self.frame(dst, src) / TCP(sport=dport, dport=sport, flags="RA"))

    def dns_lookup(self, ts: float, client: str, qname: str, rcode: int = 0,
                   answer_ip: str = "198.51.100.10") -> None:
        txid = self.rng.randint(1, 65535)
        sport = self.ephemeral_port()
        query = self.frame(client, GATEWAY) / UDP(sport=sport, dport=53) / DNS(id=txid, rd=1, qd=DNSQR(qname=qname))
        self.add(ts, query)
        if rcode == 0:
            reply = DNS(id=txid, qr=1, rd=1, ra=1, rcode=0, qd=DNSQR(qname=qname),
                        an=DNSRR(rrname=qname, ttl=300, rdata=answer_ip))
        else:
            reply = DNS(id=txid, qr=1, rd=1, ra=1, rcode=rcode, qd=DNSQR(qname=qname))
        self.add(ts + self.rng.uniform(0.005, 0.03),
                 self.frame(GATEWAY, client) / UDP(sport=53, dport=sport) / reply)

    def arp_exchange(self, ts: float, asker: str, target: str, target_mac: str) -> None:
        self.add(ts, Ether(src=mac_for(asker), dst="ff:ff:ff:ff:ff:ff") /
                 ARP(op=1, psrc=asker, hwsrc=mac_for(asker), pdst=target))
        self.add(ts + 0.001, Ether(src=target_mac, dst=mac_for(asker)) /
                 ARP(op=2, psrc=target, hwsrc=target_mac, pdst=asker, hwdst=mac_for(asker)))

    def write(self, path: Path) -> int:
        self.packets.sort(key=lambda p: float(p.time))
        wrpcap(str(path), self.packets)
        return len(self.packets)


# -- scenarios ---------------------------------------------------------------

def add_background(cap: Capture, start: float, duration: float) -> None:
    """Normal office traffic: web sessions, DNS lookups, file share, ARP.

    Gaps are random (exponential), so no flow looks periodic, and every
    connection succeeds, so nothing should be flagged.
    """
    rng = cap.rng
    end = start + duration
    for host in WORKSTATIONS:
        t = start + rng.uniform(0, 5)
        while t < end:
            domain = rng.choice(NORMAL_DOMAINS)
            server = rng.choice(EXTERNAL_WEB)
            cap.dns_lookup(t, host, domain, answer_ip=server)
            t = cap.tcp_session(t + 0.05, host, server, rng.choice([443, 443, 443, 80]),
                                data_packets=rng.randint(4, 12), size=rng.randint(300, 1200))
            t += rng.expovariate(1 / 12.0)
        # occasional mistyped name -> a couple of normal NXDOMAIN answers
        cap.dns_lookup(start + rng.uniform(0, duration), host, "pritner.corp.test", rcode=3)

    # file share access and an admin SSH session (normal)
    t = start + 20
    while t < end:
        cap.tcp_session(t, rng.choice(WORKSTATIONS), FILE_SERVER, 445, data_packets=rng.randint(6, 16), size=1200)
        t += rng.expovariate(1 / 40.0) + 5
    cap.tcp_session(start + 30, "192.168.10.21", SSH_SERVER, 22, data_packets=20, size=200)

    # ARP: hosts resolving the gateway (always the real gateway MAC)
    t = start + 1
    while t < end:
        cap.arp_exchange(t, rng.choice(WORKSTATIONS), GATEWAY, GATEWAY_MAC)
        t += rng.expovariate(1 / 45.0) + 5


def add_port_scan(cap: Capture, start: float) -> None:
    """Rogue host SYN-scans the web server: 40 ports in about 8 seconds."""
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
             1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443,
             8888, 9000, 9200, 10000, 11211, 27017, 5000, 5601, 7001, 8081, 9090, 9443, 50000]
    open_ports = {22, 80, 443, 3389}
    t = start
    for port in ports:
        answer = "open" if port in open_ports else "closed"
        cap.syn_probe(t, ROGUE_HOST, WEB_SERVER, port, answer)
        t += cap.rng.uniform(0.12, 0.25)


def random_label(rng: random.Random, length: int, alphabet: str) -> str:
    return "".join(rng.choice(alphabet) for _ in range(length))


def add_dns_tunnelling(cap: Capture, start: float, host: str = "192.168.10.25", count: int = 40) -> None:
    """Long encoded-looking subdomains under one domain (data hidden in DNS names)."""
    alphabet = string.ascii_lowercase + string.digits
    t = start
    for _ in range(count):
        label = random_label(cap.rng, 48, alphabet)
        cap.dns_lookup(t, host, f"{label}.sync.tunnel.example", answer_ip="203.0.113.53")
        t += cap.rng.uniform(1.5, 4.0)


def add_dns_failed_lookups(cap: Capture, start: float, host: str = "192.168.10.20", count: int = 60) -> None:
    """Many random-looking domains that do not exist (NXDOMAIN), like DGA malware."""
    t = start
    for i in range(count):
        name = random_label(cap.rng, cap.rng.randint(10, 16), string.ascii_lowercase)
        tld = cap.rng.choice(["test", "invalid", "example"])
        rcode = 0 if i % 12 == 0 else 3  # a few succeed
        cap.dns_lookup(t, host, f"{name}.{tld}", rcode=rcode, answer_ip="203.0.113.77")
        t += cap.rng.uniform(1.0, 2.0)


def add_dns_flood(cap: Capture, start: float, host: str = "192.168.10.35", count: int = 150) -> None:
    """150 normal-looking queries in about 30 seconds."""
    t = start
    for _ in range(count):
        cap.dns_lookup(t, host, cap.rng.choice(["telemetry.example.org", "status.example.org"]),
                       answer_ip="198.51.100.11")
        t += cap.rng.uniform(0.1, 0.3)


def add_ssh_bruteforce(cap: Capture, start: float, attacker: str = "203.0.113.45", attempts: int = 40) -> None:
    """Many short SSH connections from one external address (password guessing)."""
    t = start
    for _ in range(attempts):
        end = cap.tcp_session(t, attacker, SSH_SERVER, 22, data_packets=4, size=160)
        t = end + cap.rng.uniform(0.8, 2.0)


def add_watchlist_connections(cap: Capture, start: float, host: str = "192.168.10.21",
                              remote: str = "203.0.113.99", attempts: int = 5) -> None:
    """Workstation repeatedly tries to reach port 4444 (common backdoor port); no answer."""
    t = start
    for _ in range(attempts):
        cap.syn_probe(t, host, remote, 4444, "none")
        t += cap.rng.uniform(6.0, 12.0)


def add_burst(cap: Capture, start: float, host: str = "192.168.10.20",
              remote: str = "203.0.113.80", packets: int = 1800, seconds: float = 6.0) -> None:
    """Large upload: 1,800 packets in 6 seconds from a normally quiet workstation."""
    sport = cap.ephemeral_port()
    cap.add(start, cap.frame(host, remote) / TCP(sport=sport, dport=443, flags="S"))
    cap.add(start + 0.02, cap.frame(remote, host) / TCP(sport=443, dport=sport, flags="SA"))
    cap.add(start + 0.03, cap.frame(host, remote) / TCP(sport=sport, dport=443, flags="A"))
    step = seconds / packets
    for i in range(packets):
        ts = start + 0.04 + i * step
        cap.add(ts, cap.frame(host, remote) / TCP(sport=sport, dport=443, flags="PA") / Raw(payload(512)))
        if i % 4 == 3:  # receiver acknowledges every few segments
            cap.add(ts + 0.001, cap.frame(remote, host) / TCP(sport=443, dport=sport, flags="A"))
    end = start + 0.05 + seconds
    cap.add(end, cap.frame(host, remote) / TCP(sport=sport, dport=443, flags="FA"))
    cap.add(end + 0.02, cap.frame(remote, host) / TCP(sport=443, dport=sport, flags="FA"))


def add_beacon(cap: Capture, start: float, host: str = "192.168.10.25", remote: str = "203.0.113.10",
               interval: float = 60.0, count: int = 12, jitter: float = 0.04) -> None:
    """Small connection at a steady rhythm (interval +/- 4%), like malware checking in."""
    t = start
    for _ in range(count):
        cap.tcp_session(t, host, remote, 8443, data_packets=2, size=180)
        t += interval * (1 + cap.rng.uniform(-jitter, jitter))


def add_arp_spoof(cap: Capture, start: float, victim: str = "192.168.10.20", replies: int = 20) -> None:
    """Rogue host keeps telling the victim 'the gateway IP is at my MAC'."""
    t = start
    for _ in range(replies):
        cap.add(t, Ether(src=ROGUE_MAC, dst=mac_for(victim)) /
                ARP(op=2, psrc=GATEWAY, hwsrc=ROGUE_MAC, pdst=victim, hwdst=mac_for(victim)))
        t += 2.0


# -- scenario table ----------------------------------------------------------

def build(name: str) -> Capture:
    cap = Capture(seed=sum(map(ord, name)))
    if name == "benign_traffic.pcap":
        add_background(cap, BASE_TIME, 300)
    elif name == "port_scan.pcap":
        add_background(cap, BASE_TIME, 180)
        add_port_scan(cap, BASE_TIME + 75)
    elif name == "dns_anomaly.pcap":
        add_background(cap, BASE_TIME, 240)
        add_dns_tunnelling(cap, BASE_TIME + 30)
        add_dns_failed_lookups(cap, BASE_TIME + 60)
        add_dns_flood(cap, BASE_TIME + 170)
    elif name == "repeated_connections.pcap":
        add_background(cap, BASE_TIME, 240)
        add_ssh_bruteforce(cap, BASE_TIME + 60)
        add_watchlist_connections(cap, BASE_TIME + 150)
    elif name == "traffic_burst.pcap":
        add_background(cap, BASE_TIME, 300)
        add_burst(cap, BASE_TIME + 140)
    elif name == "beaconing.pcap":
        add_background(cap, BASE_TIME, 780)
        add_beacon(cap, BASE_TIME + 20)
    elif name == "arp_spoofing.pcap":
        add_background(cap, BASE_TIME, 180)
        add_arp_spoof(cap, BASE_TIME + 70)
    elif name == "mixed_investigation.pcap":
        add_background(cap, BASE_TIME, 420)
        add_port_scan(cap, BASE_TIME + 60)
        add_dns_tunnelling(cap, BASE_TIME + 90, count=30)
        add_ssh_bruteforce(cap, BASE_TIME + 150, attempts=30)
        add_watchlist_connections(cap, BASE_TIME + 200)
        add_burst(cap, BASE_TIME + 250)
        add_beacon(cap, BASE_TIME + 10, interval=30.0, count=13)
        add_arp_spoof(cap, BASE_TIME + 330, replies=15)
    else:
        raise ValueError(f"unknown scenario {name}")
    return cap


SCENARIOS = {
    "benign_traffic.pcap": "Normal office traffic only. No detections expected.",
    "port_scan.pcap": "A rogue internal host SYN-scans 40 ports on the web server.",
    "dns_anomaly.pcap": "DNS tunnelling-style names, many failed (NXDOMAIN) lookups, and a query flood - three different hosts.",
    "repeated_connections.pcap": "SSH password-guessing pattern from an external address, plus repeated attempts to port 4444.",
    "traffic_burst.pcap": "A quiet workstation suddenly uploads 1,800 packets in 6 seconds.",
    "beaconing.pcap": "A workstation connects to the same external server every ~60 seconds.",
    "arp_spoofing.pcap": "A rogue host claims the gateway's IP address with its own MAC address.",
    "mixed_investigation.pcap": "Demo capture: normal traffic plus every attack pattern above.",
}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "samples"))
    args = parser.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name, description in SCENARIOS.items():
        count = build(name).write(out / name)
        print(f"{name:28s} {count:6d} packets  - {description}")
    (out / "scenarios.json").write_text(json.dumps(SCENARIOS, indent=2) + "\n")


if __name__ == "__main__":
    main()
