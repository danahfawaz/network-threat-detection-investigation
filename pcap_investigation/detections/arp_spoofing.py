"""Rule 6 - ARP Spoofing (IP-to-MAC conflict).

On a local network, ARP tells devices which MAC address owns an IP address.
If a second device starts answering "that IP is at MY MAC address", traffic
meant for the real owner (often the gateway) can be redirected through the
attacker - a man-in-the-middle position.

Flag any IP address that is announced by at least ``min_macs`` different MAC
addresses in ARP packets.
"""

from __future__ import annotations

import pandas as pd

from ..config import ArpConfig
from ..models import Finding, ScoringSignals, format_duration
from .common import plural, sample_frames

RULE = "arp_spoofing"
TITLE = "ARP Spoofing"
REQUEST, REPLY = 1, 2


def gateway_mac(frame: pd.DataFrame) -> str | None:
    """The MAC most packets to external addresses are sent to = the default gateway."""
    from ..traffic import ip_scope

    ip_rows = frame[frame["dst_ip"].notna() & frame["dst_mac"].notna()]
    if ip_rows.empty:
        return None
    external = ip_rows[ip_rows["dst_ip"].map(ip_scope).eq("External")]
    if external.empty:
        return None
    return external["dst_mac"].value_counts().index[0]


def mac_to_ip(frame: pd.DataFrame, mac: str, exclude_ip: str) -> str | None:
    """IP address a MAC uses for its own IP traffic (if it sent any)."""
    rows = frame[(frame["src_mac"] == mac) & frame["src_ip"].notna() & (frame["src_ip"] != exclude_ip)]
    if rows.empty:
        return None
    return rows["src_ip"].value_counts().index[0]


def unsolicited_replies(arp: pd.DataFrame, replies: pd.DataFrame, claimed_ip: str, window: float = 2.0) -> int:
    """Replies sent without a matching request for that IP shortly before."""
    requests = arp[(arp["arp_op"] == REQUEST) & (arp["arp_pdst"] == claimed_ip)]
    count = 0
    for _, reply in replies.iterrows():
        asked = requests[(requests["arp_psrc"] == reply["arp_pdst"])
                         & (requests["ts"] <= reply["ts"]) & (reply["ts"] - requests["ts"] <= window)]
        if asked.empty:
            count += 1
    return count


def detect(frame: pd.DataFrame, cfg: ArpConfig) -> list[Finding]:
    arp = frame[(frame["protocol"] == "ARP") & frame["arp_psrc"].notna()
                & (frame["arp_psrc"] != "0.0.0.0") & frame["arp_hwsrc"].notna()]
    findings = []
    for claimed_ip, rows in arp.groupby("arp_psrc", sort=True):
        macs = rows.groupby("arp_hwsrc")["ts"].min().sort_values()
        if len(macs) < cfg.min_macs:
            continue
        findings.append(_build(frame, arp, rows, claimed_ip, macs, cfg))
    return findings


def _build(frame, arp, rows, claimed_ip, macs, cfg) -> Finding:
    original_mac = macs.index[0]
    suspect_macs = list(macs.index[1:])
    suspect_mac = suspect_macs[0]
    suspect_rows = rows[rows["arp_hwsrc"].isin(suspect_macs)].sort_values("ts")
    suspect_replies = suspect_rows[suspect_rows["arp_op"] == REPLY]
    victims = sorted(suspect_replies["arp_pdst"].dropna().unique().tolist())
    suspect_ip = mac_to_ip(frame, suspect_mac, claimed_ip)
    unsolicited = unsolicited_replies(arp, suspect_replies, claimed_ip)
    first, last = float(suspect_rows["ts"].min()), float(suspect_rows["ts"].max())
    span = last - first
    is_gateway = gateway_mac(frame) == original_mac
    original_count = int((rows["arp_hwsrc"] == original_mac).sum())

    who = f"{suspect_ip} (MAC {suspect_mac})" if suspect_ip else f"a device with MAC {suspect_mac}"
    claimed_text = f"{claimed_ip} (the default gateway)" if is_gateway else claimed_ip
    evidence = [
        f"{claimed_ip} was announced by {len(macs)} different MAC addresses.",
        f"Original: {original_mac} (first seen earlier, {plural(original_count, 'ARP packet')}).",
        f"New: {', '.join(suspect_macs)} - {plural(len(suspect_rows), 'ARP packet')} over {format_duration(span)}.",
        f"{unsolicited} of {len(suspect_replies)} replies from the new MAC were unsolicited "
        "(no one had asked for that IP just before).",
    ]
    if victims:
        evidence.append("Replies were sent to: " + ", ".join(victims[:6]) + ".")
    if suspect_ip:
        evidence.append(f"MAC {suspect_mac} also sends normal IP traffic as {suspect_ip}.")
    if is_gateway:
        evidence.append(f"{original_mac} is the MAC that traffic to the internet goes through, "
                        f"so {claimed_ip} is the gateway.")

    return Finding(
        rule=RULE, title=TITLE, subtype="IP-to-MAC conflict", src_ip=suspect_ip, src_mac=suspect_mac,
        dst_ip=victims[0] if len(victims) == 1 else None, targets=victims, ports=[], protocol="ARP",
        first_seen=first, last_seen=last, event_count=int(len(suspect_rows)), event_label="ARP packets",
        summary=f"{claimed_ip} claimed by {len(macs)} MAC addresses (new: {suspect_mac})",
        what_happened=(f"{who[:1].upper()}{who[1:]} told other devices that it owns the IP address {claimed_text}. That IP was "
                       f"already in use by MAC {original_mac}. If devices believe this, their traffic is "
                       "sent through the new device, which can read or change it (man-in-the-middle). "
                       "A replaced network card or a failover router can also cause this - check which."),
        why_flagged=(f"One IP address with {len(macs)} different MAC addresses in ARP traffic. The rule flags "
                     f"{cfg.min_macs} or more."),
        evidence=evidence,
        recommended_steps=[
            f"Find the switch port for MAC {suspect_mac} (switch MAC address table) and the device behind it.",
            f"Check the ARP cache on {', '.join(victims[:3]) or 'affected hosts'} for {claimed_ip}.",
            "Confirm whether a hardware change or failover explains the new MAC.",
            "If not, disconnect the device and enable Dynamic ARP Inspection / port security on the switch.",
        ],
        signals=ScoringSignals(
            ratio=len(macs) / cfg.min_macs,
            scale_text=f"{len(macs)} MAC addresses for one IP (threshold {cfg.min_macs})",
            sensitive=(f"The impersonated address {claimed_ip} is the default gateway" if is_gateway else None),
            persistent=f"Continued for {format_duration(span)}" if span >= 300 else None,
            confirmed=(f"{unsolicited} unsolicited ARP replies, typical of ARP poisoning tools"
                       if unsolicited >= 3 else None),
        ),
        sample_frames=sample_frames(suspect_rows),
        metrics={"claimed_ip": claimed_ip, "original_mac": original_mac, "suspect_macs": suspect_macs,
                 "suspect_ip": suspect_ip, "unsolicited_replies": int(unsolicited),
                 "victims": victims, "is_gateway": bool(is_gateway)},
    )
