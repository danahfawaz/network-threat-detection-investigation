"""Small helpers shared by several detection rules."""

from __future__ import annotations

from collections import Counter

import pandas as pd

from ..normalize import ACK, RST, SYN, has_flags


def max_distinct_in_window(times: list[float], keys: list, window: float) -> tuple[int, float, float]:
    """Largest number of distinct keys seen inside any time window.

    Two-pointer sliding window over time-sorted events.
    Returns (best count, window start time, window end time).
    """
    counts: Counter = Counter()
    best, best_start, best_end = 0, 0.0, 0.0
    left = 0
    for right, ts in enumerate(times):
        counts[keys[right]] += 1
        while ts - times[left] > window:
            counts[keys[left]] -= 1
            if counts[keys[left]] == 0:
                del counts[keys[left]]
            left += 1
        if len(counts) > best:
            best, best_start, best_end = len(counts), times[left], ts
    return best, best_start, best_end


def max_count_in_window(times: list[float], window: float) -> tuple[int, float, float]:
    """Largest number of events inside any time window: (count, start, end)."""
    best, best_start, best_end = 0, 0.0, 0.0
    left = 0
    for right, ts in enumerate(times):
        while ts - times[left] > window:
            left += 1
        if right - left + 1 > best:
            best, best_start, best_end = right - left + 1, times[left], ts
    return best, best_start, best_end


def classify_syn_answers(frame: pd.DataFrame, syns: pd.DataFrame) -> pd.Series:
    """For each SYN row, how did the target answer? 'open', 'closed' or 'none'.

    A SYN-ACK back on the same port pair means the port accepted the
    connection; an RST means it refused; nothing means no answer.
    """
    tcp = frame[frame["protocol"] == "TCP"]
    flags = tcp["tcp_flags"]
    synack = tcp[has_flags(flags, SYN | ACK)]
    rst = tcp[has_flags(flags, RST)]

    def answer_keys(rows: pd.DataFrame) -> set:
        # reply direction: dst->src, so swap to match the original SYN
        return set(zip(rows["dst_ip"], rows["src_ip"], rows["dport"], rows["sport"]))

    open_keys, closed_keys = answer_keys(synack), answer_keys(rst)
    keys = list(zip(syns["src_ip"], syns["dst_ip"], syns["sport"], syns["dport"]))
    result = ["open" if k in open_keys else "closed" if k in closed_keys else "none" for k in keys]
    return pd.Series(result, index=syns.index, dtype="object")


def sample_frames(rows: pd.DataFrame, limit: int = 8) -> list[int]:
    return [int(f) for f in rows["frame"].head(limit)]


def plural(count: int, word: str, plural_word: str | None = None) -> str:
    return f"{count:,} {word if count == 1 else (plural_word or word + 's')}"
