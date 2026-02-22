"""Dalvik method-descriptor parsing utilities.

Shared by the taint engine and scanners that need parameter-register mapping.
"""
from __future__ import annotations

from typing import List, Tuple


def parse_descriptor_params(desc: str) -> Tuple[int, List[str]]:
    """Parse a method descriptor and return ``(logical_param_count, type_list)``."""
    params: List[str] = []
    if not desc or "(" not in desc:
        return 0, params
    sig = desc.split("(", 1)[1].split(")", 1)[0]
    i = 0
    while i < len(sig):
        ch = sig[i]
        if ch == "[":
            start = i
            i += 1
            while i < len(sig) and sig[i] == "[":
                i += 1
            if i < len(sig) and sig[i] == "L":
                i = sig.find(";", i) + 1
            else:
                i += 1
            params.append(sig[start:i])
        elif ch == "L":
            end = sig.find(";", i)
            if end == -1:
                break
            params.append(sig[i : end + 1])
            i = end + 1
        else:
            params.append(ch)
            i += 1
    return len(params), params


def descriptor_slot_count(desc: str) -> int:
    """Count the number of register *slots* consumed by the parameters.

    ``J`` (long) and ``D`` (double) each consume 2 slots; everything else 1.
    """
    if not desc or "(" not in desc:
        return 0
    sig = desc.split("(", 1)[1].split(")", 1)[0]
    slots = 0
    i = 0
    while i < len(sig):
        ch = sig[i]
        if ch == "[":
            i += 1
            while i < len(sig) and sig[i] == "[":
                i += 1
            if i < len(sig) and sig[i] == "L":
                i = sig.find(";", i) + 1
            else:
                i += 1
            slots += 1
        elif ch == "L":
            end = sig.find(";", i)
            if end == -1:
                break
            i = end + 1
            slots += 1
        elif ch in ("J", "D"):
            slots += 2
            i += 1
        else:
            slots += 1
            i += 1
    return slots
