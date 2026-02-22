"""Shared low-level helpers for working with Dalvik/DEX bytecode instructions.

Functions here are used by both the bytecode extractor and the CFG builder,
eliminating the previous duplication between ``bc_extract`` and ``cfg``.
"""
from __future__ import annotations

import re
from typing import List, Optional

_REG_RE = re.compile(r"\b([vp])(\d+)\b")


def reg_to_int(kind: str, idx: str) -> int:
    """Map a register reference to an integer.

    Parameter registers (``p0``, ``p1``, ...) are mapped to negative space
    so they stay distinct from virtual registers.
    """
    value = int(idx)
    if kind == "p":
        return -(value + 1)
    return value


def parse_regs(text: str) -> List[int]:
    """Extract register references from an instruction output string."""
    regs: List[int] = []
    if ".." in text:
        match = re.search(r"([vp])(\d+)\s*\.\.\s*([vp])(\d+)", text)
        if match:
            start = reg_to_int(match.group(1), match.group(2))
            end = reg_to_int(match.group(3), match.group(4))
            step = 1 if end >= start else -1
            regs.extend(list(range(start, end + step, step)))
            return regs
    for kind, idx in _REG_RE.findall(text):
        regs.append(reg_to_int(kind, idx))
    return regs


def ins_addr(ins) -> Optional[int]:
    """Best-effort extraction of an instruction's bytecode address."""
    for name in ("get_start_addr", "get_start", "get_pos", "get_offset"):
        if hasattr(ins, name):
            try:
                value = getattr(ins, name)()
            except Exception:
                try:
                    value = getattr(ins, name)
                except Exception:
                    continue
            if isinstance(value, int):
                return value
    return None


def ins_length(ins) -> Optional[int]:
    """Best-effort extraction of an instruction's byte-length."""
    for name in ("get_length", "get_size", "get_insn_length"):
        if hasattr(ins, name):
            try:
                value = getattr(ins, name)()
            except Exception:
                try:
                    value = getattr(ins, name)
                except Exception:
                    continue
            if isinstance(value, int):
                return value
    return None


def instruction_offsets(ins_list) -> List[int]:
    """Compute byte-offset for every instruction in *ins_list*.

    Prefers real addresses when the instruction objects expose them;
    falls back to cumulative length otherwise.
    """
    offsets: List[int] = []
    have_addr = False
    for ins in ins_list:
        addr = ins_addr(ins)
        if addr is not None:
            offsets.append(addr)
            have_addr = True
        else:
            offsets.append(0)
    if have_addr:
        return offsets
    current = 0
    out: List[int] = []
    for ins in ins_list:
        out.append(current)
        length = ins_length(ins)
        current += length if length is not None else 1
    return out
