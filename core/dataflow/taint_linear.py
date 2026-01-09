from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Set, Tuple

from core.bc_extract import ExtractedMethod, InvokeRef
from core.util.rules import match_method_pattern

class TaintTag(str, Enum):
    INTENT = "INTENT"
    URI = "URI"
    FILE_PATH = "FILE_PATH"
    URL = "URL"
    SQL = "SQL"
    DEX_PATH = "DEX_PATH"
    OTHER = "OTHER"


@dataclass
class CallPropagation:
    caller: str
    callee: str
    arg_index: int
    reg: int
    tags: Set[TaintTag]
    raw: str


@dataclass
class LocalTaintState:
    reg_taint: Dict[int, Set[TaintTag]]
    const_map: Dict[int, str]
    propagations: List[CallPropagation]


def analyze_method_local_taint(method, extracted: ExtractedMethod, rules: Dict[str, object] | None = None) -> LocalTaintState:
    reg_taint: Dict[int, Set[TaintTag]] = {}
    const_map: Dict[int, str] = {}
    propagations: List[CallPropagation] = []
    source_patterns = _source_patterns(rules or {})

    for const in extracted.const_strings:
        const_map[const.dest_reg] = const.value

    for move in extracted.moves:
        if move.src_reg is not None and move.dest_reg is not None:
            tags = reg_taint.get(move.src_reg)
            if tags:
                reg_taint.setdefault(move.dest_reg, set()).update(tags)
            if move.src_reg in const_map:
                const_map[move.dest_reg] = const_map[move.src_reg]

    for inv in extracted.invokes:
        tags = _source_taint(inv, source_patterns)
        if tags and inv.move_result_reg is not None:
            reg_taint.setdefault(inv.move_result_reg, set()).update(tags)

        if _is_uri_parse(inv):
            if inv.move_result_reg is not None and _any_tainted(inv.arg_regs, reg_taint):
                reg_taint.setdefault(inv.move_result_reg, set()).add(TaintTag.URI)

        if _is_intent_mutator(inv):
            receiver = inv.arg_regs[0] if inv.arg_regs else None
            if receiver is not None:
                arg_tags = _collect_arg_tags(inv.arg_regs[1:], reg_taint)
                if arg_tags:
                    reg_taint.setdefault(receiver, set()).update(arg_tags | {TaintTag.INTENT})

        for idx, reg in enumerate(inv.arg_regs):
            if reg in reg_taint:
                propagations.append(
                    CallPropagation(
                        caller=_method_name(method),
                        callee=_invoke_sig(inv),
                        arg_index=idx,
                        reg=reg,
                        tags=set(reg_taint[reg]),
                        raw=inv.raw,
                    )
                )

    return LocalTaintState(reg_taint=reg_taint, const_map=const_map, propagations=propagations)


def _source_taint(inv: InvokeRef, source_patterns: Dict[str, List[str]]) -> Set[TaintTag]:
    tags: Set[TaintTag] = set()

    if _matches_any(inv, source_patterns.get("intent", [])):
        tags.add(TaintTag.INTENT)
    if _matches_any(inv, source_patterns.get("uri", [])):
        tags.add(TaintTag.URI)
    return tags


def _is_intent_mutator(inv: InvokeRef) -> bool:
    if inv.target_class != "Landroid/content/Intent;":
        return False
    return inv.target_name in (
        "setAction",
        "setData",
        "setClassName",
        "setComponent",
        "setPackage",
        "setDataAndType",
        "putExtra",
        "putExtras",
    )


def _is_uri_parse(inv: InvokeRef) -> bool:
    return inv.target_class == "Landroid/net/Uri;" and inv.target_name == "parse"


def _any_tainted(regs: List[int], reg_taint: Dict[int, Set[TaintTag]]) -> bool:
    return any(reg in reg_taint for reg in regs)


def _collect_arg_tags(regs: List[int], reg_taint: Dict[int, Set[TaintTag]]) -> Set[TaintTag]:
    tags: Set[TaintTag] = set()
    for reg in regs:
        if reg in reg_taint:
            tags.update(reg_taint[reg])
    return tags


def _matches_any(inv: InvokeRef, patterns: List[str]) -> bool:
    return any(match_method_pattern(inv.target_class, inv.target_name, pat) for pat in patterns)


def _source_patterns(rules: Dict[str, object]) -> Dict[str, List[str]]:
    by_category: Dict[str, List[str]] = {"intent": [], "uri": []}
    entries = rules.get("sources", [])
    if not isinstance(entries, list):
        return by_category
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        category = entry.get("category")
        methods = entry.get("methods", [])
        if category in by_category and isinstance(methods, list):
            by_category[category].extend(methods)
    return by_category

def _invoke_sig(inv: InvokeRef) -> str:
    return f"{inv.target_class}->{inv.target_name}{inv.target_desc}"


def _method_name(method) -> str:
    try:
        return f"{method.get_class_name()}->{method.get_name()}"
    except Exception:
        return "<unknown>"
