from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Set, Tuple

from core.bytecode.extract import ExtractedMethod, InvokeRef, ConstStringRef, MoveRef, FieldRef
from core.dataflow.tags import TaintTag
from core.rules.matching import match_method_pattern


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
    reg_taint_by_offset: Dict[int, Dict[int, Set[TaintTag]]]
    const_map: Dict[int, str]
    propagations: List[CallPropagation]


_CATEGORY_TAG_MAP: Dict[str, Set[TaintTag]] = {
    "intent": {TaintTag.INTENT},
    "uri": {TaintTag.URI, TaintTag.FILE_PATH},
    "web": {TaintTag.URL},
    "sql": {TaintTag.SQL},
    "user_input": {TaintTag.USER_INPUT},
    "provider": {TaintTag.USER_INPUT, TaintTag.SQL},
}


def analyze_method_local_taint(
    method,
    extracted: ExtractedMethod,
    rules: Dict[str, object] | None = None,
) -> LocalTaintState:
    """Single-pass, offset-ordered linear taint analysis.

    Processes every instruction (const-strings, moves, field-gets, invokes)
    in offset order so that taint introduced at offset N is visible at
    offset N+1 but not at offset N-1.  Returns per-offset taint snapshots.
    """
    reg_taint: Dict[int, Set[TaintTag]] = {}
    const_map: Dict[int, str] = {}
    propagations: List[CallPropagation] = []
    reg_taint_by_offset: Dict[int, Dict[int, Set[TaintTag]]] = {}
    source_patterns = _source_patterns(rules or {})

    items = _build_offset_sorted_items(extracted)

    for offset, kind, obj in items:
        if kind == "const":
            cs: ConstStringRef = obj
            const_map[cs.dest_reg] = cs.value

        elif kind == "move":
            mv: MoveRef = obj
            if mv.src_reg is not None and mv.dest_reg is not None:
                tags = reg_taint.get(mv.src_reg)
                if tags:
                    reg_taint[mv.dest_reg] = set(tags)
                else:
                    reg_taint.pop(mv.dest_reg, None)
                if mv.src_reg in const_map:
                    const_map[mv.dest_reg] = const_map[mv.src_reg]

        elif kind == "field_get":
            fr: FieldRef = obj
            if fr.dest_reg is not None and fr.regs:
                obj_reg = fr.regs[0] if len(fr.regs) > 0 else None
                if obj_reg is not None and obj_reg in reg_taint:
                    reg_taint.setdefault(fr.dest_reg, set()).update(reg_taint[obj_reg])

        elif kind == "invoke":
            inv: InvokeRef = obj

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

            if inv.target_name == "<init>" and inv.arg_regs:
                recv = inv.arg_regs[0]
                for arg in inv.arg_regs[1:]:
                    if arg in reg_taint:
                        reg_taint.setdefault(recv, set()).update(reg_taint[arg])

            if inv.move_result_reg is not None:
                agg: Set[TaintTag] = set()
                for r in inv.arg_regs:
                    if r in reg_taint:
                        agg.update(reg_taint[r])
                if agg:
                    reg_taint.setdefault(inv.move_result_reg, set()).update(agg)

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

            reg_taint_by_offset[offset] = {r: set(t) for r, t in reg_taint.items()}

    return LocalTaintState(
        reg_taint=reg_taint,
        reg_taint_by_offset=reg_taint_by_offset,
        const_map=const_map,
        propagations=propagations,
    )


def _build_offset_sorted_items(extracted: ExtractedMethod) -> List[Tuple[int, str, object]]:
    """Merge all extracted items into a single offset-sorted list."""
    items: List[Tuple[int, str, object]] = []
    for cs in extracted.const_strings:
        items.append((cs.offset, "const", cs))
    for mv in extracted.moves:
        if not mv.opcode.startswith("move-result"):
            items.append((mv.offset, "move", mv))
    for fr in extracted.field_refs:
        if fr.opcode.startswith(("iget", "sget")):
            items.append((fr.offset, "field_get", fr))
    for inv in extracted.invokes:
        items.append((inv.offset, "invoke", inv))
    items.sort(key=lambda x: x[0])
    return items


def _source_taint(inv: InvokeRef, source_patterns: Dict[str, List[str]]) -> Set[TaintTag]:
    tags: Set[TaintTag] = set()
    for category, patterns in source_patterns.items():
        if _matches_any(inv, patterns):
            tags.update(_CATEGORY_TAG_MAP.get(category, {TaintTag.OTHER}))
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
    by_category: Dict[str, List[str]] = {}
    entries = rules.get("sources", [])
    if not isinstance(entries, list):
        return by_category
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        category = entry.get("category")
        methods = entry.get("methods", [])
        if isinstance(category, str) and isinstance(methods, list):
            by_category.setdefault(category, []).extend(methods)
    return by_category


def _invoke_sig(inv: InvokeRef) -> str:
    return f"{inv.target_class}->{inv.target_name}{inv.target_desc}"


def _method_name(method) -> str:
    try:
        return f"{method.get_class_name()}->{method.get_name()}"
    except Exception:
        return "<unknown>"
