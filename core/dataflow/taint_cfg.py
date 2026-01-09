from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from core.cfg import build_method_cfg, IRInstruction
from core.dataflow.taint_linear import TaintTag
from core.dataflow.dex_queries import build_method_index
from core.util.rules import match_method_pattern


@dataclass
class MethodTaintResult:
    reg_taint_at: Dict[int, Dict[int, Set[TaintTag]]]
    return_taint: Set[TaintTag]


class TaintEngine:
    def __init__(self, analysis, rules: Dict[str, object]) -> None:
        self.analysis = analysis
        self.rules = rules
        self.method_index = build_method_index(analysis)
        self._cfg_cache: Dict[Tuple[str, str, str], object] = {}
        self._results: Dict[Tuple[str, str, str], MethodTaintResult] = {}
        self._return_summary: Dict[Tuple[str, str, str], Set[TaintTag]] = {}
        self._param_taint: Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]] = {}
        self._source_patterns = _source_patterns(rules)
        self._sanitizer_patterns = _sanitizer_patterns(rules)

    def analyze(self) -> None:
        methods = _all_methods(self.analysis)
        sig_to_method = {_method_sig(m): m for m in methods}
        callsites = _collect_callsites(methods)

        changed = True
        while changed:
            changed = False
            for method in methods:
                sig = _method_sig(method)
                param_taint = self._param_taint.get(sig, {})
                result = _analyze_method_cfg(
                    method,
                    param_taint,
                    self._return_summary,
                    self._source_patterns,
                    self._sanitizer_patterns,
                )
                prev = self._results.get(sig)
                self._results[sig] = result
                if prev is None or prev.return_taint != result.return_taint:
                    if self._return_summary.get(sig) != result.return_taint:
                        self._return_summary[sig] = set(result.return_taint)
                        changed = True

            new_param_taint = _propagate_param_taint(callsites, self._results, sig_to_method)
            if _merge_param_taint(self._param_taint, new_param_taint):
                changed = True

    def result_for(self, method) -> Optional[MethodTaintResult]:
        sig = _method_sig(method)
        if sig not in self._results:
            self.analyze()
        return self._results.get(sig)

    def taint_at(self, method, ins_offset: int) -> Dict[int, Set[TaintTag]]:
        result = self.result_for(method)
        if not result:
            return {}
        return result.reg_taint_at.get(ins_offset, {})

    def return_taint(self, method) -> Set[TaintTag]:
        sig = _method_sig(method)
        if sig not in self._return_summary:
            self.analyze()
        return self._return_summary.get(sig, set())


def _analyze_method_cfg(
    method,
    param_taint: Dict[int, Set[TaintTag]],
    return_summary: Dict[Tuple[str, str, str], Set[TaintTag]],
    source_patterns: Dict[str, List[str]],
    sanitizer_patterns: Dict[str, List[str]],
) -> MethodTaintResult:
    cfg = build_method_cfg(method)
    worklist = [cfg.entry]
    in_state: Dict[int, Dict[int, Set[TaintTag]]] = {}
    out_state: Dict[int, Dict[int, Set[TaintTag]]] = {}
    reg_taint_at: Dict[int, Dict[int, Set[TaintTag]]] = {}
    return_taint: Set[TaintTag] = set()

    in_state[cfg.entry] = _clone_taint(param_taint)

    while worklist:
        bid = worklist.pop(0)
        block = cfg.blocks[bid]
        cur = _clone_taint(in_state.get(bid, {}))
        for ins in block.instrs:
            _transfer_instruction(ins, cur, return_summary, source_patterns, sanitizer_patterns)
            reg_taint_at[ins.offset] = _clone_taint(cur)
            if ins.is_return and ins.regs:
                reg = ins.regs[0]
                return_taint.update(cur.get(reg, set()))
        out_state[bid] = _clone_taint(cur)
        for succ in block.succs:
            merged = _merge_taint(in_state.get(succ, {}), out_state[bid])
            if merged:
                in_state[succ] = merged
                if succ not in worklist:
                    worklist.append(succ)

    return MethodTaintResult(reg_taint_at=reg_taint_at, return_taint=return_taint)


def _transfer_instruction(
    ins: IRInstruction,
    reg_taint: Dict[int, Set[TaintTag]],
    return_summary: Dict[Tuple[str, str, str], Set[TaintTag]],
    source_patterns: Dict[str, List[str]],
    sanitizer_patterns: Dict[str, List[str]],
) -> None:
    opcode = ins.opcode
    if opcode.startswith("move") and len(ins.regs) >= 2:
        dest, src = ins.regs[0], ins.regs[1]
        if src in reg_taint:
            reg_taint[dest] = set(reg_taint[src])
        else:
            reg_taint.pop(dest, None)
        return

    if ins.is_invoke and ins.target_sig:
        cls, name, desc = ins.target_sig
        _apply_sources(ins, reg_taint, cls, name, source_patterns)
        _apply_sanitizers(ins, reg_taint, cls, name, sanitizer_patterns)
        _apply_intent_mutator(ins, reg_taint, cls, name)
        _apply_uri_parse(ins, reg_taint, cls, name)
        if ins.move_result_reg is not None:
            ret_tags = return_summary.get((cls, name, desc))
            if ret_tags:
                reg_taint.setdefault(ins.move_result_reg, set()).update(ret_tags)


def _apply_sources(
    ins: IRInstruction,
    reg_taint: Dict[int, Set[TaintTag]],
    cls: str,
    name: str,
    source_patterns: Dict[str, List[str]],
) -> None:
    if ins.move_result_reg is None:
        return
    tags = set()
    for category, patterns in source_patterns.items():
        if any(match_method_pattern(cls, name, pat) for pat in patterns):
            tags.update(_category_tags(category))
    if tags:
        reg_taint.setdefault(ins.move_result_reg, set()).update(tags)


def _apply_sanitizers(
    ins: IRInstruction,
    reg_taint: Dict[int, Set[TaintTag]],
    cls: str,
    name: str,
    sanitizer_patterns: Dict[str, List[str]],
) -> None:
    for category, patterns in sanitizer_patterns.items():
        if category == "uri":
            # Canonicalization alone should not clear taint; evidence handles enforcement.
            continue
        if not any(match_method_pattern(cls, name, pat) for pat in patterns):
            continue
        tags = _category_tags(category)
        if ins.move_result_reg is not None:
            _remove_tags(reg_taint, ins.move_result_reg, tags)
        if ins.regs:
            _remove_tags(reg_taint, ins.regs[0], tags)


def _apply_intent_mutator(ins: IRInstruction, reg_taint: Dict[int, Set[TaintTag]], cls: str, name: str) -> None:
    if cls != "Landroid/content/Intent;":
        return
    mutators = {
        "setAction",
        "setData",
        "setClassName",
        "setComponent",
        "setPackage",
        "setDataAndType",
        "putExtra",
        "putExtras",
    }
    if name not in mutators:
        return
    if not ins.regs:
        return
    receiver = ins.regs[0]
    arg_tags = set()
    for reg in ins.regs[1:]:
        arg_tags.update(reg_taint.get(reg, set()))
    if arg_tags:
        reg_taint.setdefault(receiver, set()).update(arg_tags | {TaintTag.INTENT})


def _apply_uri_parse(ins: IRInstruction, reg_taint: Dict[int, Set[TaintTag]], cls: str, name: str) -> None:
    if cls != "Landroid/net/Uri;" or name != "parse":
        return
    if ins.move_result_reg is None:
        return
    if any(reg in reg_taint for reg in ins.regs):
        reg_taint.setdefault(ins.move_result_reg, set()).add(TaintTag.URI)


def _remove_tags(reg_taint: Dict[int, Set[TaintTag]], reg: int, tags: Set[TaintTag]) -> None:
    if reg not in reg_taint:
        return
    remaining = set(reg_taint[reg]) - tags
    if remaining:
        reg_taint[reg] = remaining
    else:
        reg_taint.pop(reg, None)


def _clone_taint(reg_taint: Dict[int, Set[TaintTag]]) -> Dict[int, Set[TaintTag]]:
    return {reg: set(tags) for reg, tags in reg_taint.items()}


def _merge_taint(base: Dict[int, Set[TaintTag]], incoming: Dict[int, Set[TaintTag]]) -> Optional[Dict[int, Set[TaintTag]]]:
    if not incoming:
        return None
    merged = _clone_taint(base)
    changed = False
    for reg, tags in incoming.items():
        if reg not in merged:
            merged[reg] = set(tags)
            changed = True
        else:
            before = set(merged[reg])
            merged[reg].update(tags)
            if merged[reg] != before:
                changed = True
    return merged if changed else None


def _collect_callsites(methods: List[object]) -> Dict[Tuple[str, str, str], List[IRInstruction]]:
    callsites: Dict[Tuple[str, str, str], List[IRInstruction]] = {}
    for method in methods:
        cfg = build_method_cfg(method)
        for block in cfg.blocks.values():
            for ins in block.instrs:
                if ins.is_invoke and ins.target_sig:
                    callsites.setdefault(_method_sig(method), []).append(ins)
    return callsites


def _propagate_param_taint(
    callsites: Dict[Tuple[str, str, str], List[IRInstruction]],
    results: Dict[Tuple[str, str, str], MethodTaintResult],
    sig_to_method: Dict[Tuple[str, str, str], object],
) -> Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]]:
    new_param: Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]] = {}
    for caller_sig, invokes in callsites.items():
        caller_result = results.get(caller_sig)
        if not caller_result:
            continue
        for inv in invokes:
            callee_sig = inv.target_sig
            if not callee_sig:
                continue
            if callee_sig not in sig_to_method:
                continue
            taint_at = caller_result.reg_taint_at.get(inv.offset, {})
            for idx, reg in enumerate(inv.regs):
                if reg not in taint_at:
                    continue
                param_reg = -(idx + 1)
                new_param.setdefault(callee_sig, {}).setdefault(param_reg, set()).update(taint_at[reg])
    return new_param


def _merge_param_taint(
    dest: Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]],
    incoming: Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]],
) -> bool:
    changed = False
    for sig, reg_map in incoming.items():
        base = dest.setdefault(sig, {})
        for reg, tags in reg_map.items():
            if reg not in base:
                base[reg] = set(tags)
                changed = True
            else:
                before = set(base[reg])
                base[reg].update(tags)
                if base[reg] != before:
                    changed = True
    return changed


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


def _sanitizer_patterns(rules: Dict[str, object]) -> Dict[str, List[str]]:
    by_category: Dict[str, List[str]] = {}
    entries = rules.get("sanitizers", [])
    if not isinstance(entries, list):
        return by_category
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        category = entry.get("category")
        patterns = entry.get("patterns", [])
        if isinstance(category, str) and isinstance(patterns, list):
            by_category.setdefault(category, []).extend(patterns)
    return by_category


def _category_tags(category: str) -> Set[TaintTag]:
    mapping = {
        "intent": {TaintTag.INTENT},
        "uri": {TaintTag.URI, TaintTag.FILE_PATH},
        "web": {TaintTag.URL},
        "sql": {TaintTag.SQL},
    }
    return set(mapping.get(category, {TaintTag.OTHER}))


def _all_methods(analysis) -> List[object]:
    out = []
    for m in analysis.get_methods():
        try:
            out.append(m.get_method())
        except Exception:
            continue
    return out


def _method_sig(method) -> Tuple[str, str, str]:
    try:
        return method.get_class_name(), method.get_name(), method.get_descriptor()
    except Exception:
        return "<unknown>", "<unknown>", ""
