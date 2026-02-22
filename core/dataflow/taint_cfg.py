from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from core.bytecode.cfg import build_method_cfg, IRInstruction, MethodCFG
from core.dataflow.tags import TaintTag
from core.dataflow.dex_queries import build_method_index, all_methods as _dex_all_methods
from core.dataflow.callbacks import is_callback_root, find_onclick_callbacks, collect_callback_edges
from core.rules.matching import match_method_pattern
from core.util.descriptors import parse_descriptor_params, descriptor_slot_count

_log = logging.getLogger(__name__)

_MAX_FIXPOINT_ITERATIONS = 20

_BUILDER_CLASSES = frozenset({
    "Ljava/lang/StringBuilder;",
    "Ljava/lang/StringBuffer;",
    "Landroid/content/Intent;",
    "Landroid/net/Uri$Builder;",
    "Landroid/os/Bundle;",
    "Landroid/content/ContentValues;",
    "Ljava/util/HashMap;",
    "Landroid/database/sqlite/SQLiteQueryBuilder;",
})


@dataclass
class MethodTaintResult:
    reg_taint_at: Dict[int, Dict[int, Set[TaintTag]]]
    return_taint: Set[TaintTag]
    reach_roots: Set[Tuple[str, str, str]]


class TaintEngine:
    def __init__(self, analysis, rules: Dict[str, object]) -> None:
        self.analysis = analysis
        self.rules = rules
        self.method_index = build_method_index(analysis)
        self._cfg_cache: Dict[Tuple[str, str, str], MethodCFG] = {}
        self._results: Dict[Tuple[str, str, str], MethodTaintResult] = {}
        self._return_summary: Dict[Tuple[str, str, str], Set[TaintTag]] = {}
        self._param_taint: Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]] = {}
        self._source_patterns = _source_patterns(rules)
        self._sanitizer_patterns = _sanitizer_patterns(rules)
        self._callback_roots: Set[Tuple[str, str, str]] = set()
        self._callback_edges: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]] = {}
        self._callback_reg_offsets: Dict[Tuple[str, str, str], Dict[Tuple[str, str, str], int]] = {}
        self._reach: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]] = {}
        self._analyzed: bool = False

    def _get_cfg(self, method) -> MethodCFG:
        sig = _method_sig(method)
        if sig not in self._cfg_cache:
            self._cfg_cache[sig] = build_method_cfg(method)
        return self._cfg_cache[sig]

    def analyze(self) -> None:
        if self._analyzed:
            return
        methods = _all_methods(self.analysis)
        sig_to_method = {_method_sig(m): m for m in methods}

        for m in methods:
            self._get_cfg(m)

        callsites = self._collect_callsites(methods)
        self._callback_roots = {sig for sig, m in sig_to_method.items() if is_callback_root(m)}
        self._callback_edges = collect_callback_edges(sig_to_method, self.method_index, self.analysis)
        self._build_callback_reg_offsets(sig_to_method)
        self._reach = {sig: {sig} for sig in self._callback_roots}

        changed = True
        iteration = 0
        while changed and iteration < _MAX_FIXPOINT_ITERATIONS:
            iteration += 1
            changed = False
            for method in methods:
                sig = _method_sig(method)
                param_taint = self._param_taint.get(sig, {})
                cfg = self._get_cfg(method)
                result = _analyze_method_cfg(
                    method,
                    param_taint,
                    self._return_summary,
                    self._source_patterns,
                    self._sanitizer_patterns,
                    cfg=cfg,
                )
                result.reach_roots = set(self._reach.get(sig, set()))
                prev = self._results.get(sig)
                self._results[sig] = result
                if prev is None or prev.return_taint != result.return_taint:
                    if self._return_summary.get(sig) != result.return_taint:
                        self._return_summary[sig] = set(result.return_taint)
                        changed = True

            new_param_taint, new_reach = _propagate_param_taint(
                callsites,
                self._results,
                sig_to_method,
                callback_edges=self._callback_edges,
                callback_reg_offsets=self._callback_reg_offsets,
                reach=self._reach,
                callback_roots=self._callback_roots,
            )
            if _merge_param_taint(self._param_taint, new_param_taint):
                changed = True
            if _merge_reach(self._reach, new_reach):
                changed = True

        if iteration >= _MAX_FIXPOINT_ITERATIONS:
            _log.warning("Fixed-point loop hit iteration limit (%d)", _MAX_FIXPOINT_ITERATIONS)

        self._analyzed = True

    def _collect_callsites(self, methods: List[object]) -> Dict[Tuple[str, str, str], List[IRInstruction]]:
        callsites: Dict[Tuple[str, str, str], List[IRInstruction]] = {}
        for method in methods:
            cfg = self._get_cfg(method)
            for block in cfg.blocks.values():
                for ins in block.instrs:
                    if ins.is_invoke and ins.target_sig:
                        callsites.setdefault(_method_sig(method), []).append(ins)
        return callsites

    def _build_callback_reg_offsets(self, sig_to_method: Dict[Tuple[str, str, str], object]) -> None:
        """For each caller with callback edges, find the offset of the
        setOnClickListener / startActivity call that registered the edge."""
        for caller_sig, cb_targets in self._callback_edges.items():
            method = sig_to_method.get(caller_sig)
            if not method:
                continue
            cfg = self._get_cfg(method)
            for block in cfg.blocks.values():
                for ins in block.instrs:
                    if not ins.is_invoke or not ins.target_sig:
                        continue
                    _, call_name, _ = ins.target_sig
                    if call_name in ("setOnClickListener", "startActivity",
                                     "startActivityForResult", "startService",
                                     "sendBroadcast"):
                        for cb_sig in cb_targets:
                            self._callback_reg_offsets \
                                .setdefault(caller_sig, {}) \
                                .setdefault(cb_sig, ins.offset)

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

    def reach_for(self, method) -> Set[Tuple[str, str, str]]:
        sig = _method_sig(method)
        if not self._analyzed:
            self.analyze()
        return self._reach.get(sig, set())


def _analyze_method_cfg(
    method,
    param_taint: Dict[int, Set[TaintTag]],
    return_summary: Dict[Tuple[str, str, str], Set[TaintTag]],
    source_patterns: Dict[str, List[str]],
    sanitizer_patterns: Dict[str, List[str]],
    cfg: Optional[MethodCFG] = None,
) -> MethodTaintResult:
    if cfg is None:
        cfg = build_method_cfg(method)
    worklist = [cfg.entry]
    in_state: Dict[int, Dict[int, Set[TaintTag]]] = {}
    out_state: Dict[int, Dict[int, Set[TaintTag]]] = {}
    reg_taint_at: Dict[int, Dict[int, Set[TaintTag]]] = {}
    return_taint: Set[TaintTag] = set()

    in_state[cfg.entry] = _map_param_taint(method, param_taint)

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

    return MethodTaintResult(reg_taint_at=reg_taint_at, return_taint=return_taint, reach_roots=set())


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

        if ins.move_result_reg is not None:
            agg_tags: Set[TaintTag] = set()
            for reg in ins.regs:
                if reg in reg_taint:
                    agg_tags.update(reg_taint[reg])
            if agg_tags:
                reg_taint.setdefault(ins.move_result_reg, set()).update(agg_tags)

        if cls in _BUILDER_CLASSES and ins.regs and len(ins.regs) >= 2:
            recv = ins.regs[0]
            arg_tags: Set[TaintTag] = set()
            for reg in ins.regs[1:]:
                if reg in reg_taint:
                    arg_tags.update(reg_taint[reg])
            if arg_tags:
                reg_taint.setdefault(recv, set()).update(arg_tags)

        if name == "<init>" and ins.regs:
            recv = ins.regs[0]
            for arg in ins.regs[1:]:
                if arg in reg_taint:
                    reg_taint.setdefault(recv, set()).update(reg_taint[arg])

        _apply_sources(ins, reg_taint, cls, name, source_patterns)
        _apply_sanitizers(ins, reg_taint, cls, name, sanitizer_patterns)
        _apply_intent_mutator(ins, reg_taint, cls, name)
        _apply_uri_parse(ins, reg_taint, cls, name)

        if ins.move_result_reg is not None and ins.regs:
            recv = ins.regs[0]
            if recv in reg_taint:
                reg_taint.setdefault(ins.move_result_reg, set()).update(reg_taint[recv])

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
    tags: Set[TaintTag] = set()
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
        "setAction", "setData", "setClassName", "setComponent",
        "setPackage", "setDataAndType", "putExtra", "putExtras",
    }
    if name not in mutators:
        return
    if not ins.regs:
        return
    receiver = ins.regs[0]
    arg_tags: Set[TaintTag] = set()
    for reg in ins.regs[1:]:
        arg_tags.update(reg_taint.get(reg, set()))
    if arg_tags:
        reg_taint.setdefault(receiver, set()).update(arg_tags | {TaintTag.INTENT})

    if name == "<init>" and len(ins.regs) > 1:
        for reg in ins.regs[1:]:
            if reg in reg_taint:
                reg_taint.setdefault(receiver, set()).update(reg_taint[reg] | {TaintTag.INTENT})


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


def _propagate_param_taint(
    callsites: Dict[Tuple[str, str, str], List[IRInstruction]],
    results: Dict[Tuple[str, str, str], MethodTaintResult],
    sig_to_method: Dict[Tuple[str, str, str], object],
    callback_edges: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]] | None = None,
    callback_reg_offsets: Dict[Tuple[str, str, str], Dict[Tuple[str, str, str], int]] | None = None,
    reach: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]] | None = None,
    callback_roots: Set[Tuple[str, str, str]] | None = None,
) -> tuple[Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]], Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]]]:
    new_param: Dict[Tuple[str, str, str], Dict[int, Set[TaintTag]]] = {}
    new_reach: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]] = {}
    reach = reach or {}
    callback_roots = callback_roots or set()
    callback_reg_offsets = callback_reg_offsets or {}

    for caller_sig, invokes in callsites.items():
        caller_result = results.get(caller_sig)
        if not caller_result:
            continue
        caller_roots = reach.get(caller_sig, set())
        if not caller_roots and caller_sig in callback_roots:
            caller_roots = {caller_sig}

        for inv in invokes:
            callee_sig = inv.target_sig
            if not callee_sig or callee_sig not in sig_to_method:
                continue
            taint_at = caller_result.reg_taint_at.get(inv.offset, {})
            for idx, reg in enumerate(inv.regs):
                if reg not in taint_at:
                    continue
                param_reg = -(idx + 1)
                new_param.setdefault(callee_sig, {}).setdefault(param_reg, set()).update(taint_at[reg])
            if caller_roots:
                new_reach.setdefault(callee_sig, set()).update(caller_roots)

        if callback_edges and caller_sig in callback_edges:
            offsets_map = callback_reg_offsets.get(caller_sig, {})
            for cb_sig in callback_edges[caller_sig]:
                reg_off = offsets_map.get(cb_sig)
                if reg_off is not None and reg_off in caller_result.reg_taint_at:
                    site_taint = caller_result.reg_taint_at[reg_off]
                elif caller_result.reg_taint_at:
                    max_off = max(caller_result.reg_taint_at.keys())
                    site_taint = caller_result.reg_taint_at.get(max_off, {})
                else:
                    site_taint = {}

                for _reg, tags in site_taint.items():
                    new_param.setdefault(cb_sig, {}).setdefault(-1, set()).update(tags)

                if caller_roots:
                    new_reach.setdefault(cb_sig, set()).update(caller_roots)
                else:
                    new_reach.setdefault(cb_sig, set()).add(caller_sig)

        if caller_roots:
            for inv in invokes:
                callee_sig = inv.target_sig
                if not callee_sig or callee_sig not in sig_to_method:
                    continue
                new_reach.setdefault(callee_sig, set()).update(caller_roots)

    return new_param, new_reach


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


def _merge_reach(
    dest: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]],
    incoming: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]],
) -> bool:
    changed = False
    for sig, roots in incoming.items():
        base = dest.setdefault(sig, set())
        before = set(base)
        base.update(roots)
        if base != before:
            changed = True
    return changed


def _map_param_taint(method, param_taint: Dict[int, Set[TaintTag]]) -> Dict[int, Set[TaintTag]]:
    mapped: Dict[int, Set[TaintTag]] = {}
    if not param_taint:
        return mapped
    try:
        desc = method.get_descriptor()
        code = method.get_code()
        total_regs = code.get_registers_size() if code else 0
        is_static = bool(method.get_access_flags() & 0x0008)
    except Exception:
        return _clone_taint(param_taint)
    slot_count = descriptor_slot_count(desc)
    if not is_static:
        slot_count += 1
    base = max(total_regs - slot_count, 0)
    for neg_reg, tags in param_taint.items():
        if neg_reg >= 0:
            mapped.setdefault(neg_reg, set()).update(tags)
            continue
        idx = abs(neg_reg) - 1
        vreg = base + idx
        mapped.setdefault(vreg, set()).update(tags)
    return mapped


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
        "user_input": {TaintTag.USER_INPUT},
        "provider": {TaintTag.USER_INPUT, TaintTag.SQL},
    }
    return set(mapping.get(category, {TaintTag.OTHER}))


def _all_methods(analysis) -> List[object]:
    return _dex_all_methods(analysis)


def _method_sig(method) -> Tuple[str, str, str]:
    try:
        return method.get_class_name(), method.get_name(), method.get_descriptor()
    except Exception:
        return "<unknown>", "<unknown>", ""
