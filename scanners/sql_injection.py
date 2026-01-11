from __future__ import annotations

from typing import Dict, List, Optional

from core.context import ScanContext
from core.ir import EvidenceStep, Finding, Severity, Confidence, Component
from core.bc_extract import extract_method, InvokeRef
from core.dataflow.taint_linear import TaintTag
from core.dataflow.taint_provider import MethodTaintView
from core.dataflow.dex_queries import all_methods
from core.util.smali_like import find_snippet
from core.util.rules import match_invocation, rule_index, rule_list
from core.util.strings import normalize_component_name
from scanners.base import BaseScanner


class SQLInjectionScanner(BaseScanner):
    name = "sql_injection"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        sink_index = rule_index(ctx.rules, "sinks")
        sql_patterns = rule_list(sink_index, "SQL_EXEC", "methods")
        component_lookup = _component_lookup(ctx.components, _package_name(ctx))

        total = 0
        analyzed = 0
        skipped_external = 0

        for m in all_methods(ctx.analysis):
            total += 1
            comp = _component_for_method(m, component_lookup)
            if ctx.config.component_filter and comp and ctx.config.component_filter not in comp.name:
                continue
            if not hasattr(m, "get_code") or m.get_code() is None:
                skipped_external += 1
                ctx.logger.debug(f"method skipped reason=no_code method={_method_name(m)}")
                continue
            analyzed += 1
            extracted = extract_method(m)
            taint_view = _taint_view(ctx, m, extracted)
            taint_by_offset = taint_view.reg_taint_by_offset

            for inv in extracted.invokes:
                taint_at = taint_by_offset.get(inv.offset, {})
                if _is_sql_sink(inv, sql_patterns) and _has_tainted_arg(inv, taint_at, {TaintTag.URI, TaintTag.INTENT}):
                    finding = _finding_sql_injection(comp, m, inv)
                    findings.append(finding)
                    ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")

            query_param_vregs, param_name_map = _query_param_vregs(m)
            builder_findings = _detect_sql_builder_injection(
                comp,
                m,
                extracted,
                query_param_vregs,
                param_name_map,
                sql_patterns,
            )
            for f in builder_findings:
                findings.append(f)
                ctx.logger.debug(f"finding emitted id={f.id} method={_method_name(m)}")

        ctx.metrics.setdefault("scanner_stats", {})[self.name] = {
            "total": total,
            "analyzed": analyzed,
            "skipped": skipped_external,
            "skipped_no_code": skipped_external,
            "findings": len(findings),
        }
        ctx.logger.debug(
            f"stats name={self.name} methods={total} analyzed={analyzed} "
            f"skipped_no_code={skipped_external} findings={len(findings)}"
        )
        return findings


def _component_lookup(components: List[Component], package_name: Optional[str]) -> Dict[str, Component]:
    lookup: Dict[str, Component] = {}
    for comp in components:
        normalized = normalize_component_name(comp.name)
        if normalized:
            lookup[normalized] = comp
        if package_name:
            alt = _normalize_with_package(comp.name, package_name)
            normalized_alt = normalize_component_name(alt)
            if normalized_alt:
                lookup.setdefault(normalized_alt, comp)
    return lookup


def _package_name(ctx: ScanContext) -> Optional[str]:
    try:
        return ctx.apk.get_package()
    except Exception:
        return None


def _normalize_with_package(name: str, package_name: str) -> str:
    if name.startswith("."):
        return f"{package_name}{name}"
    if "." not in name:
        return f"{package_name}.{name}"
    return name


def _component_for_method(method, lookup: Dict[str, Component]) -> Optional[Component]:
    try:
        cls = normalize_component_name(method.get_class_name())
    except Exception:
        cls = None
    if not cls:
        return None
    return lookup.get(cls)


def _has_tainted_arg(inv: InvokeRef, reg_taint, tags) -> bool:
    for reg in inv.arg_regs:
        if reg in reg_taint and reg_taint[reg] & tags:
            return True
    return False


def _taint_view(ctx: ScanContext, method, extracted) -> MethodTaintView:
    if ctx.taint_provider is None:
        return MethodTaintView(reg_taint_by_offset={})
    return ctx.taint_provider.taint_by_offset(method, extracted)


def _is_sql_sink(inv: InvokeRef, patterns: List[str]) -> bool:
    return match_invocation(inv, patterns)


def _finding_sql_injection(comp: Optional[Component], method, inv: InvokeRef) -> Finding:
    snippet = find_snippet(method, [inv.target_name])
    component_name = comp.name if comp else None
    owner = component_name or _class_name(method)
    return Finding(
        id="SQL_INJECTION",
        title="SQL injection",
        description="SQL queries are influenced by untrusted input without strong validation.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name=component_name,
        entrypoint_method=_method_name(method),
        evidence=[
            EvidenceStep(kind="SOURCE", description="Untrusted input influences SQL arguments", method=_method_name(method)),
            EvidenceStep(kind="SINK", description="rawQuery/execSQL/query call", method=_method_name(method), notes=snippet),
        ],
        recommendation="Use parameterized queries and strict allowlists for selection clauses.",
        references=[],
        fingerprint=f"SQL_INJECTION|{owner}|{_invoke_signature(inv)}",
    )


def _detect_sql_builder_injection(
    comp: Optional[Component],
    method,
    extracted,
    query_param_vregs: set,
    param_name_map: dict,
    sql_patterns: List[str],
) -> List[Finding]:
    sb_regs = {ni.dest_reg for ni in extracted.new_instances if ni.class_desc == "Ljava/lang/StringBuilder;"}
    if not sb_regs:
        return []
    param_tainted = _param_tainted_regs(extracted.moves, query_param_regs={-4, -6} | set(query_param_vregs))
    sb_tainted = set()
    sb_prop_notes = []
    used_params = set()
    tainted_sql_regs = set()  # toString results where builder was tainted
    all_sql_regs = set()  # all toString results regardless of taint
    to_string_notes = {}
    for inv in extracted.invokes:
        if inv.target_class == "Ljava/lang/StringBuilder;" and inv.target_name == "append":
            if len(inv.arg_regs) >= 2:
                sb_reg = inv.arg_regs[0]
                arg_reg = inv.arg_regs[1]
                if sb_reg in sb_regs and (arg_reg in param_tainted or _is_query_param(arg_reg, query_param_vregs)):
                    sb_tainted.add(sb_reg)
                    sb_prop_notes.append(inv.raw)
                    used_params.add(_param_name(arg_reg, param_name_map))
        if inv.target_class == "Ljava/lang/StringBuilder;" and inv.target_name == "toString":
            if inv.arg_regs:
                sb_reg = inv.arg_regs[0]
                if inv.move_result_reg is not None:
                    all_sql_regs.add(inv.move_result_reg)
                    if sb_reg in sb_tainted:
                        tainted_sql_regs.add(inv.move_result_reg)
                    to_string_notes[inv.move_result_reg] = inv.raw
    findings: List[Finding] = []
    component_name = comp.name if comp else None
    owner = component_name or _class_name(method)
    for inv in extracted.invokes:
        if match_invocation(inv, sql_patterns):
            if not inv.arg_regs:
                continue
            sql_reg = inv.arg_regs[1] if len(inv.arg_regs) > 1 else None
            if sql_reg is None:
                continue
            if sql_reg not in tainted_sql_regs and sql_reg not in all_sql_regs:
                continue

            prop_notes = "; ".join(sb_prop_notes)
            if sql_reg in to_string_notes:
                prop_notes = (prop_notes + "; " + to_string_notes[sql_reg]).strip("; ")

            if sql_reg in tainted_sql_regs and used_params:
                confidence = Confidence.HIGH
                evidence = [
                    EvidenceStep(
                        kind="SOURCE",
                        description="Selection/sortOrder parameter used in SQL construction",
                        method=_method_name(method),
                        notes=", ".join(sorted(p for p in used_params if p)),
                    ),
                    EvidenceStep(
                        kind="PROPAGATION",
                        description="StringBuilder.append/toString builds SQL",
                        method=_method_name(method),
                        notes=prop_notes or inv.raw,
                    ),
                ]
            else:
                confidence = Confidence.LOW
                evidence = [
                    EvidenceStep(
                        kind="SOURCE",
                        description="Heuristic: SQL built via string concatenation",
                        method=_method_name(method),
                        notes=prop_notes or inv.raw,
                    ),
                ]

            evidence.append(
                EvidenceStep(
                    kind="SINK",
                    description=f"SQLiteDatabase.{inv.target_name} called with built SQL",
                    method=_method_name(method),
                    notes=inv.raw,
                )
            )
            findings.append(
                Finding(
                    id="SQL_INJECTION",
                    title="SQL injection",
                    description="SQL is built from untrusted or unchecked input and executed via rawQuery/execSQL.",
                    severity=Severity.HIGH,
                    confidence=confidence,
                    component_name=component_name,
                    entrypoint_method=_method_name(method),
                    evidence=evidence,
                    recommendation="Use parameterized queries and strict allowlists for selection clauses.",
                    references=[],
                    fingerprint=f"SQL_INJECTION|{owner}|{_invoke_signature(inv)}",
                )
            )
    return findings


def _is_query_param(reg: int, query_param_vregs: set) -> bool:
    return reg in (-4, -6) or reg in query_param_vregs


def _param_name(reg: int, param_name_map: dict) -> str:
    if reg >= 0:
        return param_name_map.get(reg, "")
    idx = abs(reg) - 1
    if idx == 3:
        return "p3(selection)"
    if idx == 5:
        return "p5(sortOrder)"
    return f"p{idx}"


def _param_tainted_regs(moves: List, query_param_regs: set) -> set:
    param_tainted = set(query_param_regs)
    for mv in moves:
        if mv.src_reg is not None and mv.src_reg in param_tainted and mv.dest_reg is not None:
            param_tainted.add(mv.dest_reg)
    return param_tainted


def _query_param_vregs(method) -> tuple[set, dict]:
    try:
        desc = method.get_descriptor()
        code = method.get_code()
        if not code:
            return set(), {}
        total_regs = code.get_registers_size()
    except Exception:
        return set(), {}

    param_count, param_types = _parse_descriptor_params(desc)
    is_static = False
    try:
        is_static = bool(method.get_access_flags() & 0x0008)
    except Exception:
        is_static = False
    if not is_static:
        param_count += 1
        param_types = ["this"] + param_types

    param_base = max(total_regs - param_count, 0)
    vregs = set()
    name_map = {}
    for idx in (3, 5):
        if idx < len(param_types):
            vreg = param_base + idx
            vregs.add(vreg)
            label = "p3(selection)" if idx == 3 else "p5(sortOrder)"
            name_map[vreg] = label
    return vregs, name_map


def _parse_descriptor_params(desc: str) -> tuple[int, List[str]]:
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


def _invoke_signature(inv: InvokeRef) -> str:
    return f"{inv.target_class}->{inv.target_name}{inv.target_desc}"


def _class_name(method) -> str:
    try:
        return method.get_class_name()
    except Exception:
        return "<unknown>"


def _method_name(method) -> str:
    try:
        return f"{method.get_class_name()}->{method.get_name()}"
    except Exception:
        return "<unknown>"
