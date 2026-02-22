from __future__ import annotations

from typing import Dict, List, Optional, Set

from core.config import ScanContext
from core.models import EvidenceStep, Finding, Severity, Confidence, Component
from core.bytecode.extract import extract_method, InvokeRef
from core.dataflow.tags import TaintTag
from core.dataflow.dex_queries import all_methods
from core.bytecode.smali import find_snippet
from core.rules.matching import match_invocation, rule_index, rule_list
from core.util.strings import normalize_method_name
from core.util.descriptors import parse_descriptor_params
from scanners.base import (
    BaseScanner,
    component_lookup,
    package_name,
    component_for_method,
    has_tainted_arg,
    taint_view,
    reachable_roots,
    method_name,
    invoke_signature,
)

_SQL_TAINT_TAGS: Set[TaintTag] = {
    TaintTag.INTENT,
    TaintTag.URI,
    TaintTag.FILE_PATH,
    TaintTag.URL,
    TaintTag.SQL,
    TaintTag.USER_INPUT,
    TaintTag.OTHER,
}

_LIBRARY_PREFIXES = (
    "Landroidx/",
    "Landroid/",
    "Lcom/google/android/",
    "Lcom/google/firebase/",
    "Lcom/google/ads/",
    "Lcom/facebook/",
    "Lcom/ironsource/",
    "Lio/bidmachine/",
    "Lcom/unity3d/",
    "Lcom/applovin/",
    "Lcom/chartboost/",
    "Lcom/vungle/",
    "Lcom/adcolony/",
    "Lcom/amazon/device/ads/",
    "Lcom/squareup/",
    "Lokhttp3/",
    "Lretrofit2/",
    "Lkotlinx/",
    "Lkotlin/",
    "Ljava/",
    "Ljavax/",
    "Lorg/json/",
    "Lorg/apache/",
)


def _is_library_class(class_name: str) -> bool:
    return any(class_name.startswith(prefix) for prefix in _LIBRARY_PREFIXES)


class SQLInjectionScanner(BaseScanner):
    name = "sql_injection"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        sink_index = rule_index(ctx.rules, "sinks")
        sql_patterns = rule_list(sink_index, "SQL_EXEC", "methods")
        comp_lookup = component_lookup(ctx.components, package_name(ctx))

        total = 0
        analyzed = 0
        skipped_external = 0

        for m in all_methods(ctx.analysis):
            total += 1
            comp = component_for_method(m, comp_lookup)
            if ctx.config.component_filter and comp and ctx.config.component_filter not in comp.name:
                continue
            if not hasattr(m, "get_code") or m.get_code() is None:
                skipped_external += 1
                ctx.logger.debug(f"method skipped reason=no_code method={method_name(m)}")
                continue

            if _is_library_class(_class_name(m)):
                continue

            analyzed += 1
            extracted = extract_method(m)
            tv = taint_view(ctx, m, extracted)
            taint_by_offset = tv.reg_taint_by_offset
            roots = reachable_roots(ctx, m)

            for inv in extracted.invokes:
                taint_at = taint_by_offset.get(inv.offset, {})
                if _is_sql_sink(inv, sql_patterns) and has_tainted_arg(inv, taint_at, _SQL_TAINT_TAGS):
                    finding = _finding_sql_injection(comp, m, inv, roots)
                    findings.append(finding)
                    ctx.logger.debug(f"finding emitted id={finding.id} method={method_name(m)}")

            query_param_vregs, param_name_map = _query_param_vregs(m)
            builder_findings = _detect_sql_builder_injection(
                comp,
                m,
                extracted,
                query_param_vregs,
                param_name_map,
                sql_patterns,
                taint_by_offset,
                roots,
            )
            for f in builder_findings:
                findings.append(f)
                ctx.logger.debug(f"finding emitted id={f.id} method={method_name(m)}")

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


def _is_sql_sink(inv: InvokeRef, patterns: List[str]) -> bool:
    return match_invocation(inv, patterns)


def _finding_sql_injection(comp: Optional[Component], method, inv: InvokeRef, roots: set) -> Finding:
    snippet = find_snippet(method, [inv.target_name])
    component_name = comp.name if comp else None
    owner = component_name or _class_name(method)
    propagation = []
    if roots:
        propagation.append(
            EvidenceStep(
                kind="PROPAGATION",
                description="Reached via callbacks",
                method=method_name(method),
                notes=", ".join(sorted(normalize_method_name(_sig_to_method_name(sig)) or _sig_to_method_name(sig) for sig in roots)),
            )
        )
    evidence = [
        EvidenceStep(kind="SOURCE", description="Untrusted input influences SQL arguments", method=method_name(method)),
        *propagation,
        EvidenceStep(kind="SINK", description="rawQuery/execSQL/query call", method=method_name(method), notes=snippet),
    ]
    confidence = Confidence.HIGH if roots else Confidence.MEDIUM
    return Finding(
        id="SQL_INJECTION",
        title="SQL injection",
        description="SQL queries are influenced by untrusted input without strong validation.",
        severity=Severity.HIGH,
        confidence=confidence,
        component_name=component_name,
        entrypoint_method=method_name(method),
        evidence=evidence,
        recommendation="Use parameterized queries and strict allowlists for selection clauses.",
        references=[],
        fingerprint=f"SQL_INJECTION|{owner}|{invoke_signature(inv)}",
    )


def _detect_sql_builder_injection(
    comp: Optional[Component],
    method,
    extracted,
    query_param_vregs: set,
    param_name_map: dict,
    sql_patterns: List[str],
    taint_by_offset: Dict[int, Dict[int, set]],
    roots: set,
) -> List[Finding]:
    sb_regs = {ni.dest_reg for ni in extracted.new_instances if ni.class_desc == "Ljava/lang/StringBuilder;"}
    if not sb_regs:
        return []
    param_tainted = _param_tainted_regs(extracted.moves, query_param_regs={-4, -6} | set(query_param_vregs))
    sb_tainted = set()
    sb_prop_notes = []
    used_params = set()
    tainted_sql_regs = set()
    to_string_notes = {}
    for inv in extracted.invokes:
        if inv.target_class == "Ljava/lang/StringBuilder;" and inv.target_name == "append":
            if len(inv.arg_regs) >= 2:
                sb_reg = inv.arg_regs[0]
                arg_reg = inv.arg_regs[1]
                taint_at = taint_by_offset.get(inv.offset, {})
                has_real_taint = arg_reg in taint_at and bool(taint_at[arg_reg] & _SQL_TAINT_TAGS)
                arg_tainted = arg_reg in param_tainted or _is_query_param(arg_reg, query_param_vregs) or has_real_taint
                if sb_reg in sb_regs and arg_tainted:
                    sb_tainted.add(sb_reg)
                    sb_prop_notes.append(inv.raw)
                    used_params.add(_param_name(arg_reg, param_name_map))
        if inv.target_class == "Ljava/lang/StringBuilder;" and inv.target_name == "toString":
            if inv.arg_regs:
                sb_reg = inv.arg_regs[0]
                if inv.move_result_reg is not None and sb_reg in sb_tainted:
                    tainted_sql_regs.add(inv.move_result_reg)
                    to_string_notes[inv.move_result_reg] = inv.raw

    if not tainted_sql_regs:
        return []

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
            taint_at = taint_by_offset.get(inv.offset, {})
            arg_has_real_taint = any(
                reg in taint_at and bool(taint_at[reg] & _SQL_TAINT_TAGS) for reg in inv.arg_regs
            )
            if sql_reg not in tainted_sql_regs and not arg_has_real_taint:
                continue

            prop_notes = "; ".join(sb_prop_notes)
            if sql_reg in to_string_notes:
                prop_notes = (prop_notes + "; " + to_string_notes[sql_reg]).strip("; ")

            evidence: List[EvidenceStep] = []
            tainted_path = (sql_reg in tainted_sql_regs and used_params) or arg_has_real_taint
            if tainted_path:
                evidence.append(
                    EvidenceStep(
                        kind="SOURCE",
                        description="Tainted input used in SQL construction",
                        method=method_name(method),
                        notes=", ".join(sorted(p for p in used_params if p)) or prop_notes or inv.raw,
                    )
                )
            else:
                evidence.append(
                    EvidenceStep(
                        kind="SOURCE",
                        description="Heuristic: SQL built via string concatenation",
                        method=method_name(method),
                        notes=prop_notes or inv.raw,
                    )
                )
            evidence.append(
                EvidenceStep(
                    kind="PROPAGATION",
                    description="StringBuilder.append/toString builds SQL",
                    method=method_name(method),
                    notes=prop_notes or inv.raw,
                )
            )
            if roots:
                evidence.append(
                    EvidenceStep(
                        kind="PROPAGATION",
                        description="Reached via callbacks",
                        method=method_name(method),
                        notes=", ".join(sorted(normalize_method_name(_sig_to_method_name(sig)) or _sig_to_method_name(sig) for sig in roots)),
                    )
                )

            confidence = Confidence.HIGH if tainted_path or roots else Confidence.LOW

            evidence.append(
                EvidenceStep(
                    kind="SINK",
                    description=f"SQLiteDatabase.{inv.target_name} called with built SQL",
                    method=method_name(method),
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
                    entrypoint_method=method_name(method),
                    evidence=evidence,
                    recommendation="Use parameterized queries and strict allowlists for selection clauses.",
                    references=[],
                    fingerprint=f"SQL_INJECTION|{owner}|{invoke_signature(inv)}",
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


def _sig_to_method_name(sig: tuple[str, str, str]) -> str:
    cls, name, _ = sig
    return f"{cls}->{name}"


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

    param_count, param_types = parse_descriptor_params(desc)
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


def _class_name(method) -> str:
    try:
        return method.get_class_name()
    except Exception:
        return "<unknown>"
