from __future__ import annotations

from typing import List

from core.context import ScanContext
from core.ir import Finding, EvidenceStep, Severity, Confidence
from core.bc_extract import extract_method, InvokeRef
from core.dataflow.taint_linear import TaintTag
from core.dataflow.taint_provider import MethodTaintView
from core.dataflow.dex_queries import methods_for_class
from core.util.smali_like import find_snippet
from core.util.rules import match_invocation, rule_index, rule_list
from scanners.base import BaseScanner


class ContentProviderScanner(BaseScanner):
    name = "content_provider"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        sink_index = rule_index(ctx.rules, "sinks")
        sanitizer_index = rule_index(ctx.rules, "sanitizers")
        sql_patterns = rule_list(sink_index, "SQL_EXEC", "methods")
        file_read_patterns = rule_list(sink_index, "FILE_READ", "methods")
        file_write_patterns = rule_list(sink_index, "FILE_WRITE", "methods")
        canonical_patterns = rule_list(sanitizer_index, "CANONICALIZE_PATH", "patterns")
        total = 0
        analyzed = 0
        skipped_external = 0
        for comp in ctx.components:
            if comp.type != "provider":
                continue
            if ctx.config.component_filter and ctx.config.component_filter not in comp.name:
                continue
            ctx.logger.debug(f"component start name={comp.name} type={comp.type}")
            methods = _methods_for_component(ctx, comp.name)
            for m in methods:
                total += 1
                if not hasattr(m, "get_code") or m.get_code() is None:
                    skipped_external += 1
                    ctx.logger.debug(f"method skipped reason=no_code method={_method_name(m)}")
                    continue
                analyzed += 1
                extracted = extract_method(m)
                taint_view = _taint_view(ctx, m, extracted)
                taint_by_offset = taint_view.reg_taint_by_offset
                weak_traversal = any(".." in c.value for c in extracted.const_strings)
                has_canonical = _has_canonicalization(extracted.invokes, canonical_patterns)
                for inv in extracted.invokes:
                    taint_at = taint_by_offset.get(inv.offset, {})
                    if _is_sql_sink(inv, sql_patterns) and _has_tainted_arg(inv, taint_at, {TaintTag.URI, TaintTag.INTENT}):
                        finding = _finding_sql_injection(comp, m, inv)
                        findings.append(finding)
                        ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")
                    if _is_file_open(inv, file_read_patterns, file_write_patterns) and _has_tainted_arg(inv, taint_at, {TaintTag.URI, TaintTag.INTENT}):
                        finding = _finding_arbitrary_file(comp, m, inv, extracted, weak_traversal, has_canonical)
                        findings.append(finding)
                        ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")
                query_param_vregs, param_name_map = _query_param_vregs(m)
                sql_findings = _detect_sql_builder_injection(comp, m, extracted, query_param_vregs, param_name_map, sql_patterns)
                for f in sql_findings:
                    ctx.logger.debug(f"finding emitted id={f.id} method={_method_name(m)}")
                findings.extend(sql_findings)
            ctx.logger.debug(f"component end name={comp.name} type={comp.type}")

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


def _methods_for_component(ctx: ScanContext, comp_name: str):
    class_name = _normalize_class_name(ctx, comp_name)
    return methods_for_class(ctx.analysis, class_name)


def _normalize_class_name(ctx: ScanContext, name: str) -> str:
    pkg = ctx.apk.get_package()
    if name.startswith("."):
        return f"{pkg}{name}".replace(".", "/")
    if "." not in name and pkg:
        return f"{pkg}.{name}".replace(".", "/")
    return name.replace(".", "/")


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


def _is_file_open(inv: InvokeRef, read_patterns: List[str], write_patterns: List[str]) -> bool:
    return match_invocation(inv, read_patterns) or match_invocation(inv, write_patterns)


def _finding_sql_injection(comp, method, inv: InvokeRef) -> Finding:
    snippet = find_snippet(method, [inv.target_name])
    return Finding(
        id="SQL_INJECTION",
        title="SQL injection in ContentProvider",
        description="Provider builds SQL from Uri or selection inputs without strong validation.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name=comp.name,
        entrypoint_method=_method_name(method),
        evidence=[
            EvidenceStep(kind="SOURCE", description="Uri-derived input used", method=_method_name(method)),
            EvidenceStep(kind="SINK", description="rawQuery/execSQL/query call", method=_method_name(method), notes=snippet),
        ],
        recommendation="Use parameterized queries and strict allowlists for selection clauses.",
        references=[],
        fingerprint=f"SQL_INJECTION|{comp.name}|{_invoke_signature(inv)}",
    )


def _finding_arbitrary_file(comp, method, inv: InvokeRef, extracted, weak: bool, has_canonical: bool) -> Finding:
    access = _access_mode_for_inv(inv, extracted)
    title = _access_title(access)
    desc = _access_description(access, comp.exported)
    if weak:
        desc += " Detected weak traversal check without canonicalization."
    snippet = find_snippet(method, [inv.target_name])
    evidence = [
        EvidenceStep(kind="SOURCE", description="Uri path/query used in file path", method=_method_name(method)),
        EvidenceStep(kind="SINK", description="File opened with tainted path", method=_method_name(method), notes=snippet),
    ]
    if weak:
        evidence.append(
            EvidenceStep(
                kind="WEAK_CHECK",
                description="Weak traversal check",
                method=_method_name(method),
                notes="Weak traversal check: contains('..')",
            )
        )
    if not has_canonical:
        evidence.append(
            EvidenceStep(
                kind="MISSING_ENFORCEMENT",
                description="Missing canonicalization/base-dir enforcement",
                method=_method_name(method),
                notes="Missing canonicalization/base-dir enforcement",
            )
        )
    return Finding(
        id="ARBITRARY_FILE_READ",
        title=title,
        description=desc,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=comp.name,
        entrypoint_method=_method_name(method),
        evidence=evidence,
        recommendation="Normalize and enforce base directory constraints before opening files.",
        references=[],
        fingerprint=f"ARBITRARY_FILE_READ|{comp.name}|openFile",
    )


def _method_name(method) -> str:
    try:
        return f"{method.get_class_name()}->{method.get_name()}"
    except Exception:
        return "<unknown>"


def _invoke_signature(inv: InvokeRef) -> str:
    return f"{inv.target_class}->{inv.target_name}{inv.target_desc}"


def _has_canonicalization(invokes: List[InvokeRef], patterns: List[str]) -> bool:
    for inv in invokes:
        if match_invocation(inv, patterns):
            return True
    return False


def _access_title(access: str) -> str:
    if access == "read":
        return "Arbitrary file read via ContentProvider"
    if access == "write":
        return "Arbitrary file write via ContentProvider"
    if access == "read-write":
        return "Arbitrary file read/write via ContentProvider"
    return "Arbitrary file access via ContentProvider"


def _access_description(access: str, exported: bool) -> str:
    if access == "read":
        action = "file read"
    elif access == "write":
        action = "file write"
    elif access == "read-write":
        action = "file read/write"
    else:
        action = "file access"
    return f"Uri path influences {action} in ContentProvider."


def _access_mode_for_inv(inv: InvokeRef, extracted) -> str:
    if "FileInputStream" in inv.target_class or ("ContentResolver" in inv.target_class and inv.target_name == "openInputStream"):
        return "read"
    if "Files" in inv.target_class and inv.target_name == "readAllBytes":
        return "read"
    if "FileOutputStream" in inv.target_class or "FileWriter" in inv.target_class:
        return "write"
    if "ContentResolver" in inv.target_class and inv.target_name == "openOutputStream":
        return "write"
    if "Files" in inv.target_class and inv.target_name == "write":
        return "write"
    if "ParcelFileDescriptor" in inv.target_class and inv.target_name == "open":
        flags = _pfd_flags_for_inv(inv, extracted)
        return _classify_pfd_flags(flags)
    return "unknown"


def _pfd_flags_for_inv(inv: InvokeRef, extracted) -> int | None:
    flags_reg = None
    if inv.opcode.startswith("invoke-static"):
        if len(inv.arg_regs) >= 2:
            flags_reg = inv.arg_regs[1]
    else:
        if len(inv.arg_regs) >= 3:
            flags_reg = inv.arg_regs[2]
    if flags_reg is None:
        return None
    const_map = _build_const_int_map(extracted)
    return const_map.get(flags_reg)


def _build_const_int_map(extracted) -> dict:
    const_map = {c.dest_reg: c.value for c in extracted.const_ints}
    for mv in extracted.moves:
        if mv.src_reg in const_map and mv.dest_reg is not None:
            const_map[mv.dest_reg] = const_map[mv.src_reg]
    return const_map


def _classify_pfd_flags(flags: int | None) -> str:
    if flags is None:
        return "unknown"
    mode_read_only = 0x10000000
    mode_write_only = 0x20000000
    mode_read_write = 0x30000000
    mode_create = 0x08000000
    mode_truncate = 0x04000000
    mode_append = 0x02000000
    mode_mask = flags & mode_read_write
    if mode_mask == mode_read_write:
        return "read-write"
    if mode_mask == mode_read_only:
        return "read"
    if mode_mask == mode_write_only or (flags & (mode_create | mode_truncate | mode_append)):
        return "write"
    return "unknown"


def _detect_sql_builder_injection(comp, method, extracted, query_param_vregs: set, param_name_map: dict, sql_patterns: List[str]) -> List[Finding]:
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
                if sb_reg in sb_regs and (arg_reg in param_tainted or _is_query_param(arg_reg, query_param_vregs)):
                    sb_tainted.add(sb_reg)
                    sb_prop_notes.append(inv.raw)
                    used_params.add(_param_name(arg_reg, param_name_map))
        if inv.target_class == "Ljava/lang/StringBuilder;" and inv.target_name == "toString":
            if inv.arg_regs:
                sb_reg = inv.arg_regs[0]
                if sb_reg in sb_tainted and inv.move_result_reg is not None:
                    tainted_sql_regs.add(inv.move_result_reg)
                    to_string_notes[inv.move_result_reg] = inv.raw
    findings: List[Finding] = []
    for inv in extracted.invokes:
        if match_invocation(inv, sql_patterns):
            if not inv.arg_regs:
                continue
            sql_reg = inv.arg_regs[1] if len(inv.arg_regs) > 1 else None
            if sql_reg is None:
                continue
            if sql_reg not in tainted_sql_regs:
                continue
            if not used_params:
                continue
            prop_notes = "; ".join(sb_prop_notes)
            if sql_reg in to_string_notes:
                prop_notes = (prop_notes + "; " + to_string_notes[sql_reg]).strip("; ")
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
                EvidenceStep(
                    kind="SINK",
                    description=f"SQLiteDatabase.{inv.target_name} called with built SQL",
                    method=_method_name(method),
                    notes=inv.raw,
                ),
            ]
            findings.append(
                Finding(
                    id="SQL_INJECTION",
                    title="SQL injection in ContentProvider",
                    description="SQL is built from selection/sortOrder parameter and executed via rawQuery/execSQL.",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    component_name=comp.name,
                    entrypoint_method=_method_name(method),
                    evidence=evidence,
                    recommendation="Use parameterized queries and strict allowlists for selection clauses.",
                    references=[],
                    fingerprint=f"SQL_INJECTION|{comp.name}|{_invoke_signature(inv)}",
                )
            )
    return findings


def _build_const_map(extracted) -> dict:
    const_map = {c.dest_reg: c.value for c in extracted.const_strings}
    for mv in extracted.moves:
        if mv.src_reg in const_map and mv.dest_reg is not None:
            const_map[mv.dest_reg] = const_map[mv.src_reg]
    return const_map


def _is_param_reg(reg: int) -> bool:
    return reg < 0


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
