from __future__ import annotations

from typing import List

from core.config import ScanContext
from core.models import Finding, EvidenceStep, Severity, Confidence
from core.bytecode.extract import extract_method, InvokeRef
from core.dataflow.tags import TaintTag
from core.bytecode.smali import find_snippet
from core.rules.matching import match_invocation, rule_index, rule_list
from scanners.base import BaseScanner, methods_for_component, has_tainted_arg, method_name, taint_view


class ContentProviderScanner(BaseScanner):
    name = "content_provider"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        sink_index = rule_index(ctx.rules, "sinks")
        sanitizer_index = rule_index(ctx.rules, "sanitizers")
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
            methods = methods_for_component(ctx, comp.name)
            for m in methods:
                total += 1
                if not hasattr(m, "get_code") or m.get_code() is None:
                    skipped_external += 1
                    ctx.logger.debug(f"method skipped reason=no_code method={method_name(m)}")
                    continue
                analyzed += 1
                extracted = extract_method(m)
                tv = taint_view(ctx, m, extracted)
                taint_by_offset = tv.reg_taint_by_offset
                weak_traversal = any(".." in c.value for c in extracted.const_strings)
                has_canonical = _has_canonicalization(extracted.invokes, canonical_patterns)
                for inv in extracted.invokes:
                    taint_at = taint_by_offset.get(inv.offset, {})
                    if _is_file_open(inv, file_read_patterns, file_write_patterns) and has_tainted_arg(inv, taint_at, {TaintTag.URI, TaintTag.INTENT}):
                        finding = _finding_arbitrary_file(comp, m, inv, extracted, weak_traversal, has_canonical)
                        findings.append(finding)
                        ctx.logger.debug(f"finding emitted id={finding.id} method={method_name(m)}")
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


def _is_file_open(inv: InvokeRef, read_patterns: List[str], write_patterns: List[str]) -> bool:
    return match_invocation(inv, read_patterns) or match_invocation(inv, write_patterns)


def _finding_arbitrary_file(comp, method, inv: InvokeRef, extracted, weak: bool, has_canonical: bool) -> Finding:
    access = _access_mode_for_inv(inv, extracted)
    title = _access_title(access)
    desc = _access_description(access, comp.exported)
    if weak:
        desc += " Detected weak traversal check without canonicalization."
    snippet = find_snippet(method, [inv.target_name])
    evidence = [
        EvidenceStep(kind="SOURCE", description="Uri path/query used in file path", method=method_name(method)),
        EvidenceStep(kind="SINK", description="File opened with tainted path", method=method_name(method), notes=snippet),
    ]
    if weak:
        evidence.append(
            EvidenceStep(
                kind="WEAK_CHECK",
                description="Weak traversal check",
                method=method_name(method),
                notes="Weak traversal check: contains('..')",
            )
        )
    if not has_canonical:
        evidence.append(
            EvidenceStep(
                kind="MISSING_ENFORCEMENT",
                description="Missing canonicalization/base-dir enforcement",
                method=method_name(method),
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
        entrypoint_method=method_name(method),
        evidence=evidence,
        recommendation="Normalize and enforce base directory constraints before opening files.",
        references=[],
        fingerprint=f"ARBITRARY_FILE_READ|{comp.name}|openFile",
    )


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
