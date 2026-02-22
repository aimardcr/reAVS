from __future__ import annotations

from typing import List, Dict, Set

from core.config import ScanContext
from core.models import Finding, EvidenceStep, Severity, Confidence
from core.bytecode.extract import extract_method, InvokeRef
from core.dataflow.tags import TaintTag
from core.dataflow.taint_provider import MethodTaintView
from core.dataflow.dex_queries import build_method_index
from core.bytecode.smali import find_snippet
from core.rules.matching import match_invocation, rule_index, rule_list
from scanners.base import (
    BaseScanner,
    methods_for_component,
    has_tainted_arg,
    method_name,
    invoke_signature,
    taint_view,
)


class IntentInjectionScanner(BaseScanner):
    name = "intent_injection"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        target_sdk = _get_target_sdk(ctx)
        method_index = build_method_index(ctx.analysis) if ctx.config.max_depth > 0 else {}
        sink_index = rule_index(ctx.rules, "sinks")
        forward_patterns = rule_list(sink_index, "START_COMPONENT", "methods")
        set_result_patterns = rule_list(sink_index, "SET_RESULT", "methods")
        file_write_patterns = rule_list(sink_index, "FILE_WRITE", "methods")
        webview_patterns = rule_list(sink_index, "WEBVIEW_LOAD", "methods")
        pending_patterns = rule_list(sink_index, "PENDING_INTENT", "methods")
        total = 0
        analyzed = 0
        skipped_external = 0

        for comp in ctx.components:
            if ctx.config.component_filter and ctx.config.component_filter not in comp.name:
                continue
            if comp.type not in ("activity", "service", "receiver"):
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

                mutator_notes = _intent_mutator_notes(extracted.invokes, taint_by_offset)
                for inv in extracted.invokes:
                    taint_at = taint_by_offset.get(inv.offset, {})
                    if _is_intent_forward(inv, forward_patterns) and has_tainted_arg(inv, taint_at, {TaintTag.INTENT}):
                        finding = _finding_intent_forward(comp, m, inv, extracted.invokes, forward_patterns)
                        findings.append(finding)
                        _log_match(ctx, finding, m)
                    if _is_set_result(inv, set_result_patterns) and has_tainted_arg(inv, taint_at, {TaintTag.INTENT}):
                        if not _has_tainted_result_intent(inv, taint_at, mutator_notes):
                            continue
                        finding = _finding_set_result(comp, m, inv, mutator_notes)
                        findings.append(finding)
                        _log_match(ctx, finding, m)
                    if _is_file_write(inv, file_write_patterns) and has_tainted_arg(inv, taint_at, {TaintTag.INTENT, TaintTag.URI}):
                        finding = _finding_arbitrary_write(comp, m, inv)
                        findings.append(finding)
                        _log_match(ctx, finding, m)
                    if _is_webview_load(inv, webview_patterns) and has_tainted_arg(inv, taint_at, {TaintTag.INTENT, TaintTag.URI, TaintTag.URL}):
                        js_enabled = _has_js_enabled(extracted.invokes)
                        finding = _finding_webview_url(comp, m, inv, js_enabled)
                        findings.append(finding)
                        _log_match(ctx, finding, m)

                pending = _pending_intent_issue(extracted.invokes, m, target_sdk, pending_patterns)
                if pending:
                    findings.append(pending)
                    _log_match(ctx, pending, m)

                if ctx.config.max_depth > 0:
                    helper_findings = _helper_propagation_findings(
                        ctx,
                        comp,
                        m,
                        extracted.invokes,
                        tv,
                        method_index,
                        max_depth=ctx.config.max_depth,
                        forward_patterns=forward_patterns,
                        set_result_patterns=set_result_patterns,
                        file_write_patterns=file_write_patterns,
                        webview_patterns=webview_patterns,
                    )
                    for f in helper_findings:
                        findings.append(f)
                        _log_match(ctx, f, m)
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


def _get_target_sdk(ctx: ScanContext) -> int:
    try:
        t = ctx.apk.get_target_sdk_version()
        return int(t) if t is not None else 0
    except Exception:
        return 0


def _is_intent_forward(inv: InvokeRef, patterns: List[str]) -> bool:
    return match_invocation(inv, patterns)


def _is_set_result(inv: InvokeRef, patterns: List[str]) -> bool:
    return match_invocation(inv, patterns)


def _is_file_write(inv: InvokeRef, patterns: List[str]) -> bool:
    return match_invocation(inv, patterns)


def _is_webview_load(inv: InvokeRef, patterns: List[str]) -> bool:
    return match_invocation(inv, patterns)


def _has_js_enabled(invokes: List[InvokeRef]) -> bool:
    for inv in invokes:
        if "Landroid/webkit/WebSettings;" in inv.target_class and inv.target_name == "setJavaScriptEnabled":
            return True
    return False


def _pending_intent_issue(invokes: List[InvokeRef], method, target_sdk: int, patterns: List[str]) -> Finding | None:
    if not any(match_invocation(inv, patterns) for inv in invokes):
        return None
    source = ""
    try:
        source = method.get_source() or ""
    except Exception:
        source = ""
    if "FLAG_IMMUTABLE" in source or "33554432" in source:
        return None
    if "FLAG_MUTABLE" in source or "536870912" in source:
        return Finding(
            id="PENDING_INTENT_MUTABLE",
            title="Mutable PendingIntent",
            description="PendingIntent is created with FLAG_MUTABLE, allowing external modification.",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            component_name=None,
            entrypoint_method=method_name(method),
            evidence=[EvidenceStep(kind="SINK", description="PendingIntent created with FLAG_MUTABLE", method=method_name(method))],
            recommendation="Use FLAG_IMMUTABLE unless mutation is required, and validate all inputs.",
            references=["https://developer.android.com/reference/android/app/PendingIntent"],
        )
    if target_sdk >= 31:
        return Finding(
            id="PENDING_INTENT_MISSING_IMMUTABLE",
            title="PendingIntent missing immutability flag",
            description="PendingIntent lacks an explicit immutability flag on Android 12+ targets.",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            component_name=None,
            entrypoint_method=method_name(method),
            evidence=[EvidenceStep(kind="SINK", description="PendingIntent without FLAG_IMMUTABLE", method=method_name(method))],
            recommendation="Specify FLAG_IMMUTABLE for PendingIntent where mutation is not required.",
            references=["https://developer.android.com/about/versions/12/behavior-changes-12#pending-intent-mutability"],
        )
    return None


def _helper_propagation_findings(
    ctx: ScanContext,
    comp,
    caller,
    invokes: List[InvokeRef],
    caller_taint: MethodTaintView,
    method_index: dict,
    max_depth: int,
    forward_patterns: List[str],
    set_result_patterns: List[str],
    file_write_patterns: List[str],
    webview_patterns: List[str],
) -> List[Finding]:
    findings: List[Finding] = []
    caller_class = caller.get_class_name()
    queue = [(caller, invokes, 0)]
    visited = set()

    while queue:
        current_method, current_invokes, depth = queue.pop(0)
        if depth >= max_depth:
            continue
        for inv in current_invokes:
            if not inv.opcode.startswith("invoke-"):
                continue
            if inv.target_class != caller_class:
                continue
            if not inv.opcode.startswith("invoke-direct") and not inv.opcode.startswith("invoke-static"):
                continue
            taint_at = caller_taint.taint_at(inv.offset)
            if not has_tainted_arg(inv, taint_at, {TaintTag.INTENT, TaintTag.URI, TaintTag.URL}):
                continue
            key = (inv.target_class, inv.target_name, inv.target_desc)
            if key in visited:
                continue
            visited.add(key)
            callee = method_index.get(key)
            if not callee:
                continue
            callee_extracted = extract_method(callee)
            findings.extend(
                _helper_sink_findings(
                    comp,
                    caller,
                    callee,
                    inv,
                    callee_extracted.invokes,
                    forward_patterns,
                    set_result_patterns,
                    file_write_patterns,
                    webview_patterns,
                )
            )
            queue.append((callee, callee_extracted.invokes, depth + 1))
    return findings


def _helper_sink_findings(
    comp,
    caller,
    callee,
    inv: InvokeRef,
    callee_invokes: List[InvokeRef],
    forward_patterns: List[str],
    set_result_patterns: List[str],
    file_write_patterns: List[str],
    webview_patterns: List[str],
) -> List[Finding]:
    findings: List[Finding] = []
    for c_inv in callee_invokes:
        if _is_file_write(c_inv, file_write_patterns):
            findings.append(_finding_arbitrary_write_helper(comp, caller, callee, inv, c_inv))
            if _is_intent_forward(c_inv, forward_patterns):
                findings.append(_finding_intent_forward_helper(comp, caller, callee, inv, c_inv, callee_invokes, forward_patterns))
        if _is_set_result(c_inv, set_result_patterns):
            findings.append(_finding_set_result_helper(comp, caller, callee, inv, c_inv))
        if _is_webview_load(c_inv, webview_patterns):
            js_enabled = _has_js_enabled(callee_invokes)
            findings.append(_finding_webview_url_helper(comp, caller, callee, inv, c_inv, js_enabled))
    return findings


def _finding_intent_forward(comp, method, inv: InvokeRef, invokes: List[InvokeRef], forward_patterns: List[str]) -> Finding:
    snippet = _sink_notes_from_invokes(invokes, forward_patterns) or find_snippet(method, [inv.target_name])
    return Finding(
        id="INTENT_REDIRECTION",
        title="Intent redirection/forwarding",
        description="Attacker-controlled Intent is forwarded to another component.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=[
            EvidenceStep(kind="SOURCE", description="Intent read from incoming extras", method=method_name(method)),
            EvidenceStep(kind="SINK", description="Forwarded to startActivity/startService/sendBroadcast", method=method_name(method), notes=snippet),
        ],
        recommendation="Validate or sanitize incoming Intents before forwarding.",
        references=[],
    )


def _finding_set_result(comp, method, inv: InvokeRef, mutator_notes: dict) -> Finding:
    snippet = find_snippet(method, [inv.target_name])
    prop = _mutator_summary(inv, mutator_notes)
    evidence = [
        EvidenceStep(kind="SOURCE", description="Extras read from incoming Intent", method=method_name(method)),
    ]
    if prop:
        evidence.append(
            EvidenceStep(
                kind="PROPAGATION",
                description="Result Intent mutated with tainted values",
                method=method_name(method),
                notes=prop,
            )
        )
    evidence.append(
        EvidenceStep(
            kind="SINK",
            description="setResult called with tainted Intent",
            method=method_name(method),
            notes=snippet,
        )
    )
    return Finding(
        id="INTENT_TAINTED_RESULT",
        title="Tainted setResult data",
        description="Result Intent fields are populated from untrusted extras (result intent injection).",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=evidence,
        recommendation="Only set result fields from trusted inputs or enforce allowlists.",
        references=[],
        fingerprint=f"INTENT_TAINTED_RESULT|{comp.name}|setResult",
    )


def _finding_arbitrary_write(comp, method, inv: InvokeRef) -> Finding:
    snippet = find_snippet(method, ["FileOutputStream", "openFileOutput", "ParcelFileDescriptor;->open"])
    return Finding(
        id="ARBITRARY_FILE_WRITE",
        title="Arbitrary file write via intent",
        description="File path is influenced by Intent extras before write operations.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=[
            EvidenceStep(kind="SOURCE", description="File path from Intent extras", method=method_name(method)),
            EvidenceStep(kind="SINK", description="File output stream opened with tainted path", method=method_name(method), notes=snippet),
        ],
        recommendation="Constrain file paths to an allowed directory and normalize before use.",
        references=[],
        fingerprint=f"ARBITRARY_FILE_WRITE|{comp.name}|{invoke_signature(inv)}",
    )


def _finding_webview_url(comp, method, inv: InvokeRef, js_enabled: bool) -> Finding:
    desc = "Attacker-controlled URL is loaded into WebView."
    if js_enabled:
        desc += " JavaScript appears enabled, increasing impact."
    snippet = find_snippet(method, ["WebView;->loadUrl", "loadUrl"]) or inv.raw
    evidence = [
        EvidenceStep(kind="SOURCE", description="URL read from Intent extras", method=method_name(method)),
        EvidenceStep(kind="SINK", description="WebView.loadUrl called with tainted URL", method=method_name(method), notes=snippet),
    ]
    if js_enabled:
        js_snippet = find_snippet(method, ["setJavaScriptEnabled"])
        evidence.append(
            EvidenceStep(
                kind="NOTE",
                description="WebView JavaScript enabled",
                method=method_name(method),
                notes=js_snippet,
            )
        )
    return Finding(
        id="WEBVIEW_TAINTED_URL",
        title="Tainted URL loaded in WebView",
        description=desc,
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=evidence,
        recommendation="Allowlist trusted domains or strip untrusted URL parameters before loading.",
        references=[],
        fingerprint=f"WEBVIEW_TAINTED_URL|{comp.name}|{invoke_signature(inv)}",
    )


def _finding_arbitrary_write_helper(comp, caller, callee, inv: InvokeRef, sink: InvokeRef) -> Finding:
    sink_snippet = find_snippet(callee, ["FileOutputStream", "openFileOutput", "ParcelFileDescriptor;->open"]) or sink.raw
    return Finding(
        id="ARBITRARY_FILE_WRITE",
        title="Arbitrary file write via intent",
        description="File path is influenced by Intent extras before write operations.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=comp.name,
        entrypoint_method=method_name(caller),
        evidence=[
            EvidenceStep(kind="SOURCE", description="File path from Intent extras", method=method_name(caller)),
            EvidenceStep(kind="PROPAGATION", description="Intent data passed to helper", method=method_name(caller), notes=inv.raw),
            EvidenceStep(kind="SINK", description="File output stream opened in helper", method=method_name(callee), notes=sink_snippet),
        ],
        recommendation="Constrain file paths to an allowed directory and normalize before use.",
        references=[],
        fingerprint=f"ARBITRARY_FILE_WRITE|{comp.name}|{invoke_signature(sink)}",
    )


def _finding_intent_forward_helper(comp, caller, callee, inv: InvokeRef, sink: InvokeRef, callee_invokes: List[InvokeRef], forward_patterns: List[str]) -> Finding:
    sink_snippet = _sink_notes_from_invokes(callee_invokes, forward_patterns) or find_snippet(callee, [sink.target_name]) or sink.raw
    return Finding(
        id="INTENT_REDIRECTION",
        title="Intent redirection/forwarding",
        description="Attacker-controlled Intent is forwarded to another component.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name=comp.name,
        entrypoint_method=method_name(caller),
        evidence=[
            EvidenceStep(kind="SOURCE", description="Intent read from incoming extras", method=method_name(caller)),
            EvidenceStep(kind="PROPAGATION", description="Intent passed to helper", method=method_name(caller), notes=inv.raw),
            EvidenceStep(kind="SINK", description="Forwarded to startActivity/startService/sendBroadcast", method=method_name(callee), notes=sink_snippet),
        ],
        recommendation="Validate or sanitize incoming Intents before forwarding.",
        references=[],
    )


def _finding_set_result_helper(comp, caller, callee, inv: InvokeRef, sink: InvokeRef) -> Finding:
    sink_snippet = find_snippet(callee, [sink.target_name]) or sink.raw
    return Finding(
        id="INTENT_TAINTED_RESULT",
        title="Tainted setResult data",
        description="Result Intent fields are populated from untrusted extras (result intent injection).",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name=comp.name,
        entrypoint_method=method_name(caller),
        evidence=[
            EvidenceStep(kind="SOURCE", description="Extras read from incoming Intent", method=method_name(caller)),
            EvidenceStep(kind="PROPAGATION", description="Result intent built in helper", method=method_name(caller), notes=inv.raw),
            EvidenceStep(kind="SINK", description="setResult called with tainted Intent", method=method_name(callee), notes=sink_snippet),
        ],
        recommendation="Only set result fields from trusted inputs or enforce allowlists.",
        references=[],
        fingerprint=f"INTENT_TAINTED_RESULT|{comp.name}|setResult",
    )


def _finding_webview_url_helper(comp, caller, callee, inv: InvokeRef, sink: InvokeRef, js_enabled: bool) -> Finding:
    desc = "Attacker-controlled URL is loaded into WebView."
    if js_enabled:
        desc += " JavaScript appears enabled, increasing impact."
    sink_snippet = find_snippet(callee, ["WebView;->loadUrl", "loadUrl"]) or sink.raw
    evidence = [
        EvidenceStep(kind="SOURCE", description="URL read from Intent extras", method=method_name(caller)),
        EvidenceStep(kind="PROPAGATION", description="URL passed to helper", method=method_name(caller), notes=inv.raw),
        EvidenceStep(kind="SINK", description="WebView.loadUrl called with tainted URL", method=method_name(callee), notes=sink_snippet),
    ]
    if js_enabled:
        js_snippet = find_snippet(callee, ["setJavaScriptEnabled"])
        evidence.append(
            EvidenceStep(
                kind="NOTE",
                description="WebView JavaScript enabled",
                method=method_name(callee),
                notes=js_snippet,
            )
        )
    return Finding(
        id="WEBVIEW_TAINTED_URL",
        title="Tainted URL loaded in WebView",
        description=desc,
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name=comp.name,
        entrypoint_method=method_name(caller),
        evidence=evidence,
        recommendation="Allowlist trusted domains or strip untrusted URL parameters before loading.",
        references=[],
        fingerprint=f"WEBVIEW_TAINTED_URL|{comp.name}|{invoke_signature(sink)}",
    )


def _sink_notes_from_invokes(invokes: List[InvokeRef], patterns: List[str]) -> str | None:
    notes = []
    seen = set()
    for inv in invokes:
        if not match_invocation(inv, patterns):
            continue
        if inv.raw in seen:
            continue
        seen.add(inv.raw)
        notes.append(inv.raw)
    if not notes:
        return None
    return "; ".join(notes)


def _log_match(ctx: ScanContext, finding: Finding, method) -> None:
    ctx.logger.debug(f"finding emitted id={finding.id} method={method_name(method)}")


def _intent_mutator_notes(invokes: List[InvokeRef], taint_by_offset: Dict[int, Dict[int, Set[TaintTag]]]) -> Dict[int, List[str]]:
    notes: Dict[int, List[str]] = {}
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
    for inv in invokes:
        if inv.target_class != "Landroid/content/Intent;" or inv.target_name not in mutators:
            continue
        if len(inv.arg_regs) < 2:
            continue
        receiver = inv.arg_regs[0]
        taint_at = taint_by_offset.get(inv.offset, {})
        if any(reg in taint_at for reg in inv.arg_regs[1:]):
            notes.setdefault(receiver, []).append(inv.raw)
    return notes


def _has_tainted_result_intent(inv: InvokeRef, taint_at: Dict[int, Set[TaintTag]], mutator_notes: Dict[int, List[str]]) -> bool:
    if len(inv.arg_regs) < 2:
        return False
    for reg in inv.arg_regs[1:]:
        if reg in taint_at and taint_at[reg]:
            if reg in mutator_notes:
                return True
    return False


def _mutator_summary(inv: InvokeRef, mutator_notes: Dict[int, List[str]]) -> str:
    for reg in inv.arg_regs[1:]:
        if reg in mutator_notes:
            return "; ".join(mutator_notes[reg])
    return ""
