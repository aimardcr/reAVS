from __future__ import annotations

from typing import List

from core.config import ScanContext
from core.models import Finding, EvidenceStep, Severity, Confidence
from core.bytecode.extract import extract_method, InvokeRef
from core.dataflow.tags import TaintTag
from core.dataflow.dex_queries import build_method_index
from core.bytecode.smali import find_snippet
from core.rules.matching import match_invocation, rule_index, rule_list
from scanners.base import BaseScanner, methods_for_component, has_tainted_arg, method_name, taint_view


class CodeExecutionScanner(BaseScanner):
    name = "code_execution"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        method_index = build_method_index(ctx.analysis) if ctx.config.max_depth > 0 else {}
        sink_index = rule_index(ctx.rules, "sinks")
        dex_patterns = rule_list(sink_index, "DYNAMIC_CODE_LOADING", "methods")
        exec_patterns = rule_list(sink_index, "CODE_EXECUTION", "methods")
        reflection_patterns = rule_list(sink_index, "REFLECTION_INVOKE", "methods")
        js_bridge_patterns = rule_list(sink_index, "WEBVIEW_JS_BRIDGE", "methods")
        total = 0
        analyzed = 0
        skipped_external = 0
        for comp in ctx.components:
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

                for inv in extracted.invokes:
                    taint_at = taint_by_offset.get(inv.offset, {})
                    if match_invocation(inv, dex_patterns):
                        tainted = has_tainted_arg(inv, taint_at, {TaintTag.INTENT, TaintTag.URI})
                        sev, conf = _normalize_exec_scoring(tainted)
                        finding = _finding_dex_loader(comp, m, inv, sev, conf, tainted)
                        findings.append(finding)
                        ctx.logger.debug(f"finding emitted id={finding.id} method={method_name(m)}")
                    if match_invocation(inv, exec_patterns):
                        tainted = has_tainted_arg(inv, taint_at, {TaintTag.INTENT, TaintTag.URI})
                        sev, conf = _normalize_exec_scoring(tainted)
                        finding = _finding_runtime_exec(comp, m, inv, sev, conf, tainted)
                        findings.append(finding)
                        ctx.logger.debug(f"finding emitted id={finding.id} method={method_name(m)}")
                    if match_invocation(inv, reflection_patterns):
                        tainted = has_tainted_arg(inv, taint_at, {TaintTag.INTENT, TaintTag.URI})
                        sev, conf = _normalize_exec_scoring(tainted)
                        finding = _finding_reflection(comp, m, inv, sev, conf, tainted)
                        findings.append(finding)
                        ctx.logger.debug(f"finding emitted id={finding.id} method={method_name(m)}")

                if _has_js_bridge(extracted.invokes, js_bridge_patterns) or _helper_has_js_bridge(ctx, m, method_index, js_bridge_patterns):
                    finding = _finding_js_bridge(comp, m)
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


def _has_js_bridge(invokes: List[InvokeRef], patterns: List[str]) -> bool:
    return any(match_invocation(inv, patterns) for inv in invokes)


def _finding_dex_loader(
    comp,
    method,
    inv: InvokeRef,
    severity: Severity,
    confidence: Confidence,
    tainted: bool,
) -> Finding:
    snippet = find_snippet(method, ["DexClassLoader", "PathClassLoader"]) or inv.raw
    desc = "DexClassLoader/PathClassLoader used with potentially attacker-controlled path."
    if not tainted:
        desc = "DexClassLoader/PathClassLoader used without confirmed tainted path."
    evidence = []
    if tainted:
        evidence.append(
            EvidenceStep(kind="SOURCE", description="Path read from incoming Intent", method=method_name(method))
        )
        evidence.append(
            EvidenceStep(
                kind="PROPAGATION",
                description="Tainted path passed to class loader",
                method=method_name(method),
                notes=inv.raw,
            )
        )
    evidence.append(
        EvidenceStep(
            kind="SINK",
            description="DexClassLoader/PathClassLoader invoked",
            method=method_name(method),
            notes=snippet,
        )
    )
    return Finding(
        id="DYNAMIC_CODE_LOADING",
        title="Dynamic code loading",
        description=desc,
        severity=severity,
        confidence=confidence,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=evidence,
        recommendation="Avoid dynamic loading from external paths; restrict to internal, verified code.",
        references=[],
    )


def _finding_runtime_exec(
    comp, method, inv: InvokeRef, severity: Severity, confidence: Confidence, tainted: bool
) -> Finding:
    snippet = find_snippet(method, ["Runtime;->exec", "ProcessBuilder"]) or inv.raw
    desc = "Runtime.exec or ProcessBuilder used with input that may be influenced by callers."
    if not tainted:
        desc = "Runtime.exec or ProcessBuilder used without confirmed tainted input."
    return Finding(
        id="CODE_EXECUTION",
        title="Runtime command execution",
        description=desc,
        severity=severity,
        confidence=confidence,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=[EvidenceStep(kind="SINK", description="Runtime.exec/ProcessBuilder call", method=method_name(method), notes=snippet)],
        recommendation="Avoid executing shell commands or strictly validate and allowlist inputs.",
        references=[],
    )


def _finding_reflection(
    comp, method, inv: InvokeRef, severity: Severity, confidence: Confidence, tainted: bool
) -> Finding:
    snippet = find_snippet(method, ["Class;->forName", "ClassLoader;->loadClass", "getMethod", "Method;->invoke"]) or inv.raw
    desc = "Class or method names for reflection are influenced by external input."
    if not tainted:
        desc = "Reflection invocation detected without confirmed tainted input."
    return Finding(
        id="TAINTED_REFLECTION",
        title="Reflection with tainted inputs",
        description=desc,
        severity=severity,
        confidence=confidence,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=[
            EvidenceStep(kind="SOURCE", description="Untrusted input read", method=method_name(method)),
            EvidenceStep(kind="SINK", description="Reflective call invoked", method=method_name(method), notes=snippet),
        ],
        recommendation="Use fixed class/method names and avoid reflection on untrusted values.",
        references=[],
    )


def _finding_js_bridge(comp, method) -> Finding:
    snippet = find_snippet(method, ["addJavascriptInterface"])
    return Finding(
        id="WEBVIEW_JS_BRIDGE",
        title="WebView JavaScript bridge exposed",
        description="addJavascriptInterface exposes Java methods to web content.",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name=comp.name,
        entrypoint_method=method_name(method),
        evidence=[EvidenceStep(kind="SINK", description="addJavascriptInterface used", method=method_name(method), notes=snippet)],
        recommendation="Avoid JavaScript bridges or strictly scope interfaces and load only trusted content.",
        references=[],
    )


def _helper_has_js_bridge(ctx: ScanContext, method, method_index: dict, patterns: List[str]) -> bool:
    if ctx.config.max_depth <= 0:
        return False
    caller_class = method.get_class_name()
    extracted = extract_method(method)
    queue = [(method, extracted.invokes, 0)]
    visited = set()
    while queue:
        current, invokes, depth = queue.pop(0)
        if depth >= ctx.config.max_depth:
            continue
        for inv in invokes:
            if not inv.opcode.startswith("invoke-"):
                continue
            if inv.target_class != caller_class:
                continue
            if not inv.opcode.startswith("invoke-direct") and not inv.opcode.startswith("invoke-static"):
                continue
            key = (inv.target_class, inv.target_name, inv.target_desc)
            if key in visited:
                continue
            visited.add(key)
            callee = method_index.get(key)
            if not callee:
                continue
            callee_extracted = extract_method(callee)
            if _has_js_bridge(callee_extracted.invokes, patterns):
                return True
            queue.append((callee, callee_extracted.invokes, depth + 1))
    return False


def _normalize_exec_scoring(tainted: bool) -> tuple[Severity, Confidence]:
    if tainted:
        return Severity.CRITICAL, Confidence.HIGH
    return Severity.HIGH, Confidence.MEDIUM
