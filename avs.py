#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys
from typing import List, Dict

import androguard
import xml.etree.ElementTree as ET

try:
    from androguard.core.bytecodes.axml import AXMLPrinter
except Exception:
    AXMLPrinter = None

from core.context import ScanConfig, ScanContext
from core.ir import EvidenceStep, Severity
from core.logging import Logger
from core.loader import load_apk
from core.manifest import get_components
from core.reporting.json_report import build_json_report, write_json_report, resolve_severity
from core.util.strings import normalize_component_name, normalize_method_name
from core.dataflow.rules_catalog import load_rules
from core.dataflow.taint_provider import LinearTaintProvider, CfgTaintProvider
from scanners.intent_injection import IntentInjectionScanner
from scanners.content_provider import ContentProviderScanner
from scanners.code_execution import CodeExecutionScanner
from scanners.cryptography import CryptographyScanner
from scanners.sql_injection import SQLInjectionScanner
from scanners.deeplinks import DeepLinksScanner
from scanners.webview import WebViewScanner


# Changelog: group findings by stable fingerprints and merge evidence to reduce noise.
def _dedup_findings(findings):
    severity_rank = {
        "CRITICAL": 5,
        "HIGH": 4,
        "MEDIUM": 3,
        "LOW": 2,
        "INFO": 1,
    }
    confidence_rank = {
        "HIGH": 3,
        "MEDIUM": 2,
        "LOW": 1,
    }
    grouped = {}
    for finding in findings:
        if not finding.fingerprint:
            finding.fingerprint = _default_fingerprint(finding)
        grouped.setdefault(finding.fingerprint, []).append(finding)

    merged = []
    for bucket in grouped.values():
        base = bucket[0]
        all_evidence = []
        all_methods = [f.entrypoint_method for f in bucket if f.entrypoint_method]
        all_components = [f.component_name for f in bucket if f.component_name]
        base.entrypoint_method = _pick_specific_value(all_methods)
        base.component_name = _pick_specific_value(all_components)
        other_notes = _extra_notes(all_methods, base.entrypoint_method)
        other_notes += _extra_notes(all_components, base.component_name)

        for finding in bucket:
            all_evidence.extend(finding.evidence)
            if severity_rank[finding.severity.value] > severity_rank[base.severity.value]:
                base.severity = finding.severity
            if confidence_rank[finding.confidence.value] > confidence_rank[base.confidence.value]:
                base.confidence = finding.confidence

        for note in other_notes[:5]:
            all_evidence.append(
                EvidenceStep(
                    kind="NOTE",
                    description="Also observed in",
                    notes=note,
                )
            )

        base.evidence = _merge_evidence(all_evidence)
        merged.append(base)
    return _dedup_identical_findings(merged)


def _merge_evidence(evidence):
    by_key = {}
    for ev in evidence:
        key = (ev.kind, ev.method, ev.notes)
        if key not in by_key:
            by_key[key] = ev
    return list(by_key.values())


def _default_fingerprint(finding):
    return f"{finding.id}|{finding.entrypoint_method}|{finding.component_name or ''}"


def _pick_specific_value(values):
    if not values:
        return None
    candidates = [v for v in values if v]
    if not candidates:
        return None
    candidates.sort(key=lambda v: (v == "<unknown>", -len(v)))
    return candidates[0]


def _extra_notes(values, chosen):
    uniques = []
    seen = set()
    for value in values:
        if not value or value == chosen or value in seen:
            continue
        seen.add(value)
        uniques.append(value)
    return uniques


def _evidence_signature(evidence):
    return tuple(sorted((ev.kind, ev.description, ev.method, ev.notes) for ev in evidence))


def _dedup_identical_findings(findings):
    unique = {}
    for finding in findings:
        key = (
            finding.id,
            finding.title,
            finding.description,
            finding.severity.value,
            finding.confidence.value,
            finding.component_name,
            finding.entrypoint_method,
            finding.recommendation,
            tuple(finding.references),
            _evidence_signature(finding.evidence),
        )
        if key not in unique:
            unique[key] = finding
    return list(unique.values())


def parse_args(argv: List[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AVS - Android Vulnerability Scanner")
    parser.add_argument("apk", help="Path to APK file")
    parser.add_argument("--out", help="JSON report output path")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--fast", action="store_true", help="Fast scan (default)")
    mode.add_argument("--deep", action="store_true", help="Deep scan")
    parser.add_argument("--depth", type=int, default=3, help="Helper propagation depth (deep mode)")
    parser.add_argument("--component", help="Scan only a specific component name")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")
    return parser.parse_args(argv)


def main(argv: List[str]) -> int:
    args = parse_args(argv)
    scan_mode = "deep" if args.deep else "fast"
    mode_label = "deep" if args.deep else "shallow"
    logger = Logger(verbose=args.verbose)

    logger.info("AVS v0.1.0")

    rules = load_rules({
        "sources": "rules/sources.yml",
        "sinks": "rules/sinks.yml",
        "sanitizers": "rules/sanitizers.yml",
        "policy": "rules/policy.yml",
    })

    logger.info("loading apk...")

    apk, dex, analysis = load_apk(args.apk)
    components = get_components(apk)
    package_name = apk.get_package() or args.apk

    if args.deep:
        max_depth = args.depth
    else:
        max_depth = 0
        if args.depth != 3:
            logger.warn("depth ignored in fast mode; use --deep to enable helper propagation")
    taint_provider = CfgTaintProvider(analysis, rules) if scan_mode == "deep" else LinearTaintProvider(rules)
    ctx = ScanContext(
        apk_path=args.apk,
        apk=apk,
        analysis=analysis,
        dex=dex,
        components=components,
        config=ScanConfig(
            scan_mode=scan_mode,
            component_filter=args.component,
            verbose=args.verbose,
            max_depth=max_depth,
        ),
        rules=rules,
        androguard_version=getattr(androguard, "__version__", "unknown"),
        logger=logger,
        taint_provider=taint_provider,
    )

    scanners = [
        IntentInjectionScanner(),
        ContentProviderScanner(),
        CodeExecutionScanner(),
        CryptographyScanner(),
        SQLInjectionScanner(),
        DeepLinksScanner(),
        WebViewScanner(),
    ]

    logger.info(f"scan mode={mode_label} package={package_name}")
    logger.info(f"scanners total={len(scanners)}")

    findings = []
    for scanner in scanners:
        try:
            logger.info(f"scanner start name={scanner.name}")
            before = len(findings)
            findings.extend(scanner.run(ctx))
            emitted = len(findings) - before
            logger.info(f"scanner end name={scanner.name} findings={emitted}")
        except Exception as exc:
            logger.warn(f"scanner failed name={scanner.name} error={exc}")

    findings = _dedup_findings(findings)
    _normalize_findings_severity(findings, components, rules.get("policy", {}))
    if args.out:
        app_info = _app_metadata(apk)
        report = build_json_report(
            ctx.androguard_version,
            scan_mode,
            components,
            findings,
            app_info=app_info,
            policy=rules.get("policy", {}),
        )
        write_json_report(args.out, report)

    severity_counts = _severity_counts(findings)
    totals = _aggregate_method_stats(ctx.metrics.get("scanner_stats", {}))
    comp_counts = _component_counts(components)

    # Final summary block for CI-friendly output.
    logger.info(
        "components "
        f"activities={comp_counts.get('activity', 0)} "
        f"services={comp_counts.get('service', 0)} "
        f"receivers={comp_counts.get('receiver', 0)} "
        f"providers={comp_counts.get('provider', 0)}"
    )
    logger.info(
        "methods "
        f"analyzed={totals['analyzed']} skipped={totals['skipped']} "
        f"(no_code={totals['skipped_no_code']})"
    )
    logger.info(
        "findings "
        f"CRITICAL={severity_counts.get('CRITICAL', 0)} "
        f"HIGH={severity_counts.get('HIGH', 0)} "
        f"MEDIUM={severity_counts.get('MEDIUM', 0)} "
        f"LOW={severity_counts.get('LOW', 0)} "
        f"INFO={severity_counts.get('INFO', 0)}"
    )
    logger.success(f"report json={args.out or 'n/a'}")

    print()
    _print_findings_table(findings)

    return 0


def _component_counts(components) -> Dict[str, int]:
    counts = {"activity": 0, "service": 0, "receiver": 0, "provider": 0}
    for comp in components:
        if comp.type in counts:
            counts[comp.type] += 1
    return counts


def _app_metadata(apk) -> Dict[str, object]:
    fields = {}
    getters = {
        "package_name": "get_package",
        "version_name": "get_androidversion_name",
        "version_code": "get_androidversion_code",
        "min_sdk": "get_min_sdk_version",
        "target_sdk": "get_target_sdk_version",
    }
    for key, getter in getters.items():
        value = None
        try:
            value = getattr(apk, getter)()
        except Exception:
            value = None
        if value not in (None, "", "0"):
            fields[key] = value
    return fields


def _severity_counts(findings) -> Dict[str, int]:
    counts = {sev.value: 0 for sev in Severity}
    for finding in findings:
        counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1
    return counts


def _aggregate_method_stats(stats: Dict[str, dict]) -> Dict[str, int]:
    totals = {"analyzed": 0, "skipped": 0, "skipped_no_code": 0}
    for data in stats.values():
        totals["analyzed"] += data.get("analyzed", 0)
        totals["skipped"] += data.get("skipped", 0)
        totals["skipped_no_code"] += data.get("skipped_no_code", 0)
    return totals


def _print_findings_table(findings) -> None:
    if not findings:
        print("Findings: none")
        return

    headers = ["SEVERITY", "ID", "COMPONENT", "ENTRYPOINT"]
    rows = []
    for f in _sort_findings(findings):
        component = normalize_component_name(f.component_name) or "-"
        entrypoint = normalize_method_name(f.entrypoint_method) or "-"
        rows.append([f.severity.value, f.id, component, entrypoint])

    max_widths = [10, 32, 50, 64]
    widths = []
    for idx, header in enumerate(headers):
        max_len = max(len(header), max(len(r[idx]) for r in rows))
        widths.append(min(max_len, max_widths[idx]))

    header_line = "  ".join(_clip(headers[i], widths[i]).ljust(widths[i]) for i in range(len(headers)))
    sep_line = "  ".join("-" * widths[i] for i in range(len(headers)))
    print(header_line)
    print(sep_line)
    for row in rows:
        line = "  ".join(_clip(row[i], widths[i]).ljust(widths[i]) for i in range(len(headers)))
        print(line)


def _clip(value: str, width: int) -> str:
    if len(value) <= width:
        return value
    if width <= 3:
        return value[:width]
    return value[: width - 3] + "..."


def _sort_findings(findings):
    severity_rank = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }
    return sorted(findings, key=lambda f: (severity_rank.get(f.severity.value, 99), f.id, f.title))


def _normalize_findings_severity(findings, components, policy) -> None:
    exported_lookup = {
        normalize_component_name(c.name): c.exported for c in components if normalize_component_name(c.name)
    }
    for finding in findings:
        exported = None
        if finding.component_name:
            normalized = normalize_component_name(finding.component_name)
            if normalized:
                exported = exported_lookup.get(normalized)
        severity, severity_basis = resolve_severity(finding, exported, policy=policy)
        finding.severity = severity
        finding.severity_basis = severity_basis


def _sink_method_from_finding(finding) -> str | None:
    if finding.sink_method:
        return finding.sink_method
    for ev in finding.evidence:
        if ev.kind == "SINK" and ev.method:
            return ev.method
    return None


def _sink_label_from_finding(finding) -> str:
    sink_method = _sink_method_from_finding(finding)
    if sink_method:
        return normalize_method_name(sink_method) or sink_method
    for ev in finding.evidence:
        if ev.kind == "SINK" and ev.notes:
            return _compact_sink_note(ev.notes)
    return "-"


def _compact_sink_note(note: str) -> str:
    compact = note.replace("\n", " ").strip()
    return " ".join(compact.split())


if __name__ == "__main__":
    androguard.util.set_log("CRITICAL")

    raise SystemExit(main(sys.argv[1:]))
