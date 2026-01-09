from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple

from core.ir import Component, Finding, Severity, EvidenceStep
from core.util.strings import normalize_component_name, normalize_method_name, fqcn_to_desc


def _severity_order(sev: str) -> int:
    order = {
        "CRITICAL": 0,
        "HIGH": 1,
        "MEDIUM": 2,
        "LOW": 3,
        "INFO": 4,
    }
    return order.get(sev, 99)


def _default_policy() -> Dict:
    return {
        "severity_by_id": {
            "DYNAMIC_CODE_LOADING": "CRITICAL",
            "CODE_EXECUTION": "CRITICAL",
            "UNSAFE_DESERIALIZATION": "CRITICAL",
            "WEBVIEW_JS_BRIDGE": "CRITICAL",
            "NATIVE_LIBRARY_INJECTION": "CRITICAL",
            "INTENT_REDIRECTION": "HIGH",
            "INTENT_TAINTED_RESULT": "HIGH",
            "ARBITRARY_FILE_WRITE": "HIGH",
            "ARBITRARY_FILE_READ": "HIGH",
            "SQL_INJECTION": "HIGH",
            "WEBVIEW_TAINTED_URL": "HIGH",
            "EXPORTED_COMPONENT_WITH_SENSITIVE_ACTION": "HIGH",
            "TAINTED_REFLECTION": "HIGH",
            "PENDING_INTENT_MUTABLE": "LOW",
            "PENDING_INTENT_MISSING_IMMUTABLE": "LOW",
            "HARDCODED_SECRET": "MEDIUM",
            "AES_ECB_MODE": "MEDIUM",
        },
        "severity_basis_by_level": {
            "CRITICAL": "CODE_EXECUTION",
            "HIGH": "INTENT_TAINTED_RESULT",
            "MEDIUM": "CRYPTOGRAPHIC_WEAKNESS",
            "LOW": "BEST_PRACTICE",
            "INFO": "INFORMATIONAL",
        },
        "confidence_basis_by_id": {
            "SQL_INJECTION": "DATAFLOW",
            "ARBITRARY_FILE_READ": "DATAFLOW",
            "INTENT_REDIRECTION": "DATAFLOW",
            "INTENT_TAINTED_RESULT": "DATAFLOW",
            "ARBITRARY_FILE_WRITE": "DATAFLOW",
            "WEBVIEW_TAINTED_URL": "DATAFLOW",
            "DYNAMIC_CODE_LOADING": "DATAFLOW",
            "CODE_EXECUTION": "DATAFLOW",
            "TAINTED_REFLECTION": "DATAFLOW",
            "WEBVIEW_JS_BRIDGE": "DATAFLOW",
            "PENDING_INTENT_MUTABLE": "SIGNATURE",
            "PENDING_INTENT_MISSING_IMMUTABLE": "SIGNATURE",
            "HARDCODED_CRYPTO_KEY": "HEURISTIC",
            "AES_ECB_MODE": "SIGNATURE",
        },
        "cwe_by_id": {
            "SQL_INJECTION": ["CWE-89"],
            "ARBITRARY_FILE_READ": ["CWE-22"],
            "ARBITRARY_FILE_WRITE": ["CWE-22"],
            "WEBVIEW_TAINTED_URL": ["CWE-79"],
            "DYNAMIC_CODE_LOADING": ["CWE-829"],
            "HARDCODED_SECRET": ["CWE-321"],
        },
        "external_surface_ids": {
            "INTENT_REDIRECTION",
            "INTENT_TAINTED_RESULT",
            "ARBITRARY_FILE_WRITE",
            "ARBITRARY_FILE_READ",
            "SQL_INJECTION",
            "WEBVIEW_TAINTED_URL",
            "EXPORTED_COMPONENT_WITH_SENSITIVE_ACTION",
        },
        "crypto_ids": {
            "HARDCODED_SECRET",
            "AES_ECB_MODE",
        },
        "weak_digest_prefix": "WEAK_DIGEST_",
    }


def _merge_policy(policy: Optional[Dict]) -> Dict:
    base = _default_policy()
    if not policy:
        return base
    merged = dict(base)
    for key, value in policy.items():
        if key in ("severity_by_id", "severity_basis_by_level", "confidence_basis_by_id", "cwe_by_id"):
            if isinstance(value, dict):
                merged[key] = dict(base[key])
                merged[key].update(value)
            continue
        if key in ("external_surface_ids", "crypto_ids"):
            if isinstance(value, list):
                merged[key] = set(value)
            elif isinstance(value, set):
                merged[key] = value
            continue
        merged[key] = value
    return merged


def resolve_severity(
    finding: Finding,
    component_exported: Optional[bool],
    policy: Optional[Dict] = None,
) -> Tuple[Severity, str]:
    policy = _merge_policy(policy)
    finding_id = finding.id
    weak_prefix = policy.get("weak_digest_prefix", "WEAK_DIGEST_")
    if finding_id.startswith(weak_prefix):
        severity = Severity.MEDIUM
    else:
        severity_name = policy.get("severity_by_id", {}).get(finding_id, "MEDIUM")
        severity = Severity[severity_name] if severity_name in Severity.__members__ else Severity.MEDIUM

    if _is_crypto_finding(finding_id, policy) and severity in (Severity.CRITICAL, Severity.HIGH):
        severity = Severity.MEDIUM

    if component_exported is False and finding_id in policy.get("external_surface_ids", set()):
        severity = _downgrade_severity(severity)

    _validate_severity_rules(finding, severity, policy)
    severity_basis_map = policy.get("severity_basis_by_level", {})
    severity_basis = severity_basis_map.get(severity.value, "INFORMATIONAL")
    return severity, severity_basis


def _is_crypto_finding(finding_id: str, policy: Dict) -> bool:
    weak_prefix = policy.get("weak_digest_prefix", "WEAK_DIGEST_")
    if finding_id.startswith(weak_prefix):
        return True
    return finding_id in policy.get("crypto_ids", set())


def _downgrade_severity(severity: Severity) -> Severity:
    downgrade = {
        Severity.CRITICAL: Severity.HIGH,
        Severity.HIGH: Severity.MEDIUM,
        Severity.MEDIUM: Severity.LOW,
        Severity.LOW: Severity.INFO,
        Severity.INFO: Severity.INFO,
    }
    return downgrade[severity]


def _validate_severity_rules(finding: Finding, severity: Severity, policy: Dict) -> None:
    if _is_crypto_finding(finding.id, policy):
        assert severity in (Severity.MEDIUM, Severity.LOW, Severity.INFO)
    if severity == Severity.CRITICAL:
        critical_ids = {
            fid
            for fid, sev in policy.get("severity_by_id", {}).items()
            if sev == "CRITICAL"
        }
        assert finding.id in critical_ids
        has_sink = finding.sink_method is not None or any(ev.kind == "SINK" for ev in finding.evidence)
        assert has_sink


def build_json_report(
    androguard_version: str,
    scan_mode: str,
    components: List[Component],
    findings: List[Finding],
    app_info: Optional[Dict] = None,
    policy: Optional[Dict] = None,
) -> Dict:
    timestamp = datetime.now(timezone.utc).isoformat()
    comp_sorted = sorted(components, key=lambda c: (c.type, c.name))
    component_exported = {
        normalize_component_name(c.name): c.exported for c in components if normalize_component_name(c.name)
    }
    resolved = []
    for finding in findings:
        exported = _component_is_exported(finding.component_name, component_exported)
        severity, severity_basis = resolve_severity(finding, exported, policy=policy)
        resolved.append((finding, severity, severity_basis, exported))
    findings_sorted = sorted(
        resolved,
        key=lambda f: (_severity_order(f[1].value), f[0].id, f[0].title),
    )

    severity_counts = {sev.value: 0 for sev in Severity}
    for _, severity, _, _ in resolved:
        severity_counts[severity.value] = severity_counts.get(severity.value, 0) + 1

    exported_count = sum(1 for c in components if c.exported)
    total_components = len(components)
    report = {
        "schema_version": "0.2.0",
        "tool": {
            "name": "AVS",
            "version": "0.1.0",
            "timestamp": timestamp,
            "androguard_version": androguard_version,
            "scan_mode": scan_mode,
        },
        "summary": {
            "exported_components": exported_count,
            "non_exported_components": total_components - exported_count,
            "total_components": total_components,
            "findings_by_severity": severity_counts,
        },
        "attack_surface": {
            "activities": [c.__dict__ for c in comp_sorted if c.type == "activity"],
            "services": [c.__dict__ for c in comp_sorted if c.type == "service"],
            "receivers": [c.__dict__ for c in comp_sorted if c.type == "receiver"],
            "providers": [c.__dict__ for c in comp_sorted if c.type == "provider"],
        },
        "findings": [
            _build_finding_entry(finding, severity, severity_basis, exported, policy=policy)
            for finding, severity, severity_basis, exported in findings_sorted
        ],
    }
    if app_info:
        report["app"] = app_info
    return report


def write_json_report(path: str, report: Dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)


def _build_finding_entry(
    finding: Finding,
    severity: Severity,
    severity_basis: str,
    component_exported: Optional[bool],
    policy: Optional[Dict] = None,
) -> Dict:
    evidence, primary_method, sink_method, related_methods = _normalize_methods(finding)
    component_name, component_desc = _normalize_component_fields(finding.component_name)
    references = _references_for_finding(finding, policy)
    entrypoint_method = normalize_method_name(finding.entrypoint_method)
    primary_method = normalize_method_name(primary_method)
    sink_method = normalize_method_name(sink_method)
    related_methods = _normalize_method_list(related_methods)
    normalized_evidence = _normalize_evidence_methods(evidence)
    fingerprint = _normalize_fingerprint(finding.fingerprint or _default_fingerprint(finding))
    entry = {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": severity.value,
        "severity_basis": severity_basis,
        "confidence": finding.confidence.value,
        "confidence_basis": finding.confidence_basis or _confidence_basis_for_finding(finding, policy),
        "component_name": component_name,
        "entrypoint_method": entrypoint_method,
        "primary_method": primary_method,
        "sink_method": sink_method,
        "related_methods": related_methods,
        "evidence": normalized_evidence,
        "recommendation": finding.recommendation,
        "fingerprint": fingerprint,
    }
    if component_desc:
        entry["component_desc"] = component_desc
    if component_name is None:
        class_name = _owner_from_method(primary_method or entrypoint_method)
        if class_name:
            entry["class_name"] = class_name
    if component_exported is not None:
        entry["component_exported"] = component_exported
    if references:
        entry["references"] = references
    return entry


def _normalize_component_fields(component_name: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
    if not component_name:
        return None, None
    normalized = normalize_component_name(component_name)
    return normalized, normalized


def _component_is_exported(component_name: Optional[str], exported_lookup: Dict[str, bool]) -> Optional[bool]:
    if not component_name:
        return None
    normalized = normalize_component_name(component_name)
    if not normalized:
        return None
    return exported_lookup.get(normalized)


def _normalize_methods(finding: Finding) -> Tuple[List[EvidenceStep], Optional[str], Optional[str], List[str]]:
    evidence = list(finding.evidence)
    primary_method = finding.primary_method
    if primary_method is None:
        methods = [e.method for e in evidence if e.method]
        if finding.entrypoint_method and finding.entrypoint_method in methods:
            primary_method = finding.entrypoint_method
        elif methods:
            primary_method = methods[0]
        else:
            primary_method = finding.entrypoint_method

    if primary_method:
        for idx, ev in enumerate(evidence):
            if ev.method == primary_method:
                if idx != 0:
                    evidence = [ev] + evidence[:idx] + evidence[idx + 1 :]
                break

    sink_method = finding.sink_method
    if sink_method is None:
        for ev in evidence:
            if ev.kind == "SINK" and ev.method:
                sink_method = ev.method
                break

    related_methods = finding.related_methods or _related_methods(evidence, primary_method)
    return evidence, primary_method, sink_method, related_methods


def _related_methods(evidence: List[EvidenceStep], primary_method: Optional[str]) -> List[str]:
    related = []
    seen = set()
    for ev in evidence:
        if not ev.method or ev.method == primary_method:
            continue
        if ev.method in seen:
            continue
        seen.add(ev.method)
        related.append(ev.method)
    return related


def _references_for_finding(finding: Finding, policy: Optional[Dict]) -> List[str]:
    if finding.references:
        return finding.references
    refs = _cwe_refs_for_id(finding.id, policy)
    return refs or []


def _cwe_refs_for_id(finding_id: str, policy: Optional[Dict]) -> List[str]:
    policy = _merge_policy(policy)
    if finding_id.startswith(policy.get("weak_digest_prefix", "WEAK_DIGEST_")):
        return ["CWE-328"]
    return policy.get("cwe_by_id", {}).get(finding_id, [])


def _confidence_basis_for_finding(finding: Finding, policy: Optional[Dict]) -> str:
    policy = _merge_policy(policy)
    if finding.id.startswith(policy.get("weak_digest_prefix", "WEAK_DIGEST_")):
        return "SIGNATURE"
    return policy.get("confidence_basis_by_id", {}).get(finding.id, "HEURISTIC")


def _default_fingerprint(finding: Finding) -> str:
    entrypoint = normalize_method_name(finding.entrypoint_method) or ""
    component = normalize_component_name(finding.component_name) or ""
    return f"{finding.id}|{entrypoint}|{component}"


def _normalize_fingerprint(value: str) -> str:
    parts = value.split("|")
    if not parts:
        return value
    normalized = [parts[0]]
    for part in parts[1:]:
        normalized.append(_normalize_fingerprint_part(part))
    return "|".join(normalized)


def _normalize_fingerprint_part(value: str) -> str:
    if not value:
        return value
    if "->" in value:
        return normalize_method_name(value) or value
    if _looks_desc(value):
        return normalize_component_name(value) or value
    return value


def _looks_desc(value: str) -> bool:
    if value.startswith("["):
        return value.endswith(";") and "L" in value
    return value.startswith("L") and value.endswith(";")


def _owner_from_method(method_name: Optional[str]) -> Optional[str]:
    if not method_name:
        return None
    if "->" in method_name:
        owner = method_name.split("->", 1)[0]
    else:
        owner = method_name
    normalized = normalize_component_name(owner)
    return normalized or None


def _normalize_method_list(methods: List[str]) -> List[str]:
    out = []
    for method in methods:
        normalized = normalize_method_name(method)
        if normalized:
            out.append(normalized)
    return out


def _normalize_evidence_methods(evidence: List[EvidenceStep]) -> List[Dict]:
    normalized = []
    for ev in evidence:
        normalized.append(
            {
                "kind": ev.kind,
                "description": ev.description,
                "method": normalize_method_name(ev.method),
                "notes": ev.notes,
            }
        )
    return normalized
