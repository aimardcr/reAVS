from __future__ import annotations

from core.ir import Finding, EvidenceStep, Severity, Confidence
import avs
from core.reporting import json_report


def test_fingerprint_deterministic():
    finding = Finding(
        id="SQL_INJECTION",
        title="SQL injection",
        description="desc",
        severity=Severity.HIGH,
        confidence=Confidence.MEDIUM,
        component_name="com.test.Provider",
        entrypoint_method="Lcom/test/Provider;->query",
        evidence=[],
        recommendation="",
        references=[],
    )
    assert json_report._default_fingerprint(finding) == "SQL_INJECTION|com.test.Provider->query|com.test.Provider"


def test_dedup_findings_merges_and_stable_order():
    base = Finding(
        id="CODE_EXECUTION",
        title="Runtime exec",
        description="desc",
        severity=Severity.HIGH,
        confidence=Confidence.LOW,
        component_name="com.test.MainActivity",
        entrypoint_method="Lcom/test/MainActivity;->onCreate",
        evidence=[EvidenceStep(kind="SINK", description="sink", method="Lcom/test/MainActivity;->onCreate")],
        recommendation="",
        references=[],
        fingerprint="CODE_EXECUTION|A|B",
    )
    stronger = Finding(
        id="CODE_EXECUTION",
        title="Runtime exec",
        description="desc",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        component_name="com.test.MainActivity",
        entrypoint_method="Lcom/test/MainActivity;->onCreate",
        evidence=[EvidenceStep(kind="SOURCE", description="source", method="Lcom/test/MainActivity;->onCreate")],
        recommendation="",
        references=[],
        fingerprint="CODE_EXECUTION|A|B",
    )
    merged = avs._dedup_findings([base, stronger])
    assert len(merged) == 1
    assert merged[0].severity.value == "CRITICAL"
    kinds = {e.kind for e in merged[0].evidence}
    assert "SINK" in kinds and "SOURCE" in kinds

    order_one = [f.id for f in avs._sort_findings(merged)]
    order_two = [f.id for f in avs._sort_findings(list(merged))]
    assert order_one == order_two
