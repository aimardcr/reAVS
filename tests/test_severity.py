from __future__ import annotations

import pytest

from core.models import Finding, EvidenceStep, Severity, Confidence
from core.reporting.json_report import resolve_severity
from core.rules.catalog import load_rules


def test_resolve_severity_requires_sink_for_critical():
    policy = load_rules().get("policy")
    finding = Finding(
        id="DYNAMIC_CODE_LOADING",
        title="Dynamic code loading",
        description="desc",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        component_name=None,
        entrypoint_method="Lcom/test/Main;->onStart",
        evidence=[EvidenceStep(kind="SOURCE", description="source", method="Lcom/test/Main;->onStart")],
        recommendation="",
        references=[],
    )
    with pytest.raises(AssertionError):
        resolve_severity(finding, component_exported=True, policy=policy)


def test_resolve_severity_downgrades_for_non_exported():
    policy = load_rules().get("policy")
    finding = Finding(
        id="INTENT_REDIRECTION",
        title="Intent redirection",
        description="desc",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name="com.test.MainActivity",
        entrypoint_method="Lcom/test/MainActivity;->onCreate",
        evidence=[EvidenceStep(kind="SINK", description="sink", method="Lcom/test/MainActivity;->onCreate")],
        recommendation="",
        references=[],
    )
    sev, basis = resolve_severity(finding, component_exported=False, policy=policy)
    assert sev.value == "MEDIUM"
    assert basis == "CRYPTOGRAPHIC_WEAKNESS"
