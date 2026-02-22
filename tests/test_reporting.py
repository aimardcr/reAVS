from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.ir import Component, Finding, EvidenceStep, Severity, Confidence
from core.reporting import json_report
from core.dataflow.rules_catalog import load_rules


def test_json_report_matches_golden():
    fixed = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)

    class FixedDateTime:
        @staticmethod
        def now(tz=None):
            return fixed

    json_report.datetime = FixedDateTime

    components = [
        Component(
            name="com.test.MainActivity",
            type="activity",
            exported=True,
            permission=None,
            intent_filters=[],
        ),
        Component(
            name="com.test.Provider",
            type="provider",
            exported=False,
            permission=None,
            intent_filters=[],
            authority="com.test.provider",
        ),
    ]

    findings = [
        Finding(
            id="DYNAMIC_CODE_LOADING",
            title="Dynamic code loading",
            description="DexClassLoader used with attacker-controlled path.",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            component_name="com.test.MainActivity",
            entrypoint_method="Lcom/test/MainActivity;->onCreate",
            evidence=[
                EvidenceStep(kind="SOURCE", description="Path from Intent", method="Lcom/test/MainActivity;->onCreate"),
                EvidenceStep(kind="SINK", description="DexClassLoader invoked", method="Lcom/test/MainActivity;->onCreate", notes="DexClassLoader"),
            ],
            recommendation="Avoid dynamic loading.",
            references=[],
        ),
        Finding(
            id="AES_ECB_MODE",
            title="Insecure AES/ECB mode",
            description="Cipher uses ECB mode.",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            component_name=None,
            entrypoint_method="Lcom/test/CryptoUtil;->encrypt",
            evidence=[
                EvidenceStep(kind="SINK", description="Cipher.getInstance with ECB", method="Lcom/test/CryptoUtil;->encrypt", notes="AES/ECB"),
            ],
            recommendation="Use AES/GCM.",
            references=[],
        ),
    ]

    policy = load_rules({"policy": "rules/policy.yml"}).get("policy")
    report = json_report.build_json_report("test", "fast", components, findings, policy=policy)

    golden_path = Path("tests/reporting/golden/report.json")
    with golden_path.open("r", encoding="utf-8-sig") as handle:
        golden = json.load(handle)

    assert report == golden
