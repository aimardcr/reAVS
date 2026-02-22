from __future__ import annotations

from core.models import Finding, EvidenceStep, Severity, Confidence, Component
import core.cli as cli
from tests.helpers.fakes import FakeAPK


class DummyScanner:
    name = "dummy"

    def __init__(self, findings):
        self._findings = findings

    def run(self, ctx):
        ctx.logger.debug("dummy scanner invoked")
        ctx.metrics.setdefault("scanner_stats", {})[self.name] = {
            "total": 1,
            "analyzed": 1,
            "skipped": 0,
            "skipped_no_code": 0,
            "findings": len(self._findings),
        }
        return list(self._findings)


def _make_finding():
    return Finding(
        id="DYNAMIC_CODE_LOADING",
        title="Dynamic code loading",
        description="desc",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        component_name="com.test.MainActivity",
        entrypoint_method="Lcom/test/MainActivity;->onCreate",
        evidence=[EvidenceStep(kind="SINK", description="sink", method="Lcom/test/MainActivity;->onCreate")],
        recommendation="",
        references=[],
    )


def test_cli_default_output(monkeypatch, tmp_path, capsys):
    dummy_findings = [_make_finding()]

    def fake_load_apk(path):
        return FakeAPK(package_name="com.test"), object(), object()

    def fake_get_components(apk):
        return [Component(name="com.test.MainActivity", type="activity", exported=True, permission=None, intent_filters=[])]

    def fake_load_rules(paths=None):
        return {}

    monkeypatch.setattr(cli, "load_apk", fake_load_apk)
    monkeypatch.setattr(cli, "get_components", fake_get_components)
    monkeypatch.setattr(cli, "load_rules", fake_load_rules)
    monkeypatch.setattr(cli, "IntentInjectionScanner", lambda: DummyScanner(dummy_findings))
    monkeypatch.setattr(cli, "ContentProviderScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "CodeExecutionScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "CryptographyScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "DeepLinksScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "WebViewScanner", lambda: DummyScanner([]))

    out_path = tmp_path / "report.json"
    assert cli.main(["fake.apk", "--out", str(out_path)]) == 0
    output = capsys.readouterr().out
    assert "components activities=1" in output
    assert "findings CRITICAL=1" in output
    assert "SEV" in output


def test_cli_verbose_output_includes_debug(monkeypatch, capsys):
    dummy_findings = [_make_finding()]

    def fake_load_apk(path):
        return FakeAPK(package_name="com.test"), object(), object()

    def fake_get_components(apk):
        return [Component(name="com.test.MainActivity", type="activity", exported=True, permission=None, intent_filters=[])]

    def fake_load_rules(paths=None):
        return {}

    monkeypatch.setattr(cli, "load_apk", fake_load_apk)
    monkeypatch.setattr(cli, "get_components", fake_get_components)
    monkeypatch.setattr(cli, "load_rules", fake_load_rules)
    monkeypatch.setattr(cli, "IntentInjectionScanner", lambda: DummyScanner(dummy_findings))
    monkeypatch.setattr(cli, "ContentProviderScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "CodeExecutionScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "CryptographyScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "DeepLinksScanner", lambda: DummyScanner([]))
    monkeypatch.setattr(cli, "WebViewScanner", lambda: DummyScanner([]))

    cli.main(["fake.apk", "--verbose"])
    output = capsys.readouterr().out
    assert "[DBG]" in output
    assert "Findings" in output or "SEV" in output
