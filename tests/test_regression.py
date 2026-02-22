from __future__ import annotations

from core.models import Component
from core.cli import print_findings_table
from scanners.intent import IntentInjectionScanner
from tests.helpers.fakes import FakeMethod, ins_invoke, ins_move_result


def test_zero_findings_print_table(capsys):
    print_findings_table([])
    output = capsys.readouterr().out
    assert "Findings: none" in output


def test_component_filter_scoping(make_ctx):
    app = Component(name="com.test.MainActivity", type="activity", exported=True, permission=None, intent_filters=[])
    lib = Component(name="androidx.lib.LibActivity", type="activity", exported=True, permission=None, intent_filters=[])

    app_method = FakeMethod("Lcom/test/MainActivity;", "onCreate", "()V", [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke("invoke-virtual", ["v0"], "Landroid/app/Activity;", "startActivity", "(Landroid/content/Intent;)V"),
    ])
    lib_method = FakeMethod("Landroidx/lib/LibActivity;", "onCreate", "()V", [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke("invoke-virtual", ["v0"], "Landroid/app/Activity;", "startActivity", "(Landroid/content/Intent;)V"),
    ])

    ctx = make_ctx([app, lib], methods=[app_method, lib_method], component_filter="com.test")
    findings = IntentInjectionScanner().run(ctx)
    assert all(f.component_name == "com.test.MainActivity" for f in findings)


def test_stress_many_methods(make_ctx):
    comp = Component(name="com.test.MainActivity", type="activity", exported=True, permission=None, intent_filters=[])
    methods = [FakeMethod("Lcom/test/MainActivity;", f"m{i}", "()V", []) for i in range(200)]
    ctx = make_ctx([comp], methods=methods)
    findings = IntentInjectionScanner().run(ctx)
    assert findings == []
    stats = ctx.metrics.get("scanner_stats", {}).get("intent_injection", {})
    assert stats.get("total") == 200
