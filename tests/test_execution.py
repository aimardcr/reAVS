from __future__ import annotations

from core.ir import Component
from scanners.code_execution import CodeExecutionScanner
from tests.helpers.fakes import (
    FakeMethod,
    ins_invoke,
    ins_move_result,
    ins_const_string,
    make_source,
)


def _run(scanner, make_ctx, components, methods, max_depth=0):
    ctx = make_ctx(components, methods=methods, max_depth=max_depth)
    return scanner.run(ctx)


def test_dynamic_code_loading_tainted_and_edge(make_ctx):
    comp = Component(name="com.test.Activity", type="activity", exported=True, permission=None, intent_filters=[])
    tainted = [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke("invoke-virtual", ["v0", "v1"], "Landroid/content/Intent;", "getStringExtra", "(Ljava/lang/String;)Ljava/lang/String;"),
        ins_move_result("v2"),
        ins_invoke(
            "invoke-direct",
            ["v3", "v2", "v4", "v5"],
            "Ldalvik/system/DexClassLoader;",
            "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
        ),
    ]
    method = FakeMethod("Lcom/test/Activity;", "onCreate", "()V", tainted, source=make_source(["DexClassLoader"]))
    findings = _run(CodeExecutionScanner(), make_ctx, [comp], [method])
    assert any(f.id == "DYNAMIC_CODE_LOADING" for f in findings)
    finding = next(f for f in findings if f.id == "DYNAMIC_CODE_LOADING")
    assert any(e.kind == "SOURCE" for e in finding.evidence)

    untainted = FakeMethod("Lcom/test/Activity;", "onCreate", "()V", [
        ins_const_string("v0", "/data/local/tmp/classes.dex"),
        ins_invoke(
            "invoke-direct",
            ["v3", "v0", "v4", "v5"],
            "Ldalvik/system/DexClassLoader;",
            "<init>",
            "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/ClassLoader;)V",
        ),
    ])
    findings = _run(CodeExecutionScanner(), make_ctx, [comp], [untainted])
    finding = next(f for f in findings if f.id == "DYNAMIC_CODE_LOADING")
    assert finding.severity.value == "HIGH"


def test_runtime_exec_and_reflection(make_ctx):
    comp = Component(name="com.test.ExecActivity", type="activity", exported=True, permission=None, intent_filters=[])
    instructions = [
        ins_invoke("invoke-virtual", ["v0"], "Ljava/lang/Runtime;", "exec", "(Ljava/lang/String;)Ljava/lang/Process;"),
        ins_invoke("invoke-static", ["v1"], "Ljava/lang/Class;", "forName", "(Ljava/lang/String;)Ljava/lang/Class;"),
    ]
    method = FakeMethod("Lcom/test/ExecActivity;", "onCreate", "()V", instructions)
    findings = _run(CodeExecutionScanner(), make_ctx, [comp], [method])
    ids = {f.id for f in findings}
    assert "CODE_EXECUTION" in ids
    assert "TAINTED_REFLECTION" in ids


def test_js_bridge_helper_detection(make_ctx):
    comp = Component(name="com.test.WebActivity", type="activity", exported=True, permission=None, intent_filters=[])
    entry = FakeMethod("Lcom/test/WebActivity;", "onCreate", "()V", [
        ins_invoke("invoke-direct", ["p0"], "Lcom/test/WebActivity;", "helper", "()V"),
    ])
    helper = FakeMethod("Lcom/test/WebActivity;", "helper", "()V", [
        ins_invoke("invoke-virtual", ["v0"], "Landroid/webkit/WebView;", "addJavascriptInterface", "(Ljava/lang/Object;Ljava/lang/String;)V"),
    ], source=make_source(["addJavascriptInterface"]))
    findings = _run(CodeExecutionScanner(), make_ctx, [comp], [entry, helper], max_depth=2)
    assert any(f.id == "WEBVIEW_JS_BRIDGE" for f in findings)
