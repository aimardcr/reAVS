from __future__ import annotations

from core.models import Component
from scanners.intent import IntentInjectionScanner
from tests.helpers.fakes import (
    FakeMethod,
    FakeAPK,
    ins_invoke,
    ins_move_result,
    ins_const_string,
    make_source,
)


def _run(scanner, make_ctx, components, methods, max_depth=0):
    ctx = make_ctx(components, methods=methods, max_depth=max_depth, apk=FakeAPK(package_name="com.test"))
    return scanner.run(ctx)


def test_intent_redirection_positive_and_negative(make_ctx):
    comp = Component(name="com.test.MainActivity", type="activity", exported=True, permission=None, intent_filters=[])
    instructions = [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke("invoke-virtual", ["v0"], "Landroid/app/Activity;", "startActivity", "(Landroid/content/Intent;)V"),
    ]
    source = make_source(["getIntent", "startActivity"])
    method = FakeMethod("Lcom/test/MainActivity;", "onCreate", "()V", instructions, source=source)
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [method])
    assert any(f.id == "INTENT_REDIRECTION" for f in findings)
    finding = next(f for f in findings if f.id == "INTENT_REDIRECTION")
    kinds = {e.kind for e in finding.evidence}
    assert "SOURCE" in kinds and "SINK" in kinds

    negative_method = FakeMethod("Lcom/test/MainActivity;", "onCreate", "()V", [
        ins_invoke("invoke-virtual", ["v1"], "Landroid/app/Activity;", "startActivity", "(Landroid/content/Intent;)V"),
    ])
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [negative_method])
    assert not any(f.id == "INTENT_REDIRECTION" for f in findings)


def test_set_result_tainted_edge(make_ctx):
    comp = Component(name="com.test.ResultActivity", type="activity", exported=True, permission=None, intent_filters=[])
    instructions = [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke(
            "invoke-virtual",
            ["v0", "v1"],
            "Landroid/content/Intent;",
            "getStringExtra",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ),
        ins_move_result("v2"),
        ins_invoke("invoke-direct", ["v3"], "Landroid/content/Intent;", "<init>", "()V"),
        ins_invoke(
            "invoke-virtual",
            ["v3", "v2"],
            "Landroid/content/Intent;",
            "putExtra",
            "(Ljava/lang/String;Ljava/lang/String;)Landroid/content/Intent;",
        ),
        ins_invoke("invoke-virtual", ["p0", "v3"], "Landroid/app/Activity;", "setResult", "(ILandroid/content/Intent;)V"),
    ]
    source = make_source(["getIntent", "getStringExtra", "putExtra", "setResult"])
    method = FakeMethod("Lcom/test/ResultActivity;", "onCreate", "()V", instructions, source=source)
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [method])
    ids = {f.id for f in findings}
    assert "INTENT_TAINTED_RESULT" in ids
    finding = next(f for f in findings if f.id == "INTENT_TAINTED_RESULT")
    kinds = {e.kind for e in finding.evidence}
    assert "SOURCE" in kinds and "SINK" in kinds


def test_arbitrary_file_write_positive_negative_and_helper(make_ctx):
    comp = Component(name="com.test.FileActivity", type="activity", exported=True, permission=None, intent_filters=[])
    base_instructions = [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke(
            "invoke-virtual",
            ["v0", "v1"],
            "Landroid/content/Intent;",
            "getStringExtra",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ),
        ins_move_result("v2"),
        ins_invoke("invoke-direct", ["p0", "v2"], "Lcom/test/FileActivity;", "helperWrite", "(Ljava/lang/String;)V"),
    ]
    helper_instructions = [
        ins_invoke("invoke-virtual", ["p0", "p1"], "Landroid/content/Context;", "openFileOutput", "(Ljava/lang/String;I)Ljava/io/FileOutputStream;"),
    ]
    entry = FakeMethod("Lcom/test/FileActivity;", "onCreate", "()V", base_instructions, source=make_source(["helperWrite"]))
    helper = FakeMethod("Lcom/test/FileActivity;", "helperWrite", "(Ljava/lang/String;)V", helper_instructions)
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [entry, helper], max_depth=2)
    assert any(f.id == "ARBITRARY_FILE_WRITE" for f in findings)
    finding = next(f for f in findings if f.id == "ARBITRARY_FILE_WRITE")
    kinds = {e.kind for e in finding.evidence}
    assert "PROPAGATION" in kinds and "SINK" in kinds

    negative = FakeMethod("Lcom/test/FileActivity;", "onCreate", "()V", [
        ins_invoke("invoke-virtual", ["p0", "v1"], "Landroid/content/Context;", "openFileOutput", "(Ljava/lang/String;I)Ljava/io/FileOutputStream;"),
    ])
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [negative])
    assert not any(f.id == "ARBITRARY_FILE_WRITE" for f in findings)


def test_webview_url_tainted_js_note(make_ctx):
    comp = Component(name="com.test.WebActivity", type="activity", exported=True, permission=None, intent_filters=[])
    instructions = [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke(
            "invoke-virtual",
            ["v0", "v1"],
            "Landroid/content/Intent;",
            "getStringExtra",
            "(Ljava/lang/String;)Ljava/lang/String;",
        ),
        ins_move_result("v2"),
        ins_invoke("invoke-virtual", ["v3", "v2"], "Landroid/webkit/WebView;", "loadUrl", "(Ljava/lang/String;)V"),
        ins_invoke("invoke-virtual", ["v4", "v5"], "Landroid/webkit/WebSettings;", "setJavaScriptEnabled", "(Z)V"),
    ]
    method = FakeMethod("Lcom/test/WebActivity;", "onCreate", "()V", instructions, source=make_source(["loadUrl", "setJavaScriptEnabled"]))
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [method])
    finding = next(f for f in findings if f.id == "WEBVIEW_TAINTED_URL")
    kinds = {e.kind for e in finding.evidence}
    assert "SOURCE" in kinds and "SINK" in kinds and "NOTE" in kinds

    negative = FakeMethod("Lcom/test/WebActivity;", "onCreate", "()V", [
        ins_invoke("invoke-virtual", ["v3", "v4"], "Landroid/webkit/WebView;", "loadUrl", "(Ljava/lang/String;)V"),
    ])
    findings = _run(IntentInjectionScanner(), make_ctx, [comp], [negative])
    assert not any(f.id == "WEBVIEW_TAINTED_URL" for f in findings)
