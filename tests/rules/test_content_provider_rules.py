from __future__ import annotations

from core.ir import Component
from scanners.content_provider import ContentProviderScanner
from scanners.sql_injection import SQLInjectionScanner
from tests.helpers.fakes import (
    FakeMethod,
    ins_invoke,
    ins_move_result,
    ins_const_string,
    ins_new_instance,
    make_source,
)


def _run(scanner, make_ctx, components, methods):
    ctx = make_ctx(components, methods=methods)
    return scanner.run(ctx)


def test_sql_injection_positive_negative(make_ctx):
    comp = Component(name="com.test.Provider", type="provider", exported=True, permission=None, intent_filters=[])
    instructions = [
        ins_invoke("invoke-virtual", ["p1"], "Landroid/net/Uri;", "getQuery", "()Ljava/lang/String;"),
        ins_move_result("v1"),
        ins_invoke(
            "invoke-virtual",
            ["v0", "v1", "v2"],
            "Landroid/database/sqlite/SQLiteDatabase;",
            "rawQuery",
            "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;",
        ),
    ]
    method = FakeMethod("Lcom/test/Provider;", "query", "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;", instructions)
    findings = _run(SQLInjectionScanner(), make_ctx, [comp], [method])
    assert any(f.id == "SQL_INJECTION" for f in findings)

    negative = FakeMethod("Lcom/test/Provider;", "query", "()V", [
        ins_invoke("invoke-virtual", ["v0", "v1"], "Landroid/database/sqlite/SQLiteDatabase;", "rawQuery", "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;"),
    ])
    findings = _run(SQLInjectionScanner(), make_ctx, [comp], [negative])
    assert not any(f.id == "SQL_INJECTION" for f in findings)


def test_sql_builder_injection_edge(make_ctx):
    comp = Component(name="com.test.Provider", type="provider", exported=True, permission=None, intent_filters=[])
    instructions = [
        ins_new_instance("v0", "Ljava/lang/StringBuilder;"),
        ins_invoke("invoke-direct", ["v0"], "Ljava/lang/StringBuilder;", "<init>", "()V"),
        ins_invoke("invoke-virtual", ["v0", "v3"], "Ljava/lang/StringBuilder;", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;"),
        ins_invoke("invoke-virtual", ["v0"], "Ljava/lang/StringBuilder;", "toString", "()Ljava/lang/String;"),
        ins_move_result("v4"),
        ins_invoke(
            "invoke-virtual",
            ["v1", "v4", "v2"],
            "Landroid/database/sqlite/SQLiteDatabase;",
            "rawQuery",
            "(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;",
        ),
    ]
    method = FakeMethod(
        "Lcom/test/Provider;",
        "query",
        "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;",
        instructions,
        registers_size=6,
    )
    findings = _run(SQLInjectionScanner(), make_ctx, [comp], [method])
    finding = next(f for f in findings if f.id == "SQL_INJECTION")
    kinds = {e.kind for e in finding.evidence}
    assert "PROPAGATION" in kinds and "SINK" in kinds


def test_content_provider_file_traversal_edge(make_ctx):
    comp = Component(name="com.test.Provider", type="provider", exported=True, permission=None, intent_filters=[], authority="com.test")
    instructions = [
        ins_const_string("v0", ".."),
        ins_invoke("invoke-virtual", ["p1"], "Landroid/net/Uri;", "getPath", "()Ljava/lang/String;"),
        ins_move_result("v1"),
        ins_invoke("invoke-virtual", ["v2", "v1"], "Ljava/io/FileInputStream;", "<init>", "(Ljava/lang/String;)V"),
    ]
    method = FakeMethod("Lcom/test/Provider;", "openFile", "(Landroid/net/Uri;Ljava/lang/String;)V", instructions, source=make_source(["openFile"]))
    findings = _run(ContentProviderScanner(), make_ctx, [comp], [method])
    finding = next(f for f in findings if f.id == "ARBITRARY_FILE_READ")
    kinds = {e.kind for e in finding.evidence}
    assert "WEAK_CHECK" in kinds and "MISSING_ENFORCEMENT" in kinds

    with_canonical = FakeMethod("Lcom/test/Provider;", "openFile", "(Landroid/net/Uri;Ljava/lang/String;)V", [
        ins_invoke("invoke-virtual", ["p1"], "Landroid/net/Uri;", "getPath", "()Ljava/lang/String;"),
        ins_move_result("v1"),
        ins_invoke("invoke-virtual", ["v1"], "Ljava/io/File;", "getCanonicalPath", "()Ljava/lang/String;"),
        ins_invoke("invoke-virtual", ["v2", "v1"], "Ljava/io/FileInputStream;", "<init>", "(Ljava/lang/String;)V"),
    ])
    findings = _run(ContentProviderScanner(), make_ctx, [comp], [with_canonical])
    finding = next(f for f in findings if f.id == "ARBITRARY_FILE_READ")
    kinds = {e.kind for e in finding.evidence}
    assert "MISSING_ENFORCEMENT" not in kinds
