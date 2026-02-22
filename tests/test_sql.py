from __future__ import annotations

from scanners.sql import SQLInjectionScanner
from tests.helpers.fakes import FakeMethod, ins_invoke, ins_move_result


def test_sql_injection_reachable_via_onclick(make_ctx):
    # onClick reads user input and passes to helper; helper executes SQL with arg
    onclick = FakeMethod(
        "Lcom/test/MyActivity;",
        "onClick",
        "(Landroid/view/View;)V",
        instructions=[
            ins_invoke("invoke-virtual", ["v0"], "Landroid/widget/EditText;", "getText", "()Ljava/lang/CharSequence;"),
            ins_move_result("v1"),
            ins_invoke("invoke-static", ["v1"], "Lcom/test/Helper;", "doSql", "(Ljava/lang/CharSequence;)V"),
        ],
    )
    helper = FakeMethod(
        "Lcom/test/Helper;",
        "doSql",
        "(Ljava/lang/CharSequence;)V",
        instructions=[
            ins_invoke(
                "invoke-virtual",
                ["v0", "p0"],
                "Landroid/database/sqlite/SQLiteDatabase;",
                "execSQL",
                "(Ljava/lang/String;)V",
            ),
        ],
        registers_size=2,
    )
    ctx = make_ctx([], methods=[onclick, helper], scan_mode="deep", max_depth=1)
    findings = SQLInjectionScanner().run(ctx)
    finding = next(f for f in findings if f.id == "SQL_INJECTION")
    assert finding.confidence == "HIGH"
    kinds = {e.kind for e in finding.evidence}
    assert "PROPAGATION" in kinds


def test_sql_injection_via_object_getter(make_ctx):
    # onClick builds User from UI text; DBHelper.addUser reads fields and builds SQL.
    onclick = FakeMethod(
        "Lcom/test/MyActivity;",
        "onClick",
        "(Landroid/view/View;)V",
        instructions=[
            ins_invoke("invoke-virtual", ["v0"], "Landroid/widget/EditText;", "getText", "()Ljava/lang/CharSequence;"),
            ins_move_result("v1"),
            ins_invoke("invoke-direct", ["v2", "v1"], "Lcom/test/User;", "<init>", "(Ljava/lang/CharSequence;)V"),
            ins_invoke("invoke-static", ["v2"], "Lcom/test/DBHelper;", "addUser", "(Lcom/test/User;)V"),
        ],
    )
    add_user = FakeMethod(
        "Lcom/test/DBHelper;",
        "addUser",
        "(Lcom/test/User;)V",
        instructions=[
            ins_invoke("invoke-virtual", ["v1"], "Lcom/test/User;", "getPassword", "()Ljava/lang/String;"),
            ins_move_result("v2"),
            ins_invoke(
                "invoke-virtual",
                ["v0", "v2"],
                "Landroid/database/sqlite/SQLiteDatabase;",
                "execSQL",
                "(Ljava/lang/String;)V",
            ),
        ],
        registers_size=3,
    )
    ctx = make_ctx([], methods=[onclick, add_user], scan_mode="deep", max_depth=1)
    findings = SQLInjectionScanner().run(ctx)
    finding = next(f for f in findings if f.id == "SQL_INJECTION")
    assert finding.confidence == "HIGH"
    kinds = {e.kind for e in finding.evidence}
    assert "PROPAGATION" in kinds
