from __future__ import annotations

from core.dataflow.rules_catalog import load_rules
from core.dataflow.taint_cfg import TaintEngine
from core.dataflow.taint_linear import TaintTag
from tests.helpers.fakes import FakeAnalysis, FakeInstruction, FakeMethod, ins_invoke, ins_move_result


def _rules():
    return load_rules({
        "sources": "rules/sources.yml",
        "sinks": "rules/sinks.yml",
        "sanitizers": "rules/sanitizers.yml",
        "policy": "rules/policy.yml",
    })


def test_icfg_return_taint_propagates_to_caller():
    callee_instructions = [
        ins_invoke("invoke-virtual", ["p0"], "Landroid/app/Activity;", "getIntent", "()Landroid/content/Intent;"),
        ins_move_result("v0"),
        ins_invoke("invoke-virtual", ["v0", "v1"], "Landroid/content/Intent;", "getStringExtra", "(Ljava/lang/String;)Ljava/lang/String;"),
        ins_move_result("v2"),
        FakeInstruction("return-object", "v2"),
    ]
    callee = FakeMethod("Lcom/test/Callee;", "getData", "()Ljava/lang/String;", callee_instructions)

    caller_instructions = [
        ins_invoke("invoke-static", [], "Lcom/test/Callee;", "getData", "()Ljava/lang/String;"),
        ins_move_result("v0"),
    ]
    caller = FakeMethod("Lcom/test/Caller;", "call", "()V", caller_instructions)

    analysis = FakeAnalysis([caller, callee])
    engine = TaintEngine(analysis, _rules())
    engine.analyze()

    result = engine.result_for(caller)
    assert result is not None
    taint_at = result.reg_taint_at.get(0, {})
    assert TaintTag.INTENT in taint_at.get(0, set())
