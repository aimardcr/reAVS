from __future__ import annotations

from core.bc_extract import extract_method, build_one_hop_call_edges
from core.dataflow.taint_linear import analyze_method_local_taint, TaintTag
from core.dataflow.rules_catalog import load_rules
from core.dataflow.dex_queries import build_method_index
from tests.helpers.fakes import (
    FakeMethod,
    FakeAnalysis,
    ins_invoke,
    ins_move_result,
    ins_const_string,
    ins_const_int,
    ins_new_instance,
    ins_field,
    ins_move,
    make_source,
)


def test_extract_method_collects_ir():
    instructions = [
        ins_const_string("v0", "hello"),
        ins_const_int("v1", 0x10),
        ins_new_instance("v2", "Ljava/lang/StringBuilder;"),
        ins_invoke("invoke-virtual", ["v2"], "Ljava/lang/StringBuilder;", "append", "(Ljava/lang/String;)Ljava/lang/StringBuilder;"),
        ins_move_result("v3"),
        ins_field("sget-object", "v4", "Lcom/test/Crypto;", "IV", "[B"),
        ins_move("move", "v5", "v4"),
    ]
    method = FakeMethod("Lcom/test/Main;", "doWork", "()V", instructions, registers_size=6)
    extracted = extract_method(method)

    assert len(extracted.const_strings) == 1
    assert extracted.const_strings[0].value == "hello"
    assert len(extracted.const_ints) == 1
    assert extracted.const_ints[0].value == 0x10
    assert len(extracted.new_instances) == 1
    assert extracted.new_instances[0].class_desc == "Ljava/lang/StringBuilder;"
    assert len(extracted.invokes) == 1
    assert extracted.invokes[0].move_result_reg == 3
    assert len(extracted.field_refs) == 1
    assert extracted.field_refs[0].owner_class == "Lcom/test/Crypto;"
    assert len(extracted.moves) == 2


def test_build_one_hop_call_edges():
    callee = FakeMethod("Lcom/test/Main;", "helper", "()V", [])
    caller_instructions = [
        ins_invoke("invoke-direct", ["v0"], "Lcom/test/Main;", "helper", "()V"),
    ]
    caller = FakeMethod("Lcom/test/Main;", "entry", "()V", caller_instructions)
    analysis = FakeAnalysis([caller, callee])
    method_index = build_method_index(analysis)
    edges = build_one_hop_call_edges(extract_method(caller).invokes, method_index)
    assert len(edges) == 1
    assert edges[0][1] is callee


def test_local_taint_sources_and_propagation():
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
        ins_invoke("invoke-static", ["v2"], "Landroid/net/Uri;", "parse", "(Ljava/lang/String;)Landroid/net/Uri;"),
        ins_move_result("v3"),
        ins_invoke("invoke-virtual", ["v3"], "Ljava/io/File;", "getPath", "()Ljava/lang/String;"),
    ]
    source = make_source(["getIntent", "getStringExtra", "Uri.parse", "getPath"])
    method = FakeMethod("Lcom/test/Main;", "onCreate", "()V", instructions, source=source)
    extracted = extract_method(method)
    rules = load_rules({"sources": "rules/sources.yml"})
    taint = analyze_method_local_taint(method, extracted, rules)

    assert TaintTag.INTENT in taint.reg_taint.get(0, set())
    assert TaintTag.URI in taint.reg_taint.get(3, set())
    assert any("Uri;->parse" in prop.callee for prop in taint.propagations)


def test_ir_stability_same_input_same_shape():
    instructions = [
        ins_const_string("v0", "alpha"),
        ins_invoke("invoke-virtual", ["v0"], "Ljava/lang/String;", "length", "()I"),
        ins_move_result("v1"),
    ]
    method = FakeMethod("Lcom/test/Main;", "len", "()V", instructions)
    first = extract_method(method)
    second = extract_method(method)
    first_invokes = [(i.opcode, i.target_class, i.target_name, i.target_desc, i.arg_regs, i.move_result_reg) for i in first.invokes]
    second_invokes = [(i.opcode, i.target_class, i.target_name, i.target_desc, i.arg_regs, i.move_result_reg) for i in second.invokes]
    assert first_invokes == second_invokes
    assert [c.value for c in first.const_strings] == [c.value for c in second.const_strings]
