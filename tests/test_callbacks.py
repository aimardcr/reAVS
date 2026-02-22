from __future__ import annotations

from core.dataflow.callbacks import is_callback_root, find_onclick_callbacks
from core.dataflow.dex_queries import build_method_index
from core.bytecode.extract import extract_method
from tests.helpers.fakes import FakeMethod, ins_invoke


def test_onclick_is_callback_root():
    m = FakeMethod("Lcom/test/MyClickListener;", "onClick", "(Landroid/view/View;)V")
    assert is_callback_root(m)


def test_activity_oncreate_is_callback_root():
    m = FakeMethod("Lcom/test/MyActivity;", "onCreate", "(Landroid/os/Bundle;)V")
    assert is_callback_root(m)


def test_non_callback_not_root():
    m = FakeMethod("Lcom/test/Helper;", "doWork", "()V")
    assert not is_callback_root(m)


def test_find_onclick_callbacks_wiring(make_ctx):
    # Simulate Activity.onCreate calling setOnClickListener and an onClick method in same class.
    onclick = FakeMethod("Lcom/test/MyActivity;", "onClick", "(Landroid/view/View;)V")
    oncreate = FakeMethod(
        "Lcom/test/MyActivity;",
        "onCreate",
        "(Landroid/os/Bundle;)V",
        instructions=[
            ins_invoke("invoke-virtual", ["v0", "v1"], "Landroid/view/View;", "setOnClickListener", "(Landroid/view/View$OnClickListener;)V"),
        ],
    )
    ctx = make_ctx([], methods=[oncreate, onclick], scan_mode="deep", max_depth=1)
    invokes = extract_method(oncreate).invokes
    method_index = build_method_index(ctx.analysis)
    callbacks = find_onclick_callbacks(oncreate, invokes, method_index)
    assert callbacks and callbacks[0].get_name() == "onClick"


def test_other_user_callbacks_are_roots():
    m_long = FakeMethod("Lcom/test/MyActivity;", "onLongClick", "(Landroid/view/View;)Z")
    m_focus = FakeMethod("Lcom/test/MyActivity;", "onFocusChange", "(Landroid/view/View;Z)V")
    assert is_callback_root(m_long)
    assert is_callback_root(m_focus)
