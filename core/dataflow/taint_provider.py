from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Set

from core.bc_extract import ExtractedMethod
from core.dataflow.taint_linear import analyze_method_local_taint, TaintTag
from core.dataflow.taint_cfg import TaintEngine


@dataclass
class MethodTaintView:
    reg_taint_by_offset: Dict[int, Dict[int, Set[TaintTag]]]

    def taint_at(self, offset: int) -> Dict[int, Set[TaintTag]]:
        return self.reg_taint_by_offset.get(offset, {})


class BaseTaintProvider:
    def taint_by_offset(self, method, extracted: ExtractedMethod) -> MethodTaintView:
        raise NotImplementedError


class LinearTaintProvider(BaseTaintProvider):
    def __init__(self, rules: Dict[str, object]) -> None:
        self.rules = rules

    def taint_by_offset(self, method, extracted: ExtractedMethod) -> MethodTaintView:
        state = analyze_method_local_taint(method, extracted, self.rules)
        reg_taint = state.reg_taint
        by_offset: Dict[int, Dict[int, Set[TaintTag]]] = {}
        for inv in extracted.invokes:
            by_offset[inv.offset] = reg_taint
        return MethodTaintView(reg_taint_by_offset=by_offset)


class CfgTaintProvider(BaseTaintProvider):
    def __init__(self, analysis, rules: Dict[str, object]) -> None:
        self.engine = TaintEngine(analysis, rules)

    def taint_by_offset(self, method, extracted: ExtractedMethod) -> MethodTaintView:
        result = self.engine.result_for(method)
        if not result:
            return MethodTaintView(reg_taint_by_offset={})
        return MethodTaintView(reg_taint_by_offset=result.reg_taint_at)
