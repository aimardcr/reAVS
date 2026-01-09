from __future__ import annotations

from typing import List, Dict

from core.util.smali_like import get_invoked_methods, get_const_strings


def method_has_any_call(method, fragments: List[str]) -> bool:
    invoked = get_invoked_methods(method)
    for call in invoked:
        for frag in fragments:
            if frag in call:
                return True
    return False


def method_find_calls(method, fragments: List[str]) -> List[str]:
    invoked = get_invoked_methods(method)
    matches = []
    for call in invoked:
        for frag in fragments:
            if frag in call:
                matches.append(call)
                break
    return matches


def method_const_strings(method) -> List[str]:
    return get_const_strings(method)


def rules_for_category(rules: Dict[str, List[dict]], key: str, category: str) -> List[dict]:
    items = []
    for rule in rules.get(key, []):
        if rule.get("category") == category:
            items.append(rule)
    return items
