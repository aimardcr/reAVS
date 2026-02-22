from __future__ import annotations

from typing import Dict, List


def simple_class_name(desc: str) -> str:
    if not desc:
        return ""
    desc = desc.strip()
    if "->" in desc:
        desc = desc.split("->", 1)[0]
    if desc.startswith("L"):
        desc = desc[1:]
    if desc.endswith(";"):
        desc = desc[:-1]
    if "/" in desc:
        desc = desc.split("/")[-1]
    return desc


def match_method_pattern(target_class: str, target_name: str, pattern: str) -> bool:
    if not pattern:
        return False
    pattern = pattern.strip()
    if "->" in pattern:
        class_part, name_part = pattern.split("->", 1)
        class_simple = simple_class_name(class_part)
        target_simple = simple_class_name(target_class)
        if class_simple and target_simple and class_simple != target_simple and class_part not in target_class:
            return False
        return target_name == name_part

    if ";" in pattern or "/" in pattern:
        return simple_class_name(target_class) == simple_class_name(pattern) or pattern in target_class

    if pattern[0].isupper():
        return simple_class_name(target_class) == pattern or pattern in target_class

    return target_name == pattern


def match_invocation(inv, patterns: List[str]) -> bool:
    return any(match_method_pattern(inv.target_class, inv.target_name, pat) for pat in patterns)


def rule_index(rules: Dict[str, object], key: str) -> Dict[str, dict]:
    entries = rules.get(key, [])
    if not isinstance(entries, list):
        return {}
    indexed: Dict[str, dict] = {}
    for entry in entries:
        if isinstance(entry, dict) and "id" in entry:
            indexed[entry["id"]] = entry
    return indexed


def rule_list(index: Dict[str, dict], rule_id: str, field: str) -> List[str]:
    entry = index.get(rule_id)
    if not entry:
        return []
    values = entry.get(field, [])
    return values if isinstance(values, list) else []
