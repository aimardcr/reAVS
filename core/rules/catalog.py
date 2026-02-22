from __future__ import annotations

from typing import Dict, List, Union
import yaml


class RuleError(Exception):
    pass


def _validate_rules(obj, key: str) -> Union[List[dict], Dict]:
    if key not in obj:
        raise RuleError(f"Missing {key} rules")
    value = obj[key]
    if isinstance(value, list) or isinstance(value, dict):
        return value
    raise RuleError(f"Invalid {key} rules")


def load_rules(paths: Dict[str, str]) -> Dict[str, object]:
    rules: Dict[str, object] = {}
    for name, path in paths.items():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        entries = _validate_rules(data, name)
        rules[name] = entries
    return rules
