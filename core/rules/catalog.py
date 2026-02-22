from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Union

import yaml

_RULES_DIR = Path(__file__).resolve().parent

_DEFAULT_FILES: Dict[str, str] = {
    "sources": "sources.yml",
    "sinks": "sinks.yml",
    "sanitizers": "sanitizers.yml",
    "policy": "policy.yml",
}


class RuleError(Exception):
    pass


def _validate_rules(obj, key: str) -> Union[List[dict], Dict]:
    if key not in obj:
        raise RuleError(f"Missing {key} rules")
    value = obj[key]
    if isinstance(value, list) or isinstance(value, dict):
        return value
    raise RuleError(f"Invalid {key} rules")


def load_rules(paths: Dict[str, str] | None = None) -> Dict[str, object]:
    """Load rule YAML files.

    When *paths* is ``None`` the default YAML files bundled alongside this
    module are loaded automatically.
    """
    if paths is None:
        paths = {name: str(_RULES_DIR / fname) for name, fname in _DEFAULT_FILES.items()}
    rules: Dict[str, object] = {}
    for name, path in paths.items():
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        entries = _validate_rules(data, name)
        rules[name] = entries
    return rules
