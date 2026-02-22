from __future__ import annotations

import re
from typing import List, Optional, Tuple


def get_const_strings(method) -> List[str]:
    strings: List[str] = []
    if not hasattr(method, "get_code"):
        return strings
    code = method.get_code()
    if not code:
        return strings
    bc = code.get_bc()
    for ins in bc.get_instructions():
        name = ins.get_name()
        if name in ("const-string", "const-string/jumbo"):
            try:
                s = ins.get_string()
                if s is not None:
                    strings.append(s)
            except Exception:
                continue
    return strings


def get_invoked_methods(method) -> List[str]:
    called: List[str] = []
    if not hasattr(method, "get_code"):
        return called
    code = method.get_code()
    if not code:
        return called
    bc = code.get_bc()
    for ins in bc.get_instructions():
        if ins.get_name().startswith("invoke-"):
            try:
                called.append(str(ins.get_output()))
            except Exception:
                continue
    return called


def get_invoke_refs(method) -> List[Tuple[str, str, str, str]]:
    refs: List[Tuple[str, str, str, str]] = []
    if not hasattr(method, "get_code"):
        return refs
    code = method.get_code()
    if not code:
        return refs
    bc = code.get_bc()
    for ins in bc.get_instructions():
        if ins.get_name().startswith("invoke-"):
            try:
                out = str(ins.get_output())
            except Exception:
                continue
            cls, name, desc = _parse_invoke_output(out)
            if cls and name:
                refs.append((cls, name, desc, out))
    return refs


_INVOKE_SIG_RE = re.compile(r"(L[^;]+;)->([^\(]+)(\(.*)$")


def parse_invoke_sig(raw: str) -> Optional[Tuple[str, str, str]]:
    """Extract ``(class, method_name, descriptor)`` from an invoke raw output.

    Returns ``None`` when the string cannot be parsed.
    """
    if "->" not in raw:
        return None
    m = _INVOKE_SIG_RE.search(raw)
    if m:
        return m.group(1).strip(), m.group(2).strip(), m.group(3).strip()
    left, right = raw.split("->", 1)
    cls = left.split(",")[-1].strip()
    if " " in cls:
        cls = cls.split()[-1].strip()
    if "(" in right:
        name, desc = right.split("(", 1)
        desc = "(" + desc
    else:
        name, desc = right, ""
    return cls.strip(), name.strip(), desc.strip()


def _parse_invoke_output(output: str) -> Tuple[str, str, str]:
    result = parse_invoke_sig(output)
    if result is None:
        return "", "", ""
    return result


def find_snippet(method, keywords: List[str]) -> str | None:
    if not hasattr(method, "get_source"):
        return None
    try:
        source = method.get_source() or ""
    except Exception:
        return None
    if not source:
        return None
    for line in source.splitlines():
        text = line.strip()
        if not text:
            continue
        for kw in keywords:
            if kw in text:
                return text
    return None


def contains_method_call(invoked: List[str], fragments: List[str]) -> bool:
    for call in invoked:
        for frag in fragments:
            if frag in call:
                return True
    return False


def find_method_calls(invoked: List[str], fragments: List[str]) -> List[str]:
    matches: List[str] = []
    for call in invoked:
        for frag in fragments:
            if frag in call:
                matches.append(call)
                break
    return matches
