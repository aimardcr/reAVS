from __future__ import annotations

from typing import List


def methods_for_class(dx, class_name: str):
    methods = []
    for m in dx.get_methods():
        try:
            if m.get_method().get_class_name().strip("L;") == class_name or m.get_method().get_class_name().strip("L;") == class_name.replace(".", "/"):
                methods.append(m.get_method())
        except Exception:
            continue
    return methods


def all_methods(dx) -> List[object]:
    out = []
    for m in dx.get_methods():
        try:
            out.append(m.get_method())
        except Exception:
            continue
    return out


def build_method_index(dx) -> dict:
    index = {}
    for m in dx.get_methods():
        try:
            method = m.get_method()
            cls = method.get_class_name()
            name = method.get_name()
            desc = method.get_descriptor()
            index[(cls, name, desc)] = method
        except Exception:
            continue
    return index
