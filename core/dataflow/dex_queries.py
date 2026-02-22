from __future__ import annotations

import logging
from typing import Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)


def _dalvik_class_name(raw: str) -> str:
    """Convert Dalvik class descriptor ``Lcom/foo/Bar;`` to ``com/foo/Bar``."""
    if raw.startswith("L") and raw.endswith(";"):
        return raw[1:-1]
    return raw


def _is_external(method_analysis) -> bool:
    """Return True when MethodAnalysis wraps an ExternalMethod (no bytecode)."""
    try:
        return method_analysis.is_external()
    except Exception:
        return False


def methods_for_class(dx, class_name: str, include_inner: bool = False) -> List[object]:
    """Return concrete methods belonging to *class_name*.

    *class_name* may use dot or slash separators (e.g. ``com.foo.Bar`` or
    ``com/foo/Bar``).  When *include_inner* is True the match extends to
    inner/anonymous classes like ``com/foo/Bar$1``.
    """
    normalized = class_name.replace(".", "/")
    methods: List[object] = []
    for m in dx.get_methods():
        if _is_external(m):
            continue
        try:
            method = m.get_method()
            raw_cls = _dalvik_class_name(method.get_class_name())
            if raw_cls == normalized:
                methods.append(method)
            elif include_inner and raw_cls.startswith(normalized + "$"):
                methods.append(method)
        except AttributeError:
            continue
        except Exception:
            _log.debug("methods_for_class: skipped method in %s", class_name, exc_info=True)
            continue
    return methods


def all_methods(dx) -> List[object]:
    """Return every concrete (non-external) method in the analysis."""
    out: List[object] = []
    for m in dx.get_methods():
        if _is_external(m):
            continue
        try:
            out.append(m.get_method())
        except AttributeError:
            continue
        except Exception:
            _log.debug("all_methods: skipped a method", exc_info=True)
            continue
    return out


def build_method_index(dx) -> Dict[Tuple[str, str, str], object]:
    """Build ``(class, name, descriptor) -> method`` lookup including externals."""
    index: Dict[Tuple[str, str, str], object] = {}
    for m in dx.get_methods():
        try:
            method = m.get_method()
            cls = method.get_class_name()
            name = method.get_name()
            desc = method.get_descriptor()
            index[(cls, name, desc)] = method
        except AttributeError:
            continue
        except Exception:
            _log.debug("build_method_index: skipped a method", exc_info=True)
            continue
    return index
