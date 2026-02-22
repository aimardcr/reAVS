from __future__ import annotations

from typing import Dict, List, Optional, Set

from core.config import ScanContext
from core.models import Finding


class BaseScanner:
    name = "base"

    def run(self, ctx: ScanContext) -> List[Finding]:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# Shared helpers used across scanner modules
# ---------------------------------------------------------------------------

def method_name(method) -> str:
    try:
        return f"{method.get_class_name()}->{method.get_name()}"
    except Exception:
        return "<unknown>"


def invoke_signature(inv) -> str:
    return f"{inv.target_class}->{inv.target_name}{inv.target_desc}"


def has_tainted_arg(inv, reg_taint: Dict[int, Set[str]], tags: Set[str]) -> bool:
    for reg in inv.arg_regs:
        if reg in reg_taint and (not tags or reg_taint[reg] & tags):
            return True
    return False


def taint_view(ctx: ScanContext, method, extracted):
    from core.dataflow.taint_provider import MethodTaintView

    if ctx.taint_provider is None:
        return MethodTaintView(reg_taint_by_offset={})
    return ctx.taint_provider.taint_by_offset(method, extracted)


def reachable_roots(ctx: ScanContext, method) -> Set:
    provider = ctx.taint_provider
    if provider is None:
        return set()
    roots = getattr(provider, "reachable_roots", None)
    if not roots:
        return set()
    try:
        return set(roots(method))
    except Exception:
        return set()


def normalize_class_name(ctx: ScanContext, name: str) -> str:
    pkg = ctx.apk.get_package()
    if name.startswith("."):
        return f"{pkg}{name}".replace(".", "/")
    if "." not in name and pkg:
        return f"{pkg}.{name}".replace(".", "/")
    return name.replace(".", "/")


def methods_for_component(ctx: ScanContext, comp_name: str) -> list:
    from core.dataflow.dex_queries import methods_for_class

    class_name = normalize_class_name(ctx, comp_name)
    return methods_for_class(ctx.analysis, class_name, include_inner=True)


def package_name(ctx: ScanContext) -> Optional[str]:
    try:
        return ctx.apk.get_package()
    except Exception:
        return None


def component_lookup(components, package_name_str: Optional[str]) -> Dict:
    from core.util.strings import normalize_component_name

    lookup: Dict = {}
    for comp in components:
        normalized = normalize_component_name(comp.name)
        if normalized:
            lookup[normalized] = comp
        if package_name_str:
            alt = _normalize_with_package(comp.name, package_name_str)
            normalized_alt = normalize_component_name(alt)
            if normalized_alt:
                lookup.setdefault(normalized_alt, comp)
    return lookup


def _normalize_with_package(name: str, pkg: str) -> str:
    if name.startswith("."):
        return f"{pkg}{name}"
    if "." not in name:
        return f"{pkg}.{name}"
    return name


def component_for_method(method, lookup: Dict):
    from core.util.strings import normalize_component_name

    try:
        cls = normalize_component_name(method.get_class_name())
    except Exception:
        cls = None
    if not cls:
        return None
    return lookup.get(cls)
