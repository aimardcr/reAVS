from __future__ import annotations

from typing import List, Optional
import xml.etree.ElementTree as ET

from core.models import Component

try:
    from androguard.core.bytecodes.axml import AXMLPrinter
except Exception:  # pragma: no cover - optional dependency in some environments
    AXMLPrinter = None

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _attr(elem: ET.Element, name: str) -> Optional[str]:
    return elem.get(f"{ANDROID_NS}{name}")


def _parse_intent_filters(comp: ET.Element) -> List[str]:
    summaries: List[str] = []
    for f in _find_children(comp, "intent-filter"):
        parts: List[str] = []
        for action in _find_children(f, "action"):
            name = _attr(action, "name")
            if name:
                parts.append(f"action:{name}")
        for cat in _find_children(f, "category"):
            name = _attr(cat, "name")
            if name:
                parts.append(f"category:{name}")
        for data in _find_children(f, "data"):
            attrs = []
            for key in ["scheme", "host", "path", "pathPrefix", "pathPattern", "mimeType"]:
                val = _attr(data, key)
                if val:
                    attrs.append(f"{key}={val}")
            if attrs:
                parts.append("data:" + ",".join(attrs))
        if parts:
            summaries.append(" | ".join(parts))
    return summaries


def _infer_exported(comp: ET.Element, has_intent_filter: bool) -> bool:
    exported_attr = _attr(comp, "exported")
    if exported_attr is not None:
        return exported_attr.lower() == "true"
    return has_intent_filter


def parse_manifest_element(root: ET.Element) -> List[Component]:
    app = _find_first(root, "application")
    if app is None:
        return []

    components: List[Component] = []
    for tag, ctype in [
        ("activity", "activity"),
        ("service", "service"),
        ("receiver", "receiver"),
        ("provider", "provider"),
    ]:
        for comp in _find_children(app, tag):
            name = _attr(comp, "name") or ""
            intents = _parse_intent_filters(comp)
            exported = _infer_exported(comp, bool(intents))
            permission = _attr(comp, "permission")
            authority = _attr(comp, "authorities") if ctype == "provider" else None
            notes = None
            if ctype == "provider":
                grant_uri = _attr(comp, "grantUriPermissions")
                read_perm = _attr(comp, "readPermission")
                write_perm = _attr(comp, "writePermission")
                notes_parts = []
                if grant_uri:
                    notes_parts.append(f"grantUriPermissions={grant_uri}")
                if read_perm:
                    notes_parts.append(f"readPermission={read_perm}")
                if write_perm:
                    notes_parts.append(f"writePermission={write_perm}")
                if notes_parts:
                    notes = "; ".join(notes_parts)
            components.append(
                Component(
                    name=name,
                    type=ctype,
                    exported=exported,
                    permission=permission,
                    intent_filters=intents,
                    authority=authority,
                    notes=notes,
                )
            )
    return components


def parse_manifest_xml(xml_text: str) -> List[Component]:
    root = ET.fromstring(xml_text)
    return parse_manifest_element(root)


def get_components(apk: object) -> List[Component]:
    xml = apk.get_android_manifest_xml()
    xml_text: str
    try:
        if _looks_like_element(xml):
            return parse_manifest_element(xml)
        if hasattr(xml, "getroot"):
            root = xml.getroot()
            if _looks_like_element(root):
                return parse_manifest_element(root)
    except Exception:
        pass
    try:
        manifest_text = apk.get_manifest()
        if isinstance(manifest_text, str) and manifest_text.strip().startswith("<"):
            return parse_manifest_xml(manifest_text)
    except Exception:
        pass
    if isinstance(xml, bytes):
        xml_text = _decode_manifest_bytes(xml)
    elif hasattr(xml, "decode"):
        xml_text = xml.decode("utf-8", errors="ignore")
    else:
        xml_text = _decode_manifest_bytes(str(xml).encode("utf-8", errors="ignore"))
    try:
        return parse_manifest_xml(xml_text)
    except Exception:
        return []


def _decode_manifest_bytes(data: bytes) -> str:
    if AXMLPrinter is not None:
        try:
            return AXMLPrinter(data).get_xml().decode("utf-8", errors="ignore")
        except Exception:
            pass
    try:
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def _looks_like_element(obj: object) -> bool:
    if obj is None:
        return False
    if not hasattr(obj, "tag"):
        return False
    try:
        list(obj)
    except Exception:
        return False
    return True


def _local_name(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def _find_first(root: ET.Element, name: str) -> Optional[ET.Element]:
    for elem in root.iter():
        if _local_name(elem.tag) == name:
            return elem
    return None


def _find_children(parent: ET.Element, name: str) -> List[ET.Element]:
    out: List[ET.Element] = []
    for child in list(parent):
        if _local_name(child.tag) == name:
            out.append(child)
    return out
