from __future__ import annotations

from typing import List, Dict

from core.context import ScanContext
from core.ir import Finding, EvidenceStep, Severity, Confidence
from core.bc_extract import extract_method, InvokeRef
from core.util.strings import is_base64ish, is_hexish
from core.util.smali_like import find_snippet
from core.dataflow.dex_queries import all_methods
from scanners.base import BaseScanner


class CryptoSecretsScanner(BaseScanner):
    name = "crypto_secrets"

    def run(self, ctx: ScanContext) -> List[Finding]:
        findings: List[Finding] = []
        methods = all_methods(ctx.analysis)
        analyzed_methods = []
        class_iv_usage: Dict[str, bool] = {}
        class_iv_fields: Dict[str, set] = {}
        class_crypto_usage: Dict[str, bool] = {}
        total = 0
        analyzed = 0
        skipped_external = 0
        heuristic_finding: Finding | None = None

        for m in methods:
            total += 1
            if not hasattr(m, "get_code") or m.get_code() is None:
                skipped_external += 1
                ctx.logger.debug(f"method skipped reason=no_code method={_method_name(m)}")
                continue
            analyzed += 1
            extracted = extract_method(m)
            class_name = _class_name(m)
            analyzed_methods.append((m, extracted, class_name))
            if m.get_name() == "<clinit>":
                iv_fields = _extract_iv_fields_from_clinit(class_name, m, extracted)
                if iv_fields:
                    class_iv_fields[class_name] = iv_fields

            if any("IvParameterSpec" in inv.target_class for inv in extracted.invokes):
                class_iv_usage[class_name] = True

            if _has_crypto_context(extracted):
                class_crypto_usage[class_name] = True

        for m, extracted, class_name in analyzed_methods:
            if _is_system_class(class_name):
                continue
            key_info = _detect_hardcoded_key(extracted)
            if key_info:
                if key_info["confirmed"]:
                    finding = _finding_hardcoded_key(m, key_info["key"], True)
                    findings.append(finding)
                    ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")
                else:
                    if not class_crypto_usage.get(class_name, False):
                        continue
                    candidate = _finding_hardcoded_key(m, key_info["key"], False)
                    if heuristic_finding is None:
                        heuristic_finding = candidate
                    else:
                        heuristic_finding.evidence.append(
                            EvidenceStep(
                                kind="NOTE",
                                description="Also observed in",
                                notes=_method_name(m),
                            )
                        )

            if _has_ecb_mode(extracted.const_strings):
                finding = _finding_ecb(m)
                findings.append(finding)
                ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")

            if _has_weak_digest(extracted, "MD5"):
                finding = _finding_weak_digest(m, "MD5")
                findings.append(finding)
                ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")

            if _has_weak_digest(extracted, "SHA-1"):
                finding = _finding_weak_digest(m, "SHA-1")
                findings.append(finding)
                ctx.logger.debug(f"finding emitted id={finding.id} method={_method_name(m)}")

        if heuristic_finding is not None:
            findings.append(heuristic_finding)

        for class_name, has_iv in class_iv_usage.items():
            if _is_system_class(class_name):
                continue
            if has_iv:
                iv_fields = class_iv_fields.get(class_name, set())
                findings.extend(_detect_hardcoded_iv(class_name, methods, iv_fields))

        ctx.metrics.setdefault("scanner_stats", {})[self.name] = {
            "total": total,
            "analyzed": analyzed,
            "skipped": skipped_external,
            "skipped_no_code": skipped_external,
            "findings": len(findings),
        }
        ctx.logger.debug(
            f"stats name={self.name} methods={total} analyzed={analyzed} "
            f"skipped_no_code={skipped_external} findings={len(findings)}"
        )
        return findings


def _detect_hardcoded_key(extracted) -> dict | None:
    const_map = {c.dest_reg: c.value for c in extracted.const_strings}
    for mv in extracted.moves:
        if mv.src_reg in const_map and mv.dest_reg is not None:
            const_map[mv.dest_reg] = const_map[mv.src_reg]

    base64_consts = [v for v in const_map.values() if is_base64ish(v)]
    secret_keyspec_used = any("SecretKeySpec" in inv.target_class for inv in extracted.invokes)
    key_bytes_from_const = {}

    for inv in extracted.invokes:
        if inv.target_class == "Landroid/util/Base64;" and inv.target_name == "decode":
            if inv.arg_regs and inv.move_result_reg is not None:
                arg = inv.arg_regs[0]
                if arg in const_map and _looks_key_material(const_map[arg]):
                    key_bytes_from_const[inv.move_result_reg] = const_map[arg]
        if inv.target_class == "Ljava/lang/String;" and inv.target_name == "getBytes":
            if inv.arg_regs and inv.move_result_reg is not None:
                arg = inv.arg_regs[0]
                if arg in const_map and _looks_key_material(const_map[arg]):
                    key_bytes_from_const[inv.move_result_reg] = const_map[arg]

    for inv in extracted.invokes:
        if inv.target_class == "Ljavax/crypto/spec/SecretKeySpec;" and inv.target_name == "<init>":
            if len(inv.arg_regs) >= 2:
                key_reg = inv.arg_regs[1]
                if key_reg in key_bytes_from_const:
                    return {"confirmed": True, "key": key_bytes_from_const[key_reg]}

    if not secret_keyspec_used and base64_consts:
        return {"confirmed": False, "key": base64_consts[0]}
    return None


def _has_ecb_mode(consts) -> bool:
    return any("/ECB/" in c.value for c in consts)


def _has_weak_digest(extracted, algo: str) -> bool:
    const_map = {c.dest_reg: c.value for c in extracted.const_strings}
    for mv in extracted.moves:
        if mv.src_reg in const_map and mv.dest_reg is not None:
            const_map[mv.dest_reg] = const_map[mv.src_reg]

    for inv in extracted.invokes:
        if inv.target_class == "Ljava/security/MessageDigest;" and inv.target_name == "getInstance":
            if inv.arg_regs and inv.arg_regs[0] in const_map:
                if _matches_digest_algo(const_map[inv.arg_regs[0]], algo):
                    return True
    return False


def _matches_digest_algo(value: str, algo: str) -> bool:
    return value.strip().upper() == algo.upper()


def _finding_hardcoded_key(method, key_constant: str | None, confirmed: bool) -> Finding:
    snippet = find_snippet(method, ["SecretKeySpec", "Base64;->decode", "getBytes"])
    if confirmed:
        severity = Severity.HIGH
        confidence = Confidence.MEDIUM
        description = "Hardcoded key material is used in SecretKeySpec."
        evidence = [
            EvidenceStep(kind="SOURCE", description="Hardcoded key material constant", method=_method_name(method)),
            EvidenceStep(kind="SINK", description="SecretKeySpec constructed", method=_method_name(method), notes=snippet),
        ]
    else:
        severity = Severity.INFO
        confidence = Confidence.LOW
        description = "Heuristic: possible hardcoded key material near crypto API usage."
        evidence = [
            EvidenceStep(kind="SOURCE", description="Possible key material constant", method=_method_name(method)),
        ]
    return Finding(
        id="HARDCODED_SECRET",
        title="Hardcoded cryptographic secret",
        description=description,
        severity=severity,
        confidence=confidence,
        component_name=None,
        entrypoint_method=_method_name(method),
        evidence=evidence,
        recommendation="Load keys from secure storage and avoid hardcoded secrets.",
        references=[],
        fingerprint=f"HARDCODED_SECRET|{_class_name(method)}|{key_constant or ''}",
    )


def _looks_key_material(value: str) -> bool:
    if is_base64ish(value) or is_hexish(value):
        return True
    return len(value) >= 16


def _looks_iv_material(value: str) -> bool:
    if is_base64ish(value) or is_hexish(value):
        return True
    return len(value) in (8, 16)


def _has_crypto_context(extracted) -> bool:
    for inv in extracted.invokes:
        cls = inv.target_class
        if cls.startswith("Ljavax/crypto/"):
            return True
        if cls.startswith("Ljava/security/MessageDigest;"):
            return True
        if cls.startswith("Ljavax/crypto/Mac;"):
            return True
    return False


def _is_system_class(class_name: str) -> bool:
    return class_name.startswith(
        (
            "Landroid/",
            "Landroidx/",
            "Lcom/google/android/",
            "Lcom/google/firebase/",
            "Lcom/google/common/",
            "Lcom/google/crypto/",
            "Lkotlin/",
            "Ljava/",
            "Ljavax/",
            "Lorg/jetbrains/",
        )
    )


def _finding_hardcoded_iv(class_name: str) -> Finding:
    return Finding(
        id="HARDCODED_SECRET",
        title="Hardcoded cryptographic secret (IV)",
        description="Static constant used for IvParameterSpec suggests a hardcoded IV.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=class_name,
        entrypoint_method=None,
        evidence=[EvidenceStep(kind="SINK", description="IvParameterSpec from static constant", method=class_name)],
        recommendation="Use random IVs per encryption operation and store alongside ciphertext.",
        references=[],
    )


def _finding_ecb(method) -> Finding:
    snippet = find_snippet(method, ["Cipher;->getInstance", "AES/ECB"])
    return Finding(
        id="AES_ECB_MODE",
        title="Insecure AES/ECB mode",
        description="Cipher transformation uses ECB, which leaks patterns.",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        component_name=None,
        entrypoint_method=_method_name(method),
        evidence=[EvidenceStep(kind="SINK", description="Cipher.getInstance with /ECB/", method=_method_name(method), notes=snippet)],
        recommendation="Use authenticated encryption modes like AES/GCM.",
        references=[],
    )


def _finding_weak_digest(method, algo: str) -> Finding:
    snippet = find_snippet(method, ["MessageDigest;->getInstance", algo])
    return Finding(
        id=f"WEAK_DIGEST_{algo.replace('-', '')}",
        title=f"Weak digest algorithm {algo}",
        description=f"MessageDigest.getInstance uses {algo} which is considered weak.",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        component_name=None,
        entrypoint_method=_method_name(method),
        evidence=[EvidenceStep(kind="SINK", description=f"MessageDigest.getInstance({algo})", method=_method_name(method), notes=snippet)],
        recommendation="Use SHA-256 or stronger hash functions.",
        references=[],
    )


def _class_name(method) -> str:
    try:
        return method.get_class_name()
    except Exception:
        return "<unknown>"


def _method_name(method) -> str:
    try:
        return f"{method.get_class_name()}->{method.get_name()}"
    except Exception:
        return "<unknown>"


def _extract_iv_fields_from_clinit(class_name: str, method, extracted) -> set:
    const_regs = {c.dest_reg for c in extracted.const_strings if len(c.value) == 16}
    iv_fields = set()
    for inv in extracted.invokes:
        if inv.target_class == "Ljava/lang/String;" and inv.target_name == "getBytes":
            if inv.arg_regs and inv.arg_regs[0] in const_regs and inv.move_result_reg is not None:
                field_refs = extracted.field_refs or _bytecode_field_refs(method)
                for ref in field_refs:
                    if not ref.opcode.startswith("sput"):
                        continue
                    if ref.owner_class != class_name:
                        continue
                    if ref.src_reg == inv.move_result_reg:
                        iv_fields.add((ref.owner_class, ref.field_name, ref.field_desc))
    if not iv_fields:
        iv_fields = _extract_iv_fields_from_source(class_name, method)
    return iv_fields


def _detect_hardcoded_iv(class_name: str, methods, iv_fields: set) -> List[Finding]:
    findings: List[Finding] = []
    for m in methods:
        if _class_name(m) != class_name:
            continue
        if not hasattr(m, "get_code") or m.get_code() is None:
            continue
        extracted = extract_method(m)
        findings.extend(_detect_hardcoded_iv_in_extracted(class_name, m, extracted, iv_fields))
    return findings


def _detect_hardcoded_iv_in_extracted(class_name: str, method, extracted, iv_fields: set) -> List[Finding]:
    const_map = {c.dest_reg: c.value for c in extracted.const_strings}
    for mv in extracted.moves:
        if mv.src_reg in const_map and mv.dest_reg is not None:
            const_map[mv.dest_reg] = const_map[mv.src_reg]

    iv_field_regs = {}
    field_refs = extracted.field_refs
    if not field_refs:
        field_refs = _bytecode_field_refs(method)
        if not field_refs:
            field_refs = _source_field_refs(method)
    for ref in field_refs:
        if ref.opcode.startswith("sget") and (ref.owner_class, ref.field_name, ref.field_desc) in iv_fields:
            if ref.dest_reg is not None:
                iv_field_regs[ref.dest_reg] = ref

    iv_spec_regs = set()
    iv_spec_note = None
    new_ivspec = {ni.dest_reg: ni for ni in extracted.new_instances if ni.class_desc == "Ljavax/crypto/spec/IvParameterSpec;"}
    bytes_from_const = {}
    for inv in extracted.invokes:
        if inv.target_class == "Landroid/util/Base64;" and inv.target_name == "decode":
            if inv.arg_regs and inv.move_result_reg is not None:
                arg = inv.arg_regs[0]
                if arg in const_map and _looks_iv_material(const_map[arg]):
                    bytes_from_const[inv.move_result_reg] = const_map[arg]
        if inv.target_class == "Ljava/lang/String;" and inv.target_name == "getBytes":
            if inv.arg_regs and inv.move_result_reg is not None:
                arg = inv.arg_regs[0]
                if arg in const_map and _looks_iv_material(const_map[arg]):
                    bytes_from_const[inv.move_result_reg] = const_map[arg]
        if inv.target_class == "Ljavax/crypto/spec/IvParameterSpec;" and inv.target_name == "<init>":
            if len(inv.arg_regs) >= 2:
                this_reg = inv.arg_regs[0]
                arg_reg = inv.arg_regs[1]
                if this_reg in new_ivspec and (arg_reg in iv_field_regs or arg_reg in bytes_from_const):
                    iv_spec_regs.add(this_reg)
                    iv_spec_note = inv.raw
    findings: List[Finding] = []
    if iv_spec_regs:
        evidence = [
            EvidenceStep(
                kind="SOURCE",
                description="IV loaded from static constant or literal",
                method=_method_name(method),
                notes=",".join(sorted(f"{o}->{n}:{d}" for o, n, d in iv_fields)) if iv_fields else None,
            ),
            EvidenceStep(
                kind="SINK",
                description="IvParameterSpec constructed from static IV",
                method=_method_name(method),
                notes=iv_spec_note,
            ),
        ]
        findings.append(
            Finding(
                id="HARDCODED_SECRET",
                title="Hardcoded cryptographic secret (IV)",
                description="Static IV used to construct IvParameterSpec.",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                component_name=class_name,
                entrypoint_method=_method_name(method),
                evidence=evidence,
                recommendation="Use random IVs per encryption operation and store alongside ciphertext.",
                references=[],
            )
        )
    return findings


def _extract_iv_fields_from_source(class_name: str, method) -> set:
    iv_fields = set()
    lines = _source_lines(method)
    if not lines:
        return iv_fields
    const_reg = None
    saw_get_bytes = False
    bytes_reg = None
    for line in lines:
        line = line.strip()
        m_const = _re_const_string(line)
        if m_const:
            reg, value = m_const
            if len(value) == 16:
                const_reg = reg
                continue
        if "Ljava/lang/String;->getBytes" in line and const_reg is not None:
            regs = _parse_reg_list(line)
            if regs and regs[0] == const_reg:
                saw_get_bytes = True
                continue
        if saw_get_bytes and line.startswith("move-result"):
            reg = _first_reg(line)
            if reg is not None:
                bytes_reg = reg
            saw_get_bytes = False
            continue
        if bytes_reg is not None and line.startswith("sput-object"):
            reg = _first_reg(line)
            owner, field, desc = _parse_field_sig(line)
            if reg == bytes_reg and owner == class_name and field and desc:
                iv_fields.add((owner, field, desc))
                bytes_reg = None
    return iv_fields


def _source_field_refs(method) -> List:
    refs = []
    for line in _source_lines(method):
        line = line.strip()
        if line.startswith("sget") or line.startswith("sput"):
            owner, field, desc = _parse_field_sig(line)
            if not owner:
                continue
            reg = _first_reg(line)
            if reg is None:
                continue
            if line.startswith("sget"):
                refs.append(type("F", (), {"opcode": line.split()[0], "owner_class": owner, "field_name": field, "field_desc": desc, "dest_reg": reg}))
            else:
                refs.append(type("F", (), {"opcode": line.split()[0], "owner_class": owner, "field_name": field, "field_desc": desc, "dest_reg": None, "src_reg": reg}))
    return refs


def _bytecode_field_refs(method) -> List:
    refs = []
    try:
        code = method.get_code()
        if not code:
            return refs
        bc = code.get_bc()
        for ins in bc.get_instructions():
            name = ins.get_name()
            if not (name.startswith("sget") or name.startswith("sput")):
                continue
            try:
                raw = str(ins.get_output())
            except Exception:
                continue
            reg = _first_reg(raw)
            owner, field, desc = _parse_field_sig_flexible(raw)
            if not owner:
                continue
            if name.startswith("sget"):
                refs.append(type("F", (), {"opcode": name, "owner_class": owner, "field_name": field, "field_desc": desc, "dest_reg": reg}))
            else:
                refs.append(type("F", (), {"opcode": name, "owner_class": owner, "field_name": field, "field_desc": desc, "src_reg": reg}))
    except Exception:
        return refs
    return refs


def _source_lines(method) -> List[str]:
    try:
        src = method.get_source()
    except Exception:
        return []
    if not src:
        return []
    return src.splitlines()




def _re_const_string(line: str):
    if "const-string" not in line:
        return None
    parts = line.split(",")
    if len(parts) < 2:
        return None
    reg = _first_reg(line)
    value = parts[-1].strip().strip("\"'")
    return reg, value


def _parse_reg_list(line: str) -> List[int]:
    if "{" not in line or "}" not in line:
        return []
    inside = line.split("{", 1)[1].split("}", 1)[0]
    regs = []
    for token in inside.split(","):
        reg = _reg_to_int(token.strip())
        if reg is not None:
            regs.append(reg)
    return regs


def _first_reg(line: str) -> int | None:
    for token in line.replace("{", " ").replace("}", " ").split():
        reg = _reg_to_int(token)
        if reg is not None:
            return reg
    return None


def _reg_to_int(token: str) -> int | None:
    token = token.strip().strip(",")
    if token.startswith("v") and token[1:].isdigit():
        return int(token[1:])
    if token.startswith("p") and token[1:].isdigit():
        return -(int(token[1:]) + 1)
    return None


def _parse_field_sig(line: str):
    if "->" not in line:
        return "", "", ""
    frag = line.split(",")[-1].strip()
    if "->" not in frag or ":" not in frag:
        return "", "", ""
    owner, rest = frag.split("->", 1)
    field, desc = rest.split(":", 1)
    return owner.strip(), field.strip(), desc.strip()


def _parse_field_sig_flexible(line: str):
    if "->" not in line:
        return "", "", ""
    frag = line.split(",")[-1].strip()
    if "->" not in frag:
        return "", "", ""
    owner, rest = frag.split("->", 1)
    if ":" in rest:
        field, desc = rest.split(":", 1)
    else:
        parts = rest.split()
        if len(parts) >= 2:
            field = parts[0]
            desc = parts[1]
        else:
            return "", "", ""
    return owner.strip(), field.strip(), desc.strip()
