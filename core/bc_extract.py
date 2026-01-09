from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


@dataclass
class InvokeRef:
    offset: int
    opcode: str
    target_class: str
    target_name: str
    target_desc: str
    arg_regs: List[int]
    raw: str
    move_result_reg: Optional[int]


@dataclass
class ConstStringRef:
    offset: int
    dest_reg: int
    value: str
    raw: str


@dataclass
class ConstIntRef:
    offset: int
    dest_reg: int
    value: int
    raw: str


@dataclass
class NewInstanceRef:
    offset: int
    dest_reg: int
    class_desc: str
    raw: str


@dataclass
class FieldRef:
    offset: int
    opcode: str
    owner_class: str
    field_name: str
    field_desc: str
    regs: List[int]
    dest_reg: Optional[int]
    src_reg: Optional[int]
    raw: str


@dataclass
class MoveRef:
    offset: int
    opcode: str
    dest_reg: Optional[int]
    src_reg: Optional[int]
    raw: str


@dataclass
class ExtractedMethod:
    invokes: List[InvokeRef]
    const_strings: List[ConstStringRef]
    new_instances: List[NewInstanceRef]
    field_refs: List[FieldRef]
    moves: List[MoveRef]
    instruction_order: List[Tuple[str, int]]
    const_ints: List[ConstIntRef] = field(default_factory=list)


_REG_RE = re.compile(r"\b([vp])(\d+)\b")
_FIELD_RE = re.compile(r"(L[^;]+;)->([^:]+):(.+)$")
_FIELD_RE_ANY = re.compile(r"(L[^;]+;)->([\w$<>]+):([^\s,]+)")
_FIELD_RE_SPACE = re.compile(r"(L[^;]+;)->([^\s:]+)\s+([^\s,]+)")


def normalize_class_desc(value: str) -> str:
    if not value:
        return value
    if value.startswith("L") and value.endswith(";"):
        return value
    value = value.replace(".", "/")
    if value.startswith("L") and value.endswith(";"):
        return value
    if value.startswith("L") and value.endswith(";") is False:
        return value + ";"
    return "L" + value.strip("L;") + ";"


def normalize_method_sig(cls: str, name: str, desc: str) -> Tuple[str, str, str]:
    return normalize_class_desc(cls), name or "", desc or ""


def _reg_to_int(kind: str, idx: str) -> int:
    # Use negative space for parameter registers to keep them distinct.
    value = int(idx)
    if kind == "p":
        return -(value + 1)
    return value


def _parse_regs(text: str) -> List[int]:
    regs: List[int] = []
    if ".." in text:
        match = re.search(r"([vp])(\d+)\s*\.\.\s*([vp])(\d+)", text)
        if match:
            start = _reg_to_int(match.group(1), match.group(2))
            end = _reg_to_int(match.group(3), match.group(4))
            step = 1 if end >= start else -1
            regs.extend(list(range(start, end + step, step)))
            return regs
    for kind, idx in _REG_RE.findall(text):
        regs.append(_reg_to_int(kind, idx))
    return regs


def _parse_first_reg(text: str) -> Optional[int]:
    match = _REG_RE.search(text)
    if not match:
        return None
    return _reg_to_int(match.group(1), match.group(2))


def _parse_invoke_output(output: str) -> Tuple[str, str, str, List[int]]:
    if "->" not in output:
        return "", "", "", []
    left, right = output.split("->", 1)
    regs = _parse_regs(left)
    if "(" in right:
        name, desc = right.split("(", 1)
        desc = "(" + desc
    else:
        name, desc = right, ""
    cls = left.split(",")[-1].strip()
    if " " in cls:
        cls = cls.split()[-1].strip()
    if "L" not in cls:
        # fallback: parse class from right side if possible
        cls = right.split("(", 1)[0]
    return normalize_class_desc(cls), name.strip(), desc.strip(), regs


def get_invoke_refs(method) -> List[InvokeRef]:
    invokes: List[InvokeRef] = []
    if not hasattr(method, "get_code"):
        return invokes
    code = method.get_code()
    if not code:
        return invokes
    bc = code.get_bc()
    offsets = _instruction_offsets(bc)
    last_invoke: Optional[InvokeRef] = None
    for idx, ins in enumerate(bc.get_instructions()):
        opcode = ins.get_name()
        try:
            raw = str(ins.get_output())
        except Exception:
            raw = ""
        offset = offsets[idx]
        if opcode.startswith("invoke-"):
            cls, name, desc, regs = _parse_invoke_output(raw)
            invoke = InvokeRef(
                offset=offset,
                opcode=opcode,
                target_class=cls,
                target_name=name,
                target_desc=desc,
                arg_regs=regs,
                raw=raw,
                move_result_reg=None,
            )
            invokes.append(invoke)
            last_invoke = invoke
        elif opcode.startswith("move-result") and last_invoke:
            regs = _parse_regs(raw)
            if regs:
                last_invoke.move_result_reg = regs[0]
            else:
                dest = _parse_first_reg(raw)
                if dest is not None:
                    last_invoke.move_result_reg = dest
            last_invoke = None
        else:
            last_invoke = None
    return invokes


def get_const_strings(method) -> List[ConstStringRef]:
    strings: List[ConstStringRef] = []
    if not hasattr(method, "get_code"):
        return strings
    code = method.get_code()
    if not code:
        return strings
    bc = code.get_bc()
    offsets = _instruction_offsets(bc)
    for idx, ins in enumerate(bc.get_instructions()):
        opcode = ins.get_name()
        if opcode in ("const-string", "const-string/jumbo"):
            try:
                raw = str(ins.get_output())
            except Exception:
                raw = ""
            regs = _parse_regs(raw)
            try:
                value = ins.get_string()
            except Exception:
                value = ""
            if regs:
                strings.append(ConstStringRef(offset=offsets[idx], dest_reg=regs[0], value=value, raw=raw))
    return strings


def _parse_const_int(raw: str) -> Optional[int]:
    if "," not in raw:
        return None
    tail = raw.split(",", 1)[1]
    match = re.search(r"(-?0x[0-9a-fA-F]+|-?\d+)", tail)
    if not match:
        return None
    try:
        return int(match.group(1), 0)
    except Exception:
        return None


def get_const_ints(method) -> List[ConstIntRef]:
    ints: List[ConstIntRef] = []
    if not hasattr(method, "get_code"):
        return ints
    code = method.get_code()
    if not code:
        return ints
    bc = code.get_bc()
    offsets = _instruction_offsets(bc)
    for idx, ins in enumerate(bc.get_instructions()):
        opcode = ins.get_name()
        if opcode in ("const/4", "const/16", "const", "const/high16"):
            try:
                raw = str(ins.get_output())
            except Exception:
                raw = ""
            regs = _parse_regs(raw)
            value = _parse_const_int(raw)
            if regs and value is not None:
                ints.append(ConstIntRef(offset=offsets[idx], dest_reg=regs[0], value=value, raw=raw))
    return ints


def get_new_instances(method) -> List[NewInstanceRef]:
    instances: List[NewInstanceRef] = []
    if not hasattr(method, "get_code"):
        return instances
    code = method.get_code()
    if not code:
        return instances
    bc = code.get_bc()
    offsets = _instruction_offsets(bc)
    for idx, ins in enumerate(bc.get_instructions()):
        if ins.get_name() == "new-instance":
            try:
                raw = str(ins.get_output())
            except Exception:
                raw = ""
            regs = _parse_regs(raw)
            cls = ""
            if "L" in raw:
                cls = raw.split(",")[-1].strip()
            if regs:
                instances.append(
                    NewInstanceRef(
                        offset=offsets[idx],
                        dest_reg=regs[0],
                        class_desc=normalize_class_desc(cls),
                        raw=raw,
                    )
                )
    return instances


def get_field_refs(method) -> List[FieldRef]:
    refs: List[FieldRef] = []
    if not hasattr(method, "get_code"):
        return refs
    code = method.get_code()
    if not code:
        return refs
    bc = code.get_bc()
    offsets = _instruction_offsets(bc)
    for idx, ins in enumerate(bc.get_instructions()):
        opcode = ins.get_name()
        if opcode.startswith(("sget", "sput", "iget", "iput")):
            try:
                raw = str(ins.get_output())
            except Exception:
                raw = ""
            regs = _parse_regs(raw)
            dest_reg: Optional[int] = None
            src_reg: Optional[int] = None
            if opcode.startswith("sget") or opcode.startswith("iget"):
                dest_reg = regs[0] if regs else None
            elif opcode.startswith("sput") or opcode.startswith("iput"):
                src_reg = regs[0] if regs else None
            owner = field = desc = ""
            match = _FIELD_RE.search(raw)
            if match:
                owner, field, desc = match.group(1), match.group(2), match.group(3)
            else:
                m2 = _FIELD_RE_ANY.search(raw) or _FIELD_RE_SPACE.search(raw)
                if m2:
                    owner, field, desc = m2.group(1), m2.group(2), m2.group(3)
            if not owner or not field or not desc:
                try:
                    for op in ins.get_operands():
                        value = op[1] if isinstance(op, tuple) and len(op) > 1 else op
                        if hasattr(value, "get_class_name") and hasattr(value, "get_name") and hasattr(value, "get_descriptor"):
                            owner = value.get_class_name()
                            field = value.get_name()
                            desc = value.get_descriptor()
                            break
                        text = str(value)
                        m3 = _FIELD_RE.search(text) or _FIELD_RE_ANY.search(text) or _FIELD_RE_SPACE.search(text)
                        if m3:
                            owner, field, desc = m3.group(1), m3.group(2), m3.group(3)
                            break
                except Exception:
                    pass
            if owner and field and desc:
                refs.append(
                    FieldRef(
                        offset=offsets[idx],
                        opcode=opcode,
                        owner_class=normalize_class_desc(owner),
                        field_name=field,
                        field_desc=desc,
                        regs=regs,
                        dest_reg=dest_reg,
                        src_reg=src_reg,
                        raw=raw,
                    )
                )
    return refs


def get_moves(method) -> List[MoveRef]:
    moves: List[MoveRef] = []
    if not hasattr(method, "get_code"):
        return moves
    code = method.get_code()
    if not code:
        return moves
    bc = code.get_bc()
    offsets = _instruction_offsets(bc)
    for idx, ins in enumerate(bc.get_instructions()):
        opcode = ins.get_name()
        if opcode.startswith("move"):
            try:
                raw = str(ins.get_output())
            except Exception:
                raw = ""
            regs = _parse_regs(raw)
            dest = regs[0] if len(regs) >= 1 else None
            src = regs[1] if len(regs) >= 2 else None
            moves.append(MoveRef(offset=offsets[idx], opcode=opcode, dest_reg=dest, src_reg=src, raw=raw))
    return moves


def _instruction_offsets(bc) -> List[int]:
    ins_list = list(bc.get_instructions())
    offsets: List[int] = []
    have_addr = False
    for ins in ins_list:
        addr = _ins_addr(ins)
        if addr is not None:
            offsets.append(addr)
            have_addr = True
        else:
            offsets.append(0)
    if have_addr:
        return offsets
    current = 0
    out: List[int] = []
    for ins in ins_list:
        out.append(current)
        length = _ins_length(ins)
        current += length if length is not None else 1
    return out


def _ins_addr(ins) -> Optional[int]:
    for name in ("get_start_addr", "get_start", "get_pos", "get_offset"):
        if hasattr(ins, name):
            try:
                value = getattr(ins, name)()
            except Exception:
                try:
                    value = getattr(ins, name)
                except Exception:
                    continue
            if isinstance(value, int):
                return value
    return None


def _ins_length(ins) -> Optional[int]:
    for name in ("get_length", "get_size", "get_insn_length"):
        if hasattr(ins, name):
            try:
                value = getattr(ins, name)()
            except Exception:
                try:
                    value = getattr(ins, name)
                except Exception:
                    continue
            if isinstance(value, int):
                return value
    return None


def extract_method(method) -> ExtractedMethod:
    invokes = get_invoke_refs(method)
    consts = get_const_strings(method)
    const_ints = get_const_ints(method)
    instances = get_new_instances(method)
    fields = get_field_refs(method)
    moves = get_moves(method)
    order: List[Tuple[str, int]] = []
    for i, _ in enumerate(invokes):
        order.append(("invoke", i))
    for i, _ in enumerate(consts):
        order.append(("const", i))
    for i, _ in enumerate(instances):
        order.append(("new", i))
    for i, _ in enumerate(fields):
        order.append(("field", i))
    for i, _ in enumerate(moves):
        order.append(("move", i))
    return ExtractedMethod(
        invokes=invokes,
        const_strings=consts,
        const_ints=const_ints,
        new_instances=instances,
        field_refs=fields,
        moves=moves,
        instruction_order=order,
    )


def build_one_hop_call_edges(invokes: List[InvokeRef], method_index: dict) -> List[Tuple[InvokeRef, object]]:
    edges: List[Tuple[InvokeRef, object]] = []
    for inv in invokes:
        key = normalize_method_sig(inv.target_class, inv.target_name, inv.target_desc)
        callee = method_index.get(key)
        if callee is not None:
            edges.append((inv, callee))
    return edges
