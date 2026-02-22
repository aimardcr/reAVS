from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple
import re

from core.bytecode.smali import parse_invoke_sig as _shared_parse_invoke_sig


@dataclass
class IRInstruction:
    offset: int
    opcode: str
    raw: str
    regs: List[int]
    target_sig: Optional[Tuple[str, str, str]]
    branch_targets: List[int]
    fallthrough: Optional[int]
    move_result_reg: Optional[int]
    is_branch: bool
    is_return: bool
    is_throw: bool
    is_invoke: bool
    is_switch: bool


@dataclass
class BasicBlock:
    id: int
    start: int
    end: int
    instrs: List[IRInstruction]
    succs: Set[int]
    preds: Set[int]
    is_entry: bool = False
    is_exit: bool = False


@dataclass
class MethodCFG:
    method_sig: Tuple[str, str, str]
    blocks: Dict[int, BasicBlock]
    entry: int
    exits: Set[int]
    offset_to_block: Dict[int, int]


def build_method_cfg(method) -> MethodCFG:
    """Build a per-method CFG from DEX bytecode.

    This prefers real instruction offsets when available; otherwise it uses
    instruction indices as stable offsets.
    """
    method_sig = _method_sig(method)
    instrs = _extract_instructions(method)
    if not instrs:
        entry_block = BasicBlock(id=0, start=0, end=0, instrs=[], succs=set(), preds=set(), is_entry=True, is_exit=True)
        return MethodCFG(method_sig=method_sig, blocks={0: entry_block}, entry=0, exits={0}, offset_to_block={})

    leaders = _find_leaders(instrs, method)
    blocks, offset_to_block = _build_blocks(instrs, leaders)
    _link_blocks(blocks, instrs, offset_to_block, method)
    entry = offset_to_block.get(instrs[0].offset, 0)
    exits = {bid for bid, b in blocks.items() if not b.succs}
    for bid in exits:
        blocks[bid].is_exit = True
    blocks[entry].is_entry = True
    return MethodCFG(method_sig=method_sig, blocks=blocks, entry=entry, exits=exits, offset_to_block=offset_to_block)


def _method_sig(method) -> Tuple[str, str, str]:
    try:
        return method.get_class_name(), method.get_name(), method.get_descriptor()
    except Exception:
        return "<unknown>", "<unknown>", ""


def _extract_instructions(method) -> List[IRInstruction]:
    if not hasattr(method, "get_code"):
        return []
    code = method.get_code()
    if not code:
        return []
    try:
        bc = code.get_bc()
        ins_list = list(bc.get_instructions())
    except Exception:
        return []

    offsets = _instruction_offsets(ins_list)
    offset_set = set(offsets)
    instrs: List[IRInstruction] = []

    idx = 0
    while idx < len(ins_list):
        ins = ins_list[idx]
        opcode = ins.get_name()
        raw = ""
        try:
            raw = str(ins.get_output())
        except Exception:
            raw = ""
        offset = offsets[idx]
        regs = _parse_regs(raw)
        is_branch = _is_branch_opcode(opcode)
        is_switch = _is_switch_opcode(opcode)
        is_return = opcode.startswith("return")
        is_throw = opcode == "throw"
        is_invoke = opcode.startswith("invoke-")
        branch_targets = _resolve_branch_targets(ins, opcode, offset, offset_set)
        fallthrough = None
        if not is_return and not is_throw and idx + 1 < len(ins_list):
            fallthrough = offsets[idx + 1]
        target_sig = None
        move_result_reg = None
        if is_invoke:
            target_sig = _parse_invoke_sig(raw)
            if idx + 1 < len(ins_list):
                next_ins = ins_list[idx + 1]
                try:
                    next_op = next_ins.get_name()
                except Exception:
                    next_op = ""
                if next_op.startswith("move-result"):
                    next_raw = ""
                    try:
                        next_raw = str(next_ins.get_output())
                    except Exception:
                        next_raw = ""
                    next_regs = _parse_regs(next_raw)
                    if next_regs:
                        move_result_reg = next_regs[0]
        instrs.append(
            IRInstruction(
                offset=offset,
                opcode=opcode,
                raw=raw,
                regs=regs,
                target_sig=target_sig,
                branch_targets=branch_targets,
                fallthrough=fallthrough,
                move_result_reg=move_result_reg,
                is_branch=is_branch,
                is_return=is_return,
                is_throw=is_throw,
                is_invoke=is_invoke,
                is_switch=is_switch,
            )
        )
        idx += 1
    return instrs


def _find_leaders(instrs: List[IRInstruction], method) -> Set[int]:
    leaders: Set[int] = {instrs[0].offset}
    offsets = {ins.offset for ins in instrs}
    for ins in instrs:
        if ins.is_branch or ins.is_switch:
            for tgt in ins.branch_targets:
                if tgt in offsets:
                    leaders.add(tgt)
            if ins.fallthrough is not None:
                leaders.add(ins.fallthrough)
        if ins.is_return or ins.is_throw:
            if ins.fallthrough is not None:
                leaders.add(ins.fallthrough)

    for handler_offset in _exception_handler_offsets(method):
        if handler_offset in offsets:
            leaders.add(handler_offset)
    return leaders


def _build_blocks(instrs: List[IRInstruction], leaders: Set[int]) -> Tuple[Dict[int, BasicBlock], Dict[int, int]]:
    blocks: Dict[int, BasicBlock] = {}
    offset_to_block: Dict[int, int] = {}
    current: List[IRInstruction] = []
    block_id = 0
    current_start = instrs[0].offset

    leader_set = set(leaders)
    for ins in instrs:
        if ins.offset in leader_set and current:
            block = BasicBlock(
                id=block_id,
                start=current_start,
                end=current[-1].offset,
                instrs=current,
                succs=set(),
                preds=set(),
            )
            blocks[block_id] = block
            for i in current:
                offset_to_block[i.offset] = block_id
            block_id += 1
            current = []
            current_start = ins.offset
        current.append(ins)

    if current:
        block = BasicBlock(
            id=block_id,
            start=current_start,
            end=current[-1].offset,
            instrs=current,
            succs=set(),
            preds=set(),
        )
        blocks[block_id] = block
        for i in current:
            offset_to_block[i.offset] = block_id
    return blocks, offset_to_block


def _link_blocks(
    blocks: Dict[int, BasicBlock],
    instrs: List[IRInstruction],
    offset_to_block: Dict[int, int],
    method,
) -> None:
    offsets = {ins.offset for ins in instrs}
    code_offset = _code_offset(method)
    for block in blocks.values():
        if not block.instrs:
            continue
        last = block.instrs[-1]
        succ_offsets: List[int] = []
        if last.is_branch or last.is_switch:
            succ_offsets.extend([t for t in last.branch_targets if t in offsets])
            if last.fallthrough is not None:
                succ_offsets.append(last.fallthrough)
        elif not last.is_return and not last.is_throw:
            if last.fallthrough is not None:
                succ_offsets.append(last.fallthrough)
        for off in succ_offsets:
            bid = offset_to_block.get(off)
            if bid is None:
                continue
            block.succs.add(bid)
            blocks[bid].preds.add(block.id)

    for try_start, try_end, handler_offsets in _exception_regions(method):
        covered = _blocks_covering_range(blocks, try_start, try_end)
        for b in covered:
            for h in handler_offsets:
                resolved = _resolve_handler_offset(h, instrs, offset_to_block, offsets, code_offset)
                if resolved is None:
                    continue
                bid = offset_to_block.get(resolved)
                if bid is None:
                    continue
                blocks[b].succs.add(bid)
                blocks[bid].preds.add(b)


def _blocks_covering_range(blocks: Dict[int, BasicBlock], start: int, end: int) -> List[int]:
    covered = []
    for bid, block in blocks.items():
        if block.start >= end or block.end < start:
            continue
        covered.append(bid)
    return covered


def _resolve_handler_offset(
    handler_off: int,
    instrs: List[IRInstruction],
    offset_to_block: Dict[int, int],
    offsets: Set[int],
    code_offset: Optional[int],
) -> Optional[int]:
    if code_offset is not None and handler_off >= code_offset:
        local_off = handler_off - code_offset
        if local_off in offsets:
            return local_off
        if 0 <= local_off < len(instrs):
            return instrs[local_off].offset
        if offsets:
            return min(offsets, key=lambda off: abs(off - local_off))
    if handler_off in offsets:
        return handler_off
    if handler_off in offset_to_block:
        return handler_off
    if 0 <= handler_off < len(instrs):
        return instrs[handler_off].offset
    # Fall back to nearest instruction offset at/after handler_off.
    for off in sorted(offsets):
        if off >= handler_off:
            return off
    # Final fallback: snap to closest offset.
    if offsets:
        return min(offsets, key=lambda off: abs(off - handler_off))
    return None


def _code_offset(method) -> Optional[int]:
    if not hasattr(method, "get_code"):
        return None
    code = method.get_code()
    if not code:
        return None
    for name in ("get_offset", "get_start_addr", "start_addr", "offset"):
        if hasattr(code, name):
            try:
                value = getattr(code, name)()
            except Exception:
                try:
                    value = getattr(code, name)
                except Exception:
                    continue
            if isinstance(value, int):
                return value
    return None


def _exception_handler_offsets(method) -> List[int]:
    handlers = []
    for _, _, hs in _exception_regions(method):
        handlers.extend(hs)
    return handlers


def _exception_regions(method) -> List[Tuple[int, int, List[int]]]:
    regions: List[Tuple[int, int, List[int]]] = []
    if not hasattr(method, "get_code"):
        return regions
    code = method.get_code()
    if not code or not hasattr(code, "get_tries"):
        return regions
    try:
        tries = code.get_tries() or []
    except Exception:
        return regions
    sig = _method_sig(method)
    method_id = f"{sig[0]}->{sig[1]}{sig[2]}"
    for t in tries:
        start = _get_try_attr(t, ("get_start_addr", "start_addr", "get_start", "start", "start_off"))
        end = _get_try_attr(t, ("get_end_addr", "end_addr", "get_end", "end", "end_off"))
        if end is None:
            count = _get_try_attr(t, ("get_insn_count", "get_length", "get_len", "insn_count", "length", "len"))
            if start is not None and isinstance(count, int):
                end = start + count
        handlers = _get_try_handlers(t, code)
        if start is None or end is None or not handlers:
            continue
        regions.append((start, end, handlers))
    return regions



def _get_try_attr(obj, names: Tuple[str, ...]) -> Optional[int]:
    for name in names:
        if hasattr(obj, name):
            try:
                val = getattr(obj, name)()
            except Exception:
                try:
                    val = getattr(obj, name)
                except Exception:
                    continue
            if isinstance(val, int):
                return val
    return None


def _get_try_handlers(t, code=None) -> List[int]:
    for name in (
        "get_handler_offsets",
        "get_handlers",
        "handlers",
        "get_exception_handlers",
        "get_catch_list",
        "get_catches",
    ):
        if not hasattr(t, name):
            continue
        try:
            handlers = getattr(t, name)()
        except Exception:
            try:
                handlers = getattr(t, name)
            except Exception:
                continue
        out = _coerce_handler_list(handlers)
        if out:
            return out
    handler_off = _get_try_attr(t, ("get_handler_off", "handler_off"))
    if handler_off is not None:
        if code is not None:
            resolved = _handlers_from_code(code, handler_off)
            if resolved:
                return resolved
        return [handler_off]
    return []


def _handlers_from_code(code, handler_off: int) -> List[int]:
    handlers = None
    for name in ("get_exception_handlers", "get_handlers", "get_catch_handlers", "get_catches"):
        if not hasattr(code, name):
            continue
        try:
            handlers = getattr(code, name)()
        except Exception:
            try:
                handlers = getattr(code, name)
            except Exception:
                handlers = None
        if handlers is not None:
            break
    if handlers is None:
        return []
    handler_list = handlers if isinstance(handlers, list) else list(handlers) if isinstance(handlers, tuple) else [handlers]
    entries = []
    for h in handler_list:
        off = _handler_offset_value(h)
        addr = _handler_addr_value(h)
        if addr is None and off is not None:
            addr = off
        entries.append((off, addr))
    # Match by explicit handler_off field if available.
    for off, addr in entries:
        if off is not None and off == handler_off and addr is not None:
            return [addr]
    # Fallback: treat handler_off as index into handler list.
    if isinstance(handler_off, int) and 0 <= handler_off < len(handler_list):
        addr = entries[handler_off][1]
        if addr is not None:
            return [addr]
    # Single-handler fallback: use the only handler address.
    if len(entries) == 1 and entries[0][1] is not None:
        return [entries[0][1]]
    return []


def _handler_offset_value(h) -> Optional[int]:
    # Avoid treating a raw address as an "offset" when handler entries are unstructured.
    if isinstance(h, int):
        return None
    if isinstance(h, tuple) or isinstance(h, list):
        return None
    for name in ("get_handler_off", "get_offset", "get_off", "handler_off", "offset"):
        if hasattr(h, name):
            try:
                val = getattr(h, name)()
            except Exception:
                try:
                    val = getattr(h, name)
                except Exception:
                    continue
            if isinstance(val, int):
                return val
    return None


def _handler_addr_value(h) -> Optional[int]:
    if isinstance(h, int):
        return h
    if isinstance(h, tuple) or isinstance(h, list):
        # Prefer the last int as an address.
        for item in reversed(h):
            if isinstance(item, int):
                return item
        return None
    for name in ("get_handler_addr", "get_addr", "get_start_addr", "get_address", "handler_addr", "addr", "address"):
        if hasattr(h, name):
            try:
                val = getattr(h, name)()
            except Exception:
                try:
                    val = getattr(h, name)
                except Exception:
                    continue
            if isinstance(val, int):
                return val
    return None


def _coerce_handler_list(handlers) -> List[int]:
    if handlers is None:
        return []
    if isinstance(handlers, tuple):
        handlers = list(handlers)
    if isinstance(handlers, list):
        out: List[int] = []
        for h in handlers:
            out.extend(_handler_offsets_from_obj(h))
        return out
    return _handler_offsets_from_obj(handlers)


def _handler_offsets_from_obj(h) -> List[int]:
    if isinstance(h, int):
        return [h]
    if isinstance(h, tuple) or isinstance(h, list):
        # Androguard sometimes returns (type, addr) or (addr, type).
        for item in h:
            if isinstance(item, int):
                return [item]
        return []
    for name in ("get_handler_off", "get_handler_offset", "get_handler_addr", "get_offset"):
        if hasattr(h, name):
            try:
                val = getattr(h, name)()
            except Exception:
                try:
                    val = getattr(h, name)
                except Exception:
                    continue
            if isinstance(val, int):
                return [val]
    # Catch-all handlers may be exposed separately.
    for name in ("get_catch_all_addr", "catch_all_addr"):
        if hasattr(h, name):
            try:
                val = getattr(h, name)()
            except Exception:
                try:
                    val = getattr(h, name)
                except Exception:
                    continue
            if isinstance(val, int):
                return [val]
    return []


def _instruction_offsets(ins_list: List[object]) -> List[int]:
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


def _is_branch_opcode(opcode: str) -> bool:
    return opcode.startswith("if-") or opcode.startswith("goto")


def _is_switch_opcode(opcode: str) -> bool:
    return opcode.endswith("switch")


def _resolve_branch_targets(ins, opcode: str, current_offset: int, offset_set: Set[int]) -> List[int]:
    targets: List[int] = []
    if not (_is_branch_opcode(opcode) or _is_switch_opcode(opcode)):
        return targets

    for val in _iter_offset_operands(ins):
        if val in offset_set:
            targets.append(val)
        elif (current_offset + val) in offset_set:
            targets.append(current_offset + val)
        else:
            targets.append(val)

    if targets:
        return list(dict.fromkeys(targets))

    raw = ""
    try:
        raw = str(ins.get_output())
    except Exception:
        return targets
    last = raw.split(",")[-1].strip()
    m = re.search(r"([+-]?0x[0-9a-fA-F]+|[+-]?\d+)$", last)
    if m:
        try:
            off = int(m.group(1), 0)
        except Exception:
            return targets
        if off in offset_set:
            targets.append(off)
        elif (current_offset + off) in offset_set:
            targets.append(current_offset + off)
        else:
            targets.append(off)
    return targets


def _iter_offset_operands(ins):
    try:
        operands = ins.get_operands()
    except Exception:
        operands = []
    for op in operands or []:
        if isinstance(op, tuple) and len(op) >= 2:
            value = op[1]
        else:
            value = op
        if isinstance(value, int):
            yield value
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, int):
                    yield item


_REG_RE = re.compile(r"\b([vp])(\d+)\b")


def _parse_regs(text: str) -> List[int]:
    regs: List[int] = []
    for kind, idx in _REG_RE.findall(text):
        value = int(idx)
        if kind == "p":
            regs.append(-(value + 1))
        else:
            regs.append(value)
    return regs


def _parse_invoke_sig(raw: str) -> Optional[Tuple[str, str, str]]:
    return _shared_parse_invoke_sig(raw)
