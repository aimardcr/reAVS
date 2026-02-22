from __future__ import annotations

from typing import Dict, List, Set, Tuple, Optional
from core.rules.matching import simple_class_name
from core.bytecode.smali import parse_invoke_sig as _shared_parse_invoke_sig


# Known Android callback/lifecycle signatures to treat as entry roots.
_LIFECYCLE_NAMES = {
    "onCreate",
    "onStart",
    "onResume",
    "onPause",
    "onStop",
    "onDestroy",
    "onNewIntent",
    "onReceive",
    "onStartCommand",
}

_USER_EVENT_CALLBACKS = {
    ("onClick", "(Landroid/view/View;)V"),
    ("onLongClick", "(Landroid/view/View;)Z"),
    ("onFocusChange", "(Landroid/view/View;Z)V"),
    ("onEditorAction", "(Landroid/widget/TextView;ILandroid/view/KeyEvent;)Z"),
    ("onItemClick", "(Landroid/widget/AdapterView;Landroid/view/View;IJ)V"),
    ("onItemSelected", "(Landroid/widget/AdapterView;Landroid/view/View;IJ)V"),
    ("onNothingSelected", "(Landroid/widget/AdapterView;)V"),
    ("onCheckedChanged", "(Landroid/widget/CompoundButton;Z)V"),
    ("onTouch", "(Landroid/view/View;Landroid/view/MotionEvent;)Z"),
    ("onKey", "(Landroid/view/View;ILandroid/view/KeyEvent;)Z"),
    ("beforeTextChanged", "(Ljava/lang/CharSequence;III)V"),
    ("onTextChanged", "(Ljava/lang/CharSequence;III)V"),
    ("afterTextChanged", "(Landroid/text/Editable;)V"),
}


def is_callback_root(method) -> bool:
    """Return True if the method looks like an Android lifecycle or listener callback."""
    try:
        name = method.get_name()
        desc = method.get_descriptor()
        cls = method.get_class_name()
    except Exception:
        return False

    if name in _LIFECYCLE_NAMES:
        return True

    # Common user-event listeners
    if (name, desc) in _USER_EVENT_CALLBACKS:
        return True

    # BroadcastReceiver-like callbacks (onReceive with Intent)
    if name == "onReceive" and "Landroid/content/Intent;" in desc:
        return True

    # ContentProvider CRUD style callbacks.
    if name in {"query", "insert", "update", "delete", "openFile"} and _looks_provider_class(cls):
        return True

    return False


def find_onclick_callbacks(caller, invokes, method_index: dict) -> list:
    """Best-effort discovery of onClick callback methods registered via setOnClickListener in the same class."""
    callbacks = []
    caller_cls = None
    try:
        caller_cls = caller.get_class_name()
    except Exception:
        pass
    if not caller_cls:
        return callbacks

    for inv in invokes:
        if inv.target_name != "setOnClickListener":
            continue
        # Prefer direct lookup of onClick in caller class.
        key = (caller_cls, "onClick", "(Landroid/view/View;)V")
        if key in method_index:
            callbacks.append(method_index[key])
    return callbacks


def collect_callback_edges(
    sig_to_method: Dict[Tuple[str, str, str], object],
    method_index: Dict[Tuple[str, str, str], object],
    analysis,
) -> Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]]:
    """
    Collect all callback edges including:
    1. setOnClickListener → onClick (direct and via synthetic lambdas)
    2. startActivity → target Activity.onCreate
    3. Synthetic lambda → actual callback method
    """
    edges: Dict[Tuple[str, str, str], Set[Tuple[str, str, str]]] = {}
    
    # Build a map of synthetic lambda classes to their enclosing classes
    synthetic_to_enclosing = _build_synthetic_map(analysis)
    
    # Build a map of lambda classes to their actual callback methods
    lambda_to_callback = _build_lambda_callback_map(sig_to_method, synthetic_to_enclosing)
    
    for sig, method in sig_to_method.items():
        try:
            code = method.get_code()
            if not code:
                continue
            bc = code.get_bc()
            invokes = _extract_invokes(bc)
            
            # Handle setOnClickListener with synthetic lambdas
            for inv in invokes:
                if inv["name"] == "setOnClickListener":
                    # Check if argument is a synthetic lambda
                    callback_sigs = _resolve_onclick_callback(
                        method, inv, method_index, lambda_to_callback, synthetic_to_enclosing
                    )
                    for cb_sig in callback_sigs:
                        edges.setdefault(sig, set()).add(cb_sig)
                
                # Handle startActivity → target Activity
                elif inv["name"] == "startActivity" and inv["class"] == "Landroid/app/Activity;":
                    target_activities = _resolve_intent_target(method, inv, sig_to_method, analysis)
                    for target_sig in target_activities:
                        edges.setdefault(sig, set()).add(target_sig)
            
            # Handle synthetic lambda forwarding to actual callback
            if _is_synthetic_lambda(method):
                actual_callback = lambda_to_callback.get(sig)
                if actual_callback:
                    edges.setdefault(sig, set()).add(actual_callback)
                    
        except Exception:
            continue
    
    return edges


def _build_synthetic_map(analysis) -> Dict[str, str]:
    """Build a map from synthetic lambda class to enclosing class."""
    synthetic_to_enclosing: Dict[str, str] = {}
    
    try:
        for cls in analysis.get_classes():
            class_name = cls.get_name()
            # Synthetic lambda classes: ClassName$$ExternalSyntheticLambda0, etc.
            if "$$ExternalSyntheticLambda" in class_name or "$Lambda$" in class_name:
                # Extract enclosing class
                if "$$ExternalSyntheticLambda" in class_name:
                    enclosing = class_name.split("$$ExternalSyntheticLambda")[0]
                elif "$Lambda$" in class_name:
                    enclosing = class_name.split("$Lambda$")[0]
                else:
                    continue
                synthetic_to_enclosing[class_name] = enclosing
    except Exception:
        pass
    
    return synthetic_to_enclosing


def _build_lambda_callback_map(
    sig_to_method: Dict[Tuple[str, str, str], object],
    synthetic_to_enclosing: Dict[str, str],
) -> Dict[Tuple[str, str, str], Tuple[str, str, str]]:
    """
    Build a map from synthetic lambda onClick to the actual callback method.
    
    Synthetic lambdas typically have:
    - onClick(Landroid/view/View;)V that calls a static $r8$lambda$... method
    - The static method then calls the actual instance method in the enclosing class
    """
    lambda_to_callback: Dict[Tuple[str, str, str], Tuple[str, str, str]] = {}
    
    for sig, method in sig_to_method.items():
        cls, name, desc = sig
        
        # Check if this is a synthetic lambda onClick
        if cls not in synthetic_to_enclosing:
            continue
        if name != "onClick" or desc != "(Landroid/view/View;)V":
            continue
        
        # Find what this onClick calls
        try:
            code = method.get_code()
            if not code:
                continue
            bc = code.get_bc()
            invokes = _extract_invokes(bc)
            
            for inv in invokes:
                # Look for static $r8$lambda$ method in the same synthetic class
                if inv["class"] == cls and "$r8$lambda$" in inv["name"]:
                    # This static method is the bridge - find what it calls
                    bridge_sig = (inv["class"], inv["name"], inv["desc"])
                    if bridge_sig in sig_to_method:
                        bridge_method = sig_to_method[bridge_sig]
                        actual_callback = _find_actual_callback_from_bridge(
                            bridge_method, synthetic_to_enclosing[cls], sig_to_method
                        )
                        if actual_callback:
                            lambda_to_callback[sig] = actual_callback
                            break
        except Exception:
            continue
    
    return lambda_to_callback


def _find_actual_callback_from_bridge(
    bridge_method,
    enclosing_class: str,
    sig_to_method: Dict[Tuple[str, str, str], object],
) -> Optional[Tuple[str, str, str]]:
    """
    Find the actual callback method that the bridge method calls.
    The bridge typically calls a private method in the enclosing class.
    """
    try:
        code = bridge_method.get_code()
        if not code:
            return None
        bc = code.get_bc()
        invokes = _extract_invokes(bc)
        
        for inv in invokes:
            # Look for calls to methods in the enclosing class
            if inv["class"] == enclosing_class:
                # Common patterns: onCreate$lambda$0, onCreate$lambda$1, etc.
                if "$lambda$" in inv["name"] or inv["name"].startswith("access$"):
                    candidate_sig = (inv["class"], inv["name"], inv["desc"])
                    if candidate_sig in sig_to_method:
                        return candidate_sig
    except Exception:
        pass
    
    return None


def _is_synthetic_lambda(method) -> bool:
    """Check if a method belongs to a synthetic lambda class."""
    try:
        cls = method.get_class_name()
        return "$$ExternalSyntheticLambda" in cls or "$Lambda$" in cls
    except Exception:
        return False


def _resolve_onclick_callback(
    method,
    inv: dict,
    method_index: Dict[Tuple[str, str, str], object],
    lambda_to_callback: Dict[Tuple[str, str, str], Tuple[str, str, str]],
    synthetic_to_enclosing: Dict[str, str],
) -> List[Tuple[str, str, str]]:
    """
    Resolve the actual onClick callback from a setOnClickListener call.
    Handles both direct onClick and synthetic lambda patterns.
    """
    callbacks = []
    
    try:
        caller_cls = method.get_class_name()
        
        # Try direct onClick in the same class
        direct_key = (caller_cls, "onClick", "(Landroid/view/View;)V")
        if direct_key in method_index:
            callbacks.append(direct_key)
        
        # Check if the argument register points to a synthetic lambda
        # This requires tracking the type of the register, which we approximate
        # by looking for new-instance instructions of synthetic lambda classes
        code = method.get_code()
        if code:
            bc = code.get_bc()
            for ins in bc.get_instructions():
                opcode = ins.get_name()
                if opcode == "new-instance":
                    try:
                        raw = str(ins.get_output())
                        # Extract class name from new-instance
                        if "L" in raw and ";" in raw:
                            start = raw.index("L")
                            end = raw.index(";", start) + 1
                            lambda_cls = raw[start:end]
                            
                            if lambda_cls in synthetic_to_enclosing:
                                # Look for onClick in this synthetic lambda
                                lambda_onclick = (lambda_cls, "onClick", "(Landroid/view/View;)V")
                                if lambda_onclick in lambda_to_callback:
                                    callbacks.append(lambda_to_callback[lambda_onclick])
                                elif lambda_onclick in method_index:
                                    callbacks.append(lambda_onclick)
                    except Exception:
                        continue
    except Exception:
        pass
    
    return callbacks


def _resolve_intent_target(
    method,
    inv: dict,
    sig_to_method: Dict[Tuple[str, str, str], object],
    analysis,
) -> List[Tuple[str, str, str]]:
    """
    Resolve the target Activity from a startActivity call.
    Looks for Intent constructor with explicit component class.
    """
    targets = []
    
    try:
        code = method.get_code()
        if not code:
            return targets
        
        bc = code.get_bc()
        instructions = list(bc.get_instructions())
        
        # Look for Intent.<init> calls with Class argument
        for ins in instructions:
            opcode = ins.get_name()
            if not opcode.startswith("invoke-"):
                continue
            
            try:
                raw = str(ins.get_output())
                if "Landroid/content/Intent;-><init>" in raw and "Ljava/lang/Class;" in raw:
                    # Look backwards for const-class instruction
                    target_class = _find_const_class_before(instructions, ins)
                    if target_class:
                        # Look for onCreate in the target activity
                        target_sig = (target_class, "onCreate", "(Landroid/os/Bundle;)V")
                        if target_sig in sig_to_method:
                            targets.append(target_sig)
            except Exception:
                continue
    except Exception:
        pass
    
    return targets


def _find_const_class_before(instructions: list, current_ins) -> Optional[str]:
    """Find the most recent const-class instruction before the current one."""
    try:
        current_idx = instructions.index(current_ins)
        # Search backwards
        for i in range(current_idx - 1, max(0, current_idx - 20), -1):
            ins = instructions[i]
            opcode = ins.get_name()
            if opcode == "const-class":
                raw = str(ins.get_output())
                # Extract class name
                if "L" in raw and ";" in raw:
                    start = raw.index("L")
                    end = raw.index(";", start) + 1
                    return raw[start:end]
    except Exception:
        pass
    
    return None


def _extract_invokes(bc) -> List[dict]:
    """Extract invoke instructions with their details."""
    invokes = []
    
    try:
        for ins in bc.get_instructions():
            opcode = ins.get_name()
            if not opcode.startswith("invoke-"):
                continue
            
            try:
                raw = str(ins.get_output())
                cls, name, desc = _parse_invoke_sig(raw)
                if cls and name:
                    invokes.append({
                        "opcode": opcode,
                        "class": cls,
                        "name": name,
                        "desc": desc,
                        "raw": raw,
                    })
            except Exception:
                continue
    except Exception:
        pass
    
    return invokes


def _parse_invoke_sig(raw: str) -> Tuple[str, str, str]:
    result = _shared_parse_invoke_sig(raw)
    if result is None:
        return "", "", ""
    return result


def _looks_provider_class(class_name: str) -> bool:
    return "ContentProvider" in class_name or simple_class_name(class_name) == "ContentProvider"
