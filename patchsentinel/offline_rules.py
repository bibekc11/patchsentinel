"""Deterministic rule-based engines used by the 'offline' provider (demo + reproducible benchmark).
They cover three bug classes on simple code shapes; anything else is escalated, never guessed."""
from __future__ import annotations
import ast, re, shlex
from typing import List, Optional, Tuple

from .analysis import find_function, header_names, params_of, statement_at, tainted_names
from .models import CLASS_BY_RULE

Edit = Tuple[int, int, int, str]  # (line, col_start, col_end, text)  1-based line, 0-based cols
SAFE_JOIN = '''def _safe_join(base, *parts):
    base_real = os.path.realpath(base)
    target = os.path.realpath(os.path.join(base_real, *parts))
    if os.path.commonpath([base_real, target]) != base_real:
        raise PermissionError("path escapes the allowed directory")
    return target
'''


# ---------------------------------------------------------------- triage
def triage(source: str, alert) -> dict:
    cls = CLASS_BY_RULE.get(alert.rule_id)
    tree = ast.parse(source)
    fn = find_function(tree, alert.function) if alert.function else None
    if fn is None:
        return {"verdict": "escalate", "vuln_class": "other", "reason": "alert is not inside a function; needs a human"}
    stmt = statement_at(fn, alert.line)
    used = header_names(stmt) if stmt is not None else set()
    flows = sorted(used & tainted_names(fn))
    if alert.rule_id in ("B603", "B607", "B404") or cls is None:
        if alert.rule_id in ("B603", "B607") and not flows:
            return {"verdict": "false_positive", "vuln_class": "command_injection", "tainted": [],
                    "reason": "subprocess arguments are literals; no caller input reaches the call"}
        return {"verdict": "escalate", "vuln_class": "other", "reason": f"rule {alert.rule_id} is not supported by the automatic fixer"}
    if not flows:
        return {"verdict": "false_positive", "vuln_class": cls, "tainted": [],
                "reason": "no function parameter (or value derived from one) reaches the flagged expression; only constants are interpolated"}
    return {"verdict": "real", "vuln_class": cls, "tainted": flows,
            "reason": f"caller-controlled value(s) {flows} flow into the flagged expression"}


# ---------------------------------------------------------------- editing helpers
def _apply(source: str, edits: List[Edit], inserts: List[Tuple[int, str]] = ()) -> str:
    lines = source.split("\n")
    for line, c0, c1, text in sorted(edits, reverse=True):
        lines[line - 1] = lines[line - 1][:c0] + text + lines[line - 1][c1:]
    for after_line, text in sorted(inserts, reverse=True):
        lines[after_line:after_line] = text.split("\n")
    return "\n".join(lines)


def _span(node) -> Optional[Tuple[int, int, int]]:
    if node.lineno != node.end_lineno:
        return None
    return node.lineno, node.col_offset, node.end_col_offset


def _ensure_import(source: str, module: str) -> str:
    if re.search(rf"^import {module}\b", source, re.M):
        return source
    tree = ast.parse(source)
    imports = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    if imports:
        return _apply(source, [], [(imports[0].lineno - 1, f"import {module}")])
    return f"import {module}\n" + source


def _body_start(fn) -> Tuple[int, int]:
    first = fn.body[0]
    if isinstance(first, ast.Expr) and isinstance(getattr(first, "value", None), ast.Constant) and isinstance(first.value.value, str) and len(fn.body) > 1:
        return fn.body[1].lineno, fn.body[1].col_offset
    return first.lineno, first.col_offset


# ---------------------------------------------------------------- SQL
def _flatten(node) -> Optional[list]:
    if isinstance(node, ast.JoinedStr):
        out = []
        for v in node.values:
            out.append(("text", v.value) if isinstance(v, ast.Constant) else ("expr", v.value))
        return out
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        l, r = _flatten(node.left), _flatten(node.right)
        return None if l is None or r is None else l + r
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [("text", node.value)]
    return [("expr", node)]


def patch_sqli(source: str, alert) -> Optional[str]:
    tree = ast.parse(source)
    fn = find_function(tree, alert.function)
    stmt = statement_at(fn, alert.line)
    tainted = tainted_names(fn)
    sql_node = None
    for n in ast.walk(stmt):
        if isinstance(n, (ast.JoinedStr, ast.BinOp)):
            parts = _flatten(n)
            if parts and any(k == "text" and re.search(r"\b(select|insert|update|delete)\b", v, re.I) for k, v in parts):
                sql_node = n
                break
    if sql_node is None or _span(sql_node) is None:
        return None
    parts = _flatten(sql_node)
    template, params = "", []
    for kind, v in parts:
        if kind == "text":
            template += v
        else:
            if not ({x.id for x in ast.walk(v) if isinstance(x, ast.Name)} & tainted):
                return None  # non-caller values (e.g. table names) cannot be bound as parameters
            template += "\x00"
            params.append(ast.unparse(v))
    template = re.sub(r"'\x00'|\"\x00\"|\x00", "?", template)
    lit = '"' + template.replace("\\", "\\\\").replace('"', '\\"') + '"'
    tup = "(" + ", ".join(params) + ("," if len(params) == 1 else "") + ")"
    line, c0, c1 = _span(sql_node)
    parent_call = next((c for c in ast.walk(stmt) if isinstance(c, ast.Call) and c.args and c.args[0] is sql_node), None)
    if parent_call is not None:
        return _apply(source, [(line, c0, c1, f"{lit}, {tup}")])
    if isinstance(stmt, ast.Assign) and stmt.value is sql_node and isinstance(stmt.targets[0], ast.Name):
        var = stmt.targets[0].id
        edits: List[Edit] = [(line, c0, c1, lit)]
        for c in ast.walk(fn):
            if isinstance(c, ast.Call) and len(c.args) == 1 and isinstance(c.args[0], ast.Name) and c.args[0].id == var and _span(c.args[0]):
                l2, a, b = _span(c.args[0])
                edits.append((l2, a, b, f"{var}, {var}_params"))
        indent = " " * stmt.col_offset
        return _apply(source, edits, [(stmt.end_lineno, f"{indent}{var}_params = {tup}")])
    return None


# ---------------------------------------------------------------- command injection
def patch_cmdi(source: str, alert) -> Optional[str]:
    tree = ast.parse(source)
    fn = find_function(tree, alert.function)
    stmt = statement_at(fn, alert.line)
    popen = system = None
    for n in ast.walk(stmt):
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and isinstance(n.func.value, ast.Name) and n.func.value.id == "os":
            if n.func.attr == "popen":
                popen = n
            elif n.func.attr == "system":
                system = n
    target = popen or system
    if target is None or not target.args:
        return None
    parts = _flatten(target.args[0])
    if parts is None:
        return None
    exprs, text = [], ""
    for kind, v in parts:
        if kind == "text":
            text += v
        else:
            text += f"\x01{len(exprs)}\x01"
            exprs.append(ast.unparse(v))
    try:
        tokens = shlex.split(text)
    except ValueError:
        return None
    code = []
    for tok in tokens:
        pieces = re.split(r"\x01(\d+)\x01", tok)
        if len(pieces) == 3 and pieces[0] == "" and pieces[2] == "":
            code.append(exprs[int(pieces[1])])
        elif len(pieces) == 1:
            code.append(repr(tok))
        else:
            segs = [repr(p) if i % 2 == 0 else f"str({exprs[int(p)]})" for i, p in enumerate(pieces) if not (i % 2 == 0 and p == "")]
            code.append(" + ".join(segs))
    arglist = "[" + ", ".join(code) + "]"
    if popen is not None:
        outer = next((c for c in ast.walk(stmt) if isinstance(c, ast.Call) and isinstance(c.func, ast.Attribute) and c.func.attr == "read" and c.func.value is popen), None)
        if outer is None or _span(outer) is None:
            return None
        line, c0, c1 = _span(outer)
        new = f"subprocess.run({arglist}, capture_output=True, text=True, check=False).stdout"
    else:
        if _span(system) is None:
            return None
        line, c0, c1 = _span(system)
        new = f"subprocess.run({arglist}, check=False).returncode"
    return _ensure_import(_apply(source, [(line, c0, c1, new)]), "subprocess")


# ---------------------------------------------------------------- path traversal
def patch_path(source: str, alert, attempt: int) -> Optional[str]:
    tree = ast.parse(source)
    fn = find_function(tree, alert.function)
    stmt = statement_at(fn, alert.line)
    tainted = [p for p in params_of(fn) if p in header_names(stmt)]
    if attempt <= 1:  # first draft: blacklist sanitising (deliberately naive; the exploit test is expected to reject it)
        if not tainted:
            return None
        line, col = _body_start(fn)
        return _apply(source, [], [(line - 1, " " * col + f'{tainted[0]} = {tainted[0]}.replace("../", "")')])
    open_call = next((c for c in ast.walk(stmt) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name) and c.func.id == "open"), None)
    if open_call is None or not open_call.args:
        return None
    join = open_call.args[0]
    if not (isinstance(join, ast.Call) and ast.unparse(join.func) == "os.path.join" and _span(join.func)):
        return None
    line, c0, c1 = _span(join.func)
    patched = _apply(source, [(line, c0, c1, "_safe_join")], [(fn.lineno - 1, SAFE_JOIN + "\n")])
    return _ensure_import(patched, "os")


# ---------------------------------------------------------------- adversarial patches used by the benchmark
def sabotage(source: str, alert, mode: str) -> Optional[str]:
    tree = ast.parse(source)
    fn = find_function(tree, alert.function)
    lines = source.split("\n")
    first, last = fn.body[0], fn.end_lineno
    if mode == "breaking":
        indent = " " * first.col_offset
        return "\n".join(lines[:first.lineno - 1] + [f"{indent}return None"] + lines[last:])
    if mode == "gaming":
        line, col = _body_start(fn)
        p = params_of(fn)[0]
        guard = [f"{' ' * col}if \"' OR '1'='1\" in str({p}) or \"OR 1=1\" in str({p}):", f"{' ' * (col + 4)}return None"]
        return _apply(source, [], [(line - 1, "\n".join(guard))])
    return None


def patch(source: str, alert, triage_result: dict, attempt: int, sabotage_mode: Optional[str] = None) -> Optional[str]:
    if sabotage_mode:
        return sabotage(source, alert, sabotage_mode)
    cls = triage_result["vuln_class"]
    if cls == "sqli":
        return patch_sqli(source, alert)
    if cls == "command_injection":
        return patch_cmdi(source, alert)
    if cls == "path_traversal":
        return patch_path(source, alert, attempt)
    return None


# ---------------------------------------------------------------- reviewer
def review(new_source: str, alert, triage_result: dict) -> dict:
    fn = find_function(ast.parse(new_source), alert.function)
    cls = triage_result["vuln_class"]
    concerns = []
    calls = [n for n in ast.walk(fn) if isinstance(n, ast.Call)]
    if cls == "sqli":
        if not any(isinstance(c.func, ast.Attribute) and c.func.attr in ("execute", "executemany") and len(c.args) >= 2 for c in calls):
            concerns.append("query is not parameterised")
    elif cls == "path_traversal":
        used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)}
        if "_safe_join" not in used and not any("realpath" in ast.unparse(c.func) or "commonpath" in ast.unparse(c.func) for c in calls):
            concerns.append("blacklist-style sanitising is bypassable; enforce directory containment instead")
    elif cls == "command_injection":
        if any(ast.unparse(c.func) in ("os.system", "os.popen") for c in calls) or any(k.arg == "shell" and getattr(k.value, "value", False) for c in calls for k in c.keywords):
            concerns.append("shell is still used with caller input")
    return {"approve": not concerns, "concerns": concerns, "engine": "rule-based reviewer"}
