"""Small AST helpers shared by triage, patching and test generation."""
from __future__ import annotations
import ast
from typing import List, Optional, Set


def find_function(tree: ast.AST, name: str) -> Optional[ast.FunctionDef]:
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name:
            return n
    return None


def params_of(fn) -> List[str]:
    return [a.arg for a in fn.args.args if a.arg not in ("self", "cls")]


def names_in(node: ast.AST) -> Set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def tainted_names(fn) -> Set[str]:
    """Parameters plus local variables derived from them (fixpoint over simple assignments)."""
    tainted = set(params_of(fn))
    changed = True
    while changed:
        changed = False
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign) and names_in(n.value) & tainted:
                for t in n.targets:
                    for nm in names_in(t):
                        if nm not in tainted:
                            tainted.add(nm)
                            changed = True
    return tainted


def statement_at(fn, line: int) -> Optional[ast.stmt]:
    best = None
    for n in ast.walk(fn):
        if isinstance(n, ast.stmt) and n.lineno <= line <= (n.end_lineno or n.lineno):
            span = (n.end_lineno or n.lineno) - n.lineno
            if best is None or span < ((best.end_lineno or best.lineno) - best.lineno):
                best = n
    return best


def header_names(stmt: ast.stmt) -> Set[str]:
    """Names used in a statement, ignoring the body of compound statements (e.g. `with open(...)`)."""
    if isinstance(stmt, (ast.With, ast.AsyncWith)):
        out: Set[str] = set()
        for item in stmt.items:
            out |= names_in(item.context_expr)
        return out
    return names_in(stmt)


def string_constants(source: str) -> Set[str]:
    try:
        return {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    except SyntaxError:
        return set()
