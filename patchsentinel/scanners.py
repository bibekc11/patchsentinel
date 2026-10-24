"""Scanner adapters: Bandit (live), SARIF (any scanner), and one built-in AST rule."""
from __future__ import annotations
import ast, json, subprocess, sys
from pathlib import Path
from typing import List, Optional

from .models import Alert, SEVERITY_ORDER

SKIP_DIRS = {".git", "__pycache__", ".venv", "venv", "node_modules", ".patchsentinel"}
SAFE_PATH_MARKERS = {"realpath", "resolve", "commonpath", "commonprefix", "is_relative_to", "_safe_join", "safe_join"}


def _py_files(repo: Path):
    for p in repo.rglob("*.py"):
        rel = p.relative_to(repo)
        if SKIP_DIRS & set(rel.parts) or "tests" in rel.parts or p.name.startswith("test_"):
            continue
        yield p, rel.as_posix()


def enclosing_function(source: str, line: int) -> Optional[str]:
    best = None
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.lineno <= line <= (node.end_lineno or node.lineno):
            if best is None or node.lineno >= best.lineno:
                best = node
    return best.name if best else None


def run_bandit(repo: Path) -> List[Alert]:
    proc = subprocess.run(
        [sys.executable, "-m", "bandit", "-r", str(repo), "-f", "json", "-q", "-x", str(repo / "tests")],
        capture_output=True, text=True, timeout=120)
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    alerts = []
    for r in data.get("results", []):
        rel = Path(r["filename"]).resolve().relative_to(repo.resolve()).as_posix()
        alerts.append(Alert(id="", rule_id=r["test_id"], severity=r["issue_severity"].upper(), file=rel,
                            line=r["line_number"], message=r["issue_text"], source="bandit"))
    return alerts


def builtin_path_rule(repo: Path) -> List[Alert]:
    """Flag open() calls whose path is built from a function parameter with no containment check."""
    alerts = []
    for p, rel in _py_files(repo):
        try:
            tree = ast.parse(p.read_text(encoding="utf-8"))
        except SyntaxError:
            continue
        for fn in [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]:
            params = {a.arg for a in fn.args.args}
            names_used = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name)} | {n.attr for n in ast.walk(fn) if isinstance(n, ast.Attribute)}
            if SAFE_PATH_MARKERS & names_used:
                continue
            for call in [n for n in ast.walk(fn) if isinstance(n, ast.Call)]:
                if isinstance(call.func, ast.Name) and call.func.id == "open" and call.args:
                    used = {n.id for n in ast.walk(call.args[0]) if isinstance(n, ast.Name)}
                    if used & params:
                        alerts.append(Alert(id="", rule_id="PS-PATH-TRAVERSAL", severity="HIGH", file=rel, line=call.lineno,
                                            message="File path built from caller input without a containment check", source="builtin"))
    return alerts


def load_sarif(path: Path, repo: Path) -> List[Alert]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    alerts = []
    for run in data.get("runs", []):
        for res in run.get("results", []):
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine", 1)
            sev = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(res.get("level", "warning"), "MEDIUM")
            alerts.append(Alert(id="", rule_id=res.get("ruleId", "SARIF"), severity=sev, file=uri.replace("file://", "").lstrip("./"),
                                line=line, message=(res.get("message") or {}).get("text", ""), source="sarif"))
    return alerts


def scan(repo: Path, policy: dict, sarif: Optional[Path] = None) -> List[Alert]:
    repo = Path(repo)
    alerts: List[Alert] = []
    if "bandit" in policy.get("scanners", ["bandit"]):
        alerts += run_bandit(repo)
    if "builtin" in policy.get("scanners", ["builtin"]):
        alerts += builtin_path_rule(repo)
    if sarif:
        alerts += load_sarif(sarif, repo)
    ignore = set(policy.get("ignore_rules", []))
    grouped = {}
    for a in alerts:
        if a.rule_id in ignore:
            continue
        f = repo / a.file
        if not f.exists():
            continue
        a.function = enclosing_function(f.read_text(encoding="utf-8"), a.line)
        key = (a.file, a.function or a.line)
        if key not in grouped or SEVERITY_ORDER.get(a.severity, 0) > SEVERITY_ORDER.get(grouped[key].severity, 0):
            grouped[key] = a
    out = sorted(grouped.values(), key=lambda x: (x.file, x.line))
    for i, a in enumerate(out, 1):
        a.id = f"A{i:02d}"
    return out


def still_flagged(patched_repo: Path, alert: Alert, policy: dict) -> bool:
    """Re-scan a patched copy; the alert counts as still present if the same rule fires in the same function."""
    for a in scan(patched_repo, {**policy, "ignore_rules": []}):
        if a.file == alert.file and a.function == alert.function and a.rule_id == alert.rule_id:
            return True
    return False
