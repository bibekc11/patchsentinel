"""The four role-separated agents. Each call is stateless: context is passed in explicitly, so agents cannot see each other's reasoning."""
from __future__ import annotations
import ast, json
from pathlib import Path

from . import offline_rules as R
from .analysis import find_function, params_of
from .llm import extract_code, extract_json
from .models import CLASS_BY_RULE, KIND_BY_CLASS

TRIAGE_SYS = ("You are the TRIAGE agent in a security remediation pipeline. Decide if a scanner alert is a real, exploitable flaw, "
              "a false positive, or needs a human. Reply with JSON only: "
              '{"verdict":"real|false_positive|escalate","vuln_class":"sqli|path_traversal|command_injection|other","reason":"one sentence"}')
BENIGN_SYS = ("You are the EXPLOIT agent. Given a function, propose 2 known-good argument lists (JSON) it handles normally. "
              'Reply with JSON only: {"benign_cases":[[...],[...]]}')
PATCH_SYS = ("You are the PATCH agent. Fix the vulnerability with the smallest change. Rules: keep public function names, signatures and behaviour "
             "for valid inputs; fix the root cause (parameterised queries; resolve paths and enforce directory containment; argument lists, never a shell); "
             "never special-case test or exploit strings; do not edit anything except this file. Reply with the COMPLETE corrected file in one ```python block.")
REVIEW_SYS = ("You are the independent REVIEWER agent. You have not seen the patcher's reasoning. Be sceptical: look for scope creep, removed functionality, "
              "blacklist-style fixes, hard-coded special cases, and anything that only satisfies tests. "
              'Reply with JSON only: {"approve":true|false,"concerns":["..."]}')


class Agents:
    def __init__(self, backend):
        self.b = backend
        self.llm = backend.name != "offline"

    # ---- triage
    def triage(self, repo: Path, alert) -> dict:
        source = (repo / alert.file).read_text(encoding="utf-8")
        static = R.triage(source, alert)
        if not self.llm:
            return {**static, "engine": "rule-based"}
        fn = find_function(ast.parse(source), alert.function or "")
        snippet = ast.get_source_segment(source, fn) if fn else source[:3000]
        user = (f"Alert: {alert.rule_id} ({alert.severity}) at {alert.file}:{alert.line}: {alert.message}\n"
                f"Static data-flow hint (parameters reaching the flagged statement): {static.get('tainted')}\n\nFunction:\n{snippet}")
        try:
            out = extract_json(self.b.complete(TRIAGE_SYS, user))
        except Exception as e:  # malformed model output is never trusted
            return {"verdict": "escalate", "vuln_class": "other", "reason": f"triage model reply unusable: {e}", "engine": self.b.name}
        out["tainted"] = static.get("tainted", [])
        if out.get("verdict") == "real" and out.get("vuln_class") not in KIND_BY_CLASS:
            out.update(verdict="escalate", reason="bug class not supported by the automatic fixer")
        out["engine"] = self.b.name
        return out

    # ---- exploit
    def benign_fallback(self, source: str, alert) -> list:
        if not self.llm:
            return []
        fn = find_function(ast.parse(source), alert.function)
        try:
            out = extract_json(self.b.complete(BENIGN_SYS, ast.get_source_segment(source, fn)))
            return [c for c in out.get("benign_cases", []) if isinstance(c, list)][:2]
        except Exception:
            return []

    # ---- patch
    def patch(self, repo: Path, alert, triage: dict, attempt: int, feedback: str):
        source = (repo / alert.file).read_text(encoding="utf-8")
        if not self.llm:
            return R.patch(source, alert, triage, attempt, self.b.sabotage.get(alert.function))
        user = (f"File: {alert.file}\nAlert: {alert.rule_id} at line {alert.line} in {alert.function}(): {alert.message}\n"
                f"Triage: {triage.get('reason')}\nAttempt {attempt}. Previous failure (empty on first try): {feedback or 'none'}\n\n```python\n{source}```")
        try:
            return extract_code(self.b.complete(PATCH_SYS, user))
        except Exception:
            return None

    # ---- review
    def review(self, alert, triage: dict, diff: str, new_source: str) -> dict:
        if not self.llm:
            return R.review(new_source, alert, triage)
        user = f"Alert: {alert.rule_id} in {alert.function}() ({triage.get('vuln_class')}).\n\nProposed diff:\n{diff}"
        try:
            out = extract_json(self.b.complete(REVIEW_SYS, user))
            out["engine"] = self.b.name
            return out
        except Exception as e:
            return {"approve": False, "concerns": [f"reviewer reply unusable: {e}"], "engine": self.b.name}
