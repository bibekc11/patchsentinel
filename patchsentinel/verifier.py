"""Deterministic acceptance gate. No language model is involved in any decision made here."""
from __future__ import annotations
import difflib
from pathlib import Path
from typing import Dict, Tuple

from . import exploit, sandbox, scanners
from .analysis import string_constants
from .models import Alert

MAX_CHANGED_LINES = 80


def changed_lines(old: str, new: str) -> int:
    return sum(1 for l in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0)
               if l[:1] in "+-" and not l.startswith(("+++", "---")))


def integrity(orig_source: str, new_source: str, test_text: str) -> Tuple[bool, str]:
    """Reject patches that special-case the exploit payload or are suspiciously large."""
    fresh = [c for c in string_constants(new_source) - string_constants(orig_source) if len(c) >= 4 and c in test_text]
    if fresh:
        return False, f"patch hard-codes exploit-test strings (test gaming): {sorted(fresh)[:3]}"
    n = changed_lines(orig_source, new_source)
    if n > MAX_CHANGED_LINES:
        return False, f"patch too large ({n} changed lines)"
    return True, f"{n} changed lines, no exploit strings embedded"


def baseline(repo: Path, spec: Dict) -> Dict:
    """Checks on the ORIGINAL code: suite is green, benign behaviour passes, and the exploit test fails (flaw is real)."""
    work = sandbox.copy_repo(repo)
    exploit.write_tests(work, spec)
    suite_rc, suite_out = sandbox.run_pytest(work, ["--ignore=.patchsentinel"])
    ben_rc, ben_out = exploit.run_node(work, "test_benign_behaviour_preserved")
    exp_rc, exp_out = exploit.run_node(work, "test_exploit_blocked")
    res = {
        "suite_green_on_original": (suite_rc == 0, "existing tests pass" if suite_rc == 0 else suite_out[-300:]),
        "benign_ok_on_original": (ben_rc == 0, "recorded behaviour reproduced" if ben_rc == 0 else ben_out[-300:]),
        "exploit_reproduced": (exp_rc == 1, "exploit test FAILS on original code (flaw is real)" if exp_rc == 1
                               else ("exploit test passed: flaw not reproducible" if exp_rc == 0 else exp_out[-300:])),
    }
    return res


def verify_patch(repo: Path, alert: Alert, spec: Dict, new_source: str, policy: dict) -> Dict:
    work = sandbox.copy_repo(repo)
    target = work / alert.file
    orig_source = (Path(repo) / alert.file).read_text(encoding="utf-8")
    target.write_text(new_source, encoding="utf-8")
    exploit.write_tests(work, spec)
    test_text = exploit.BODIES[spec["kind"]]  # exploit payloads only, not recorded benign outputs

    try:
        compile(new_source, alert.file, "exec")
        syntax = (True, "patched file compiles")
    except SyntaxError as e:
        return {"patched_file_compiles": (False, f"syntax error: {e}")}

    ex_rc, ex_out = exploit.run_node(work, "test_exploit_blocked")
    be_rc, be_out = exploit.run_node(work, "test_benign_behaviour_preserved")
    su_rc, su_out = sandbox.run_pytest(work, ["--ignore=.patchsentinel"])
    flagged = scanners.still_flagged(work, alert, policy)
    ok_int, msg_int = integrity(orig_source, new_source, test_text)
    return {
        "patched_file_compiles": syntax,
        "exploit_blocked_after_patch": (ex_rc == 0, "exploit test passes on patched code" if ex_rc == 0 else ex_out[-400:]),
        "benign_behaviour_preserved": (be_rc == 0, "same outputs as original on known-good inputs" if be_rc == 0 else be_out[-400:]),
        "existing_tests_pass": (su_rc == 0, "existing suite green" if su_rc == 0 else su_out[-400:]),
        "scanner_clear": (not flagged, "rule no longer fires in this function" if not flagged else f"{alert.rule_id} still fires in {alert.function}()"),
        "integrity": (ok_int, msg_int),
    }


def failures(checks: Dict) -> str:
    return "; ".join(f"{k}: {v[1]}" for k, v in checks.items() if not v[0])
