import json, shutil, sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from patchsentinel import offline_rules as R, sandbox, scanners, verifier  # noqa: E402
from patchsentinel.agents import Agents  # noqa: E402
from patchsentinel.audit import AuditLog, verify_chain  # noqa: E402
from patchsentinel.graph import run_alert  # noqa: E402
from patchsentinel.report import DEFAULT_POLICY  # noqa: E402

DEMO = ROOT / "demo_target"


def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(4):
        log.log("evt", n=i)
    assert verify_chain(tmp_path / "a.jsonl")[0]
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    e = json.loads(lines[2]); e["data"]["n"] = 99; lines[2] = json.dumps(e)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert not verify_chain(tmp_path / "a.jsonl")[0]


def test_integrity_flags_hardcoded_exploit_strings():
    orig = "def f(x):\n    return x\n"
    gamed = "def f(x):\n    if \"' OR '1'='1\" in x:\n        return None\n    return x\n"
    ok, msg = verifier.integrity(orig, gamed, "PAYLOADS = [\"' OR '1'='1\"]")
    assert not ok and "test gaming" in msg
    assert verifier.integrity(orig, orig + "\n# nothing\n", "PAYLOADS = ['zzzz']")[0]


def test_sandbox_blocks_network_and_times_out(tmp_path):
    rc, out = sandbox.run(tmp_path, ["-c", "import socket; socket.create_connection(('example.com', 80), 2)"])
    assert rc != 0 and "network disabled" in out
    rc, out = sandbox.run(tmp_path, ["-c", "import time; time.sleep(5)"], timeout=1)
    assert rc == 124


def test_scanner_finds_ten_cases_and_triage_splits_them():
    alerts = scanners.scan(DEMO, DEFAULT_POLICY)
    assert len(alerts) == 10
    verdicts = {a.function: R.triage((DEMO / a.file).read_text(), a)["verdict"] for a in alerts}
    assert verdicts["count_users"] == "false_positive" and verdicts["tool_version"] == "false_positive"
    assert sum(v == "real" for v in verdicts.values()) == 8


class FakeLLM:
    """Stands in for a model so the LLM code path (JSON parsing, code extraction, reviewer) is exercised without network."""
    name = "fake"

    def __init__(self, patched):
        self.patched = patched

    def complete(self, system, user):
        if system.startswith("You are the TRIAGE"):
            return '```json\n{"verdict":"real","vuln_class":"sqli","reason":"user input reaches the query"}\n```'
        if system.startswith("You are the PATCH"):
            return "Here is the fix:\n```python\n" + self.patched + "```"
        if system.startswith("You are the independent REVIEWER"):
            return '{"approve": true, "concerns": []}'
        return "{}"


def test_llm_code_path_end_to_end(tmp_path):
    alert = next(a for a in scanners.scan(DEMO, DEFAULT_POLICY) if a.function == "get_user")
    src = (DEMO / alert.file).read_text()
    patched = R.patch(src, alert, {"vuln_class": "sqli"}, 1)
    res = run_alert(Agents(FakeLLM(patched)), AuditLog(tmp_path / "a.jsonl"), DEFAULT_POLICY, alert, DEMO)
    assert res["status"] == "verified" and res["triage"]["engine"] == "fake"


def test_llm_garbage_is_never_trusted(tmp_path):
    class Garbage(FakeLLM):
        def complete(self, system, user):
            return "I think it is fine, no JSON here"
    alert = next(a for a in scanners.scan(DEMO, DEFAULT_POLICY) if a.function == "get_user")
    res = run_alert(Agents(Garbage("")), AuditLog(tmp_path / "a.jsonl"), DEFAULT_POLICY, alert, DEMO)
    assert res["status"] == "escalated"


def test_full_benchmark_matches_expected(tmp_path):
    from patchsentinel.__main__ import main
    with pytest.raises(SystemExit) as e:
        main(["benchmark", "--out", str(tmp_path)])
    assert e.value.code == 0
