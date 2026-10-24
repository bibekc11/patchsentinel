"""LangGraph state machine: triage -> exploit -> patch -> verify -> review, with capped retries and explicit escalation."""
from __future__ import annotations
import difflib, time
from pathlib import Path

from langgraph.graph import END, StateGraph

from . import exploit, verifier
from .analysis import find_function, params_of, tainted_names
from .models import KIND_BY_CLASS, RunState


def unified_diff(old: str, new: str, name: str) -> str:
    return "\n".join(difflib.unified_diff(old.splitlines(), new.splitlines(), f"a/{name}", f"b/{name}", lineterm=""))


def build_graph(agents, audit, policy, alert, repo: Path):
    max_tries = int(policy.get("max_retries", 3))
    src = (repo / alert.file).read_text(encoding="utf-8")

    def note(state, event, **data):
        audit.log(event, alert=alert.id, **data)
        return list(state.get("history", [])) + [{"event": event, **data}]

    def triage_node(state):
        t = agents.triage(repo, alert)
        hist = note(state, "triage", verdict=t["verdict"], vuln_class=t.get("vuln_class"), reason=t.get("reason"), engine=t.get("engine"))
        out = {"triage": t, "history": hist}
        if t["verdict"] == "false_positive":
            out.update(status="rejected_false_positive", reason=t["reason"])
        elif t["verdict"] != "real":
            out.update(status="escalated", reason=t["reason"])
        return out

    def exploit_node(state):
        import ast
        t = state["triage"]
        tree = ast.parse(src)
        fn = find_function(tree, alert.function)
        params = params_of(fn)
        tainted = [p for p in params if p in tainted_names(fn)]
        idx = params.index(tainted[0]) if tainted else 0
        module = exploit.module_name(alert.file)
        benign = exploit.mine_benign(repo, module, alert.function) or agents.benign_fallback(src, alert)
        if not benign:
            return {"status": "escalated", "reason": "no known-good inputs found in the project's tests; add a test that calls this function",
                    "history": note(state, "exploit_blocked", reason="no benign inputs")}
        spec = {"module": module, "function": alert.function, "kind": KIND_BY_CLASS[t["vuln_class"]], "payload_index": idx,
                "benign_cases": benign}
        expected, err = exploit.record_expected(repo, spec)
        if expected is None:
            return {"status": "escalated", "reason": f"could not execute function in sandbox: {err[-200:]}",
                    "history": note(state, "exploit_blocked", reason=err[-200:])}
        spec["expected"] = expected
        base = verifier.baseline(repo, spec)
        hist = note(state, "exploit_baseline", kind=spec["kind"], benign_cases=benign, checks={k: v for k, v in base.items()})
        out = {"spec": spec, "history": hist, "attempt": 0, "feedback": ""}
        if not base["suite_green_on_original"][0] or not base["benign_ok_on_original"][0]:
            out.update(status="escalated", reason="baseline is not green: " + verifier.failures(base))
        elif not base["exploit_reproduced"][0]:
            out.update(status="escalated_unreproducible",
                       reason="exploit could not be reproduced; returned to triage as a possible false positive for a human to confirm")
        return out

    def patch_node(state):
        attempt = state.get("attempt", 0) + 1
        new = agents.patch(repo, alert, state["triage"], attempt, state.get("feedback", ""))
        if new is None:
            return {"attempt": attempt, "status": "escalated", "reason": "patch agent produced no usable patch",
                    "history": note(state, "patch", attempt=attempt, produced=False)}
        return {"attempt": attempt, "new_source": new,
                "history": note(state, "patch", attempt=attempt, produced=True, changed_lines=verifier.changed_lines(src, new))}

    def verify_node(state):
        checks = verifier.verify_patch(repo, alert, state["spec"], state["new_source"], policy)
        ok = all(v[0] for v in checks.values())
        out = {"checks": checks, "history": note(state, "verify", attempt=state["attempt"], passed=ok,
                                                 checks={k: [v[0], v[1][-160:]] for k, v in checks.items()})}
        if not ok:
            out["feedback"] = verifier.failures(checks)
            if state["attempt"] >= max_tries:
                out.update(status="escalated_retries_exhausted", reason="verifier rejected every attempt: " + out["feedback"][:300])
        return out

    def review_node(state):
        diff = unified_diff(src, state["new_source"], alert.file)
        r = agents.review(alert, state["triage"], diff, state["new_source"])
        out = {"review": r, "history": note(state, "review", attempt=state["attempt"], approve=r["approve"], concerns=r.get("concerns"), engine=r.get("engine"))}
        if r["approve"]:
            out.update(status="verified", reason="all checks passed; awaiting human approval")
        else:
            out["feedback"] = "reviewer: " + "; ".join(r.get("concerns", []))
            if state["attempt"] >= max_tries:
                out.update(status="escalated_retries_exhausted", reason="reviewer rejected every attempt: " + out["feedback"][:300])
        return out

    def done(state):
        return "end" if state.get("status") else "go"

    g = StateGraph(RunState)
    for name, fn in [("triage", triage_node), ("exploit", exploit_node), ("patch", patch_node), ("verify", verify_node), ("review", review_node)]:
        g.add_node(name, fn)
    g.set_entry_point("triage")
    g.add_conditional_edges("triage", done, {"end": END, "go": "exploit"})
    g.add_conditional_edges("exploit", done, {"end": END, "go": "patch"})
    g.add_conditional_edges("patch", done, {"end": END, "go": "verify"})
    g.add_conditional_edges("verify", lambda s: "end" if s.get("status") else ("patch" if not all(v[0] for v in s["checks"].values()) else "review"),
                            {"end": END, "patch": "patch", "review": "review"})
    g.add_conditional_edges("review", lambda s: "end" if s.get("status") else "patch", {"end": END, "patch": "patch"})
    return g.compile()


def run_alert(agents, audit, policy, alert, repo: Path) -> dict:
    t0 = time.time()
    audit.log("alert_received", alert=alert.id, rule=alert.rule_id, file=alert.file, function=alert.function, line=alert.line)
    graph = build_graph(agents, audit, policy, alert, repo)
    final = graph.invoke({"alert": alert.to_dict(), "repo": str(repo), "attempt": 0, "history": []}, {"recursion_limit": 60})
    status = final.get("status", "escalated")
    audit.log("alert_outcome", alert=alert.id, status=status, reason=final.get("reason", ""))
    src = (repo / alert.file).read_text(encoding="utf-8")
    final["diff"] = unified_diff(src, final["new_source"], alert.file) if status == "verified" else ""
    final.update(alert=alert.to_dict(), status=status, seconds=round(time.time() - t0, 2))
    return final
