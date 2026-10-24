"""PatchSentinel Mission Control: web UI over the unchanged engine. Run: python -m patchsentinel.webapp"""
import json, threading, time
from pathlib import Path
from flask import Flask, Response, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parent.parent
app = Flask(__name__, static_folder=str(Path(__file__).parent / "web"))
S = {"running": False, "results": [], "audit": None, "out": None, "policy": None, "repo": None, "error": None, "t0": 0, "provider": "offline"}


def _worker(provider, demo):
    from . import scanners
    from .agents import Agents
    from .audit import AuditLog
    from .graph import run_alert
    from .llm import get_backend
    from .report import load_policy
    from .__main__ import BENCH_SABOTAGE
    try:
        repo = ROOT / "demo_target"
        policy = load_policy(str(ROOT / "policy.json"))
        out = ROOT / "out" / time.strftime("ui_%Y%m%d_%H%M%S"); out.mkdir(parents=True, exist_ok=True)
        audit = AuditLog(out / "audit.jsonl")
        S.update(audit=audit, out=out, policy=policy, repo=repo, t0=time.time(), provider=provider)
        agents = Agents(get_backend(provider, BENCH_SABOTAGE if demo else None))
        alerts = scanners.scan(repo, policy)
        audit.log("run_started", repo=repo.name, provider=provider, alerts=len(alerts))
        for a in alerts:
            S["results"].append(run_alert(agents, audit, policy, a, repo))
    except BaseException as e:  # surfaced in the UI, never silent
        S["error"] = f"{type(e).__name__}: {e}"
    finally:
        S["running"] = False


@app.post("/api/run")
def run():
    if S["running"]:
        return jsonify(error="already running"), 409
    body = request.get_json(silent=True) or {}
    S.update(running=True, results=[], error=None, audit=None, out=None)
    threading.Thread(target=_worker, args=(body.get("provider", "offline"), body.get("demo", True)), daemon=True).start()
    return jsonify(ok=True)


@app.get("/api/state")
def state():
    from .report import roi
    pol = S["policy"] or {"manual_fix_minutes": 60, "manual_triage_minutes": 15, "approver_roles": ["reviewer", "admin"]}
    slim = [{k: v for k, v in r.items() if k in ("alert", "status", "reason", "attempt", "diff", "checks", "triage", "review", "seconds")} for r in S["results"]]
    q = request.args
    p = {**pol, "manual_fix_minutes": float(q.get("fix", pol["manual_fix_minutes"])), "manual_triage_minutes": float(q.get("triage", pol["manual_triage_minutes"]))}
    return jsonify(running=S["running"], error=S["error"], results=slim, roles=pol["approver_roles"], provider=S["provider"],
                   roi=roi(S["results"], p, (time.time() - S["t0"]) if S["t0"] else 0))


@app.get("/api/events")
def events():
    def gen():
        pos = 0
        while True:
            path = (S["out"] / "audit.jsonl") if S["out"] else None
            if path and path.exists():
                lines = path.read_text(encoding="utf-8").splitlines()
                for ln in lines[pos:]:
                    yield f"data: {ln}\n\n"
                pos = len(lines)
            if not S["running"] and (pos or S["error"]):
                yield "event: done\ndata: {}\n\n"; return
            time.sleep(0.35)
    return Response(gen(), mimetype="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/approve")
def approve():
    from .report import export, write_report
    from .audit import verify_chain
    b = request.get_json(force=True)
    pol, audit = S["policy"], S["audit"]
    if S["running"] or not audit:
        return jsonify(error="run not finished"), 409
    if b.get("role") not in pol["approver_roles"]:
        audit.log("approval_refused", approver=b.get("approver"), role=b.get("role"), reason="role not permitted")
        return jsonify(error=f"role '{b.get('role')}' may not approve fixes (allowed: {pol['approver_roles']})"), 403
    r = next((x for x in S["results"] if x["alert"]["id"] == b.get("alert")), None)
    if not r or r["status"] != "verified":
        return jsonify(error="only verified fixes can be decided"), 400
    r["status"] = "approved" if b.get("approve") else "declined"
    audit.log("human_decision", alert=b["alert"], approver=b.get("approver", "unnamed"), role=b["role"], decision=r["status"], mode="web")
    export(S["results"], S["repo"], S["out"], False, audit)
    write_report(S["out"], S["results"], pol, time.time() - S["t0"], S["provider"], verify_chain(S["out"] / "audit.jsonl")[1])
    return jsonify(ok=True, status=r["status"])


@app.get("/api/verify")
def verify():
    from .audit import verify_chain
    if not S["out"] or not (S["out"] / "audit.jsonl").exists():
        return jsonify(ok=False, message="no audit log yet")
    ok, msg = verify_chain(S["out"] / "audit.jsonl")
    return jsonify(ok=ok, message=msg)


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


if __name__ == "__main__":
    print("PatchSentinel Mission Control -> http://127.0.0.1:5057")
    app.run(host="127.0.0.1", port=5057, threaded=True)
