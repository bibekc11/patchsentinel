import argparse, json, sys, time
from pathlib import Path

from . import scanners
from .agents import Agents
from .audit import AuditLog, verify_chain
from .graph import run_alert
from .llm import get_backend
from .report import approve, export, load_policy, write_report, LABELS

BENCH_SABOTAGE = {"get_invoice": "breaking", "find_product": "gaming"}
BENCH_EXPECTED = {"count_users": "rejected_false_positive", "tool_version": "rejected_false_positive",
                  "get_invoice": "escalated_retries_exhausted", "find_product": "escalated_retries_exhausted"}


def run_pipeline(repo, args, sabotage=None):
    repo = Path(repo).resolve()
    policy = load_policy(args.policy)
    out = Path(args.out) / time.strftime("run_%Y%m%d_%H%M%S")
    out.mkdir(parents=True, exist_ok=True)
    audit = AuditLog(out / "audit.jsonl")
    backend = get_backend(args.provider, sabotage)
    agents = Agents(backend)
    t0 = time.time()
    alerts = scanners.scan(repo, policy, Path(args.sarif) if getattr(args, "sarif", None) else None)
    if getattr(args, "only", None):
        alerts = [a for a in alerts if a.id in args.only.split(",") or a.function in args.only.split(",")]
    audit.log("run_started", repo=str(repo), provider=args.provider, alerts=len(alerts), policy=policy)
    print(f"PatchSentinel: {len(alerts)} alert(s) in {repo.name}, provider={args.provider}\n")
    results = []
    for a in alerts:
        r = run_alert(agents, audit, policy, a, repo)
        results.append(r)
        print(f"  {a.id} {a.file}:{a.function}()  {a.rule_id:<18} -> {LABELS.get(r['status'], r['status'])}  ({r['seconds']}s, {r.get('attempt', 0)} attempt(s))")
    approve(results, getattr(args, "approve", "none"), getattr(args, "approver", ""), getattr(args, "role", ""), policy, audit)
    export(results, repo, out, getattr(args, "apply", False), audit)
    ok, msg = verify_chain(out / "audit.jsonl")
    m = write_report(out, results, policy, time.time() - t0, args.provider, msg, getattr(backend, "tokens", 0))
    print(f"\nReport: {out/'report.md'}\nAudit:  {out/'audit.jsonl'} ({msg})\n{json.dumps(m, indent=2)}")
    return results, out


def main(argv=None):
    p = argparse.ArgumentParser(prog="patchsentinel", description="Proof-gated, human-approved security remediation agents")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("run", "benchmark"):
        s = sub.add_parser(name)
        if name == "run":
            s.add_argument("repo")
        s.add_argument("--provider", default="offline", choices=["offline", "anthropic", "openai"])
        s.add_argument("--policy"); s.add_argument("--out", default="out"); s.add_argument("--sarif"); s.add_argument("--only")
        s.add_argument("--approve", default="none", choices=["none", "interactive", "yes"])
        s.add_argument("--approver", default="unnamed"); s.add_argument("--role", default="reviewer")
        s.add_argument("--apply", action="store_true", help="commit approved fixes to a new git branch in the target repo")
    v = sub.add_parser("audit-verify"); v.add_argument("path")
    args = p.parse_args(argv)
    if args.cmd == "audit-verify":
        ok, msg = verify_chain(args.path); print(msg); sys.exit(0 if ok else 1)
    if args.cmd == "run":
        run_pipeline(args.repo, args)
        return
    args.provider = "offline"
    results, out = run_pipeline(Path(__file__).resolve().parent.parent / "demo_target", args, BENCH_SABOTAGE)
    print("\nBENCHMARK vs expected outcomes (10 seeded cases; traps are simulated adversarial patches)")
    good = 0
    for r in results:
        want = BENCH_EXPECTED.get(r["alert"]["function"], "verified")
        got = "verified" if r["status"] in ("verified", "approved") else r["status"]
        good += got == want
        print(f"  {r['alert']['function']:<14} expected={want:<28} got={got:<28} {'PASS' if got == want else 'FAIL'}")
    print(f"\n{good}/{len(results)} cases behaved as expected")
    sys.exit(0 if good == len(results) else 1)


if __name__ == "__main__":
    main()
