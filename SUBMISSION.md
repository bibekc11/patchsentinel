# Submission kit (AgentOps 2026, team HX-96SU)

**Domain to select in the portal: IT Infrastructure** (CGI's example: "investigate an incident and execute a verified, human-approved recovery"; ours: investigate a security alert, execute a proof-verified, human-approved remediation).

## Solution summary (paste into the portal)
Security alerts reach IT-services teams faster than reviewers can fix them, and AI autofix output is unusable without proof. PatchSentinel is a multi-agent system: scanner findings (Bandit/any SARIF) are ingested; a triage agent separates real flaws from false positives; an exploit test is generated and must FAIL on the original code; a patch agent fixes it; a plain-code verifier (no LLM) enforces six gates (exploit blocked, behaviour unchanged, tests green, scanner clear, anti-test-gaming, compiles); an independent reviewer agent checks; a role-checked human approves; the fix lands on its own git branch with evidence, a PR body and a hash-chained audit log. Retries are capped at 3, then it escalates. Benchmark: 10/10 seeded cases correct (6 verified, 2 false positives rejected, 2 adversarial patches blocked). ROI is shown with editable assumptions (policy.json / dashboard sliders), not claimed as measured.

## Judging map (10 pts each) -> where to show it
| Criterion | Proof to show |
|---|---|
| Reusability | Scanner-agnostic (SARIF), model-agnostic, `policy.json`; new bug class = rule + exploit template; same pattern fits CGI client DevSecOps delivery. Say "accelerator", not "demo". |
| Responsible AI & Governance | Dashboard: role refusal as `viewer`, audit chain badge, per-gate evidence, never auto-merged, scrubbed no-network sandbox, stated limits. |
| AI to ROI | ROI sliders on the dashboard. Say "estimate from your baseline", never "measured". |
| MVP readiness | `python -m patchsentinel benchmark` and `python -m patchsentinel.webapp` both run with no API key. |
| Originality | Evaluator asked for differentiation from autofix: autofix re-runs the scanner; we require exploit fails-before / passes-after, behaviour baseline, and anti-gaming, and we show the two traps being blocked live. |

## 5 min deck (final deck should differ from the idea deck)
1 Problem + domain (30s) · 2 Workflow ingest->decide->act->report (45s) · 3 Why not autofix: proof gate diagram (60s) · 4 Governance controls (45s) · 5 Measured benchmark + ROI assumptions (60s) · 6 Reusability roadmap + limits (60s).

## 3 min demo video (MP4 <= 50 MB)
0:00 problem line · 0:15 click Run (adversarial box ticked) · 0:45 open a verified alert: six green gates + diff · 1:15 open `get_invoice` / `find_product`: blocked after 3 tries (the traps) · 1:45 approve as `viewer` (refused) then as `reviewer` · 2:15 audit chain intact · 2:30 move ROI sliders · 2:50 one-line close.

## Likely Q&A
- *Isn't this just GitHub autofix?* No: they re-scan; we prove the exploit is blocked and behaviour kept, and catch gaming.
- *Only 3 bug classes?* Yes, stated plainly; anything else escalates, never guessed. Extension point is `exploit.py`.
- *Is the ROI real?* It is an editable estimate; the benchmark counts are real.
- *Does the LLM path work?* Tested with a stub model; live quality depends on the provider. Run the live provider once before 6 PM and report what you saw.

## Before 6 PM
Run `pytest`, `benchmark` and the dashboard on your own machine; no secrets in repo; push; copy the **full** commit SHA; upload repo URL + SHA + PPTX + MP4; wait for the saved receipt.
