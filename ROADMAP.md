# standstill — Production-Readiness Roadmap

This roadmap tracks the work required to take standstill from "demos well" to
"trustworthy in production." Items are ordered by what actually blocks prod use.

The guiding theme: the tool's **implementation** is more mature than its
**honesty** — some broken paths pass tests, permission errors can look like
"feature disabled," and half-configured can be reported as done. Most of
prod-readiness here is making failure loud and correct, not adding features.

Status legend: ✅ done · 🚧 in progress · ⬜ not started

---

## P0 — Correctness blockers

A security tool that silently doesn't work is worse than none.

| # | Item | Why it blocks | Status |
|---|------|---------------|--------|
| 1 | **Rewrite Account Factory** (`create`/`enroll`/`deregister`) against Service Catalog `provision_product` + correct poll endpoint | Currently calls non-existent boto3 methods (`create_managed_account` etc.) — `AttributeError` on first real use. `account_factory.py:97–132` | ⬜ |
| 2 | **Wire the SNS topic policy in `notify setup`** | Setup printed "complete!" but never granted EventBridge `sns:Publish` — findings silently never delivered. `notifications.py` | ✅ |
| 3 | **Fix GuardDuty `AutoEnable` param** | Passed the `ALL/NEW/NONE` enum to the deprecated boolean param instead of `AutoEnableOrganizationMembers` — org auto-enroll broken. `security_services.py` | ✅ |

## P1 — Trust & correctness hardening

Make failures honest.

| # | Item | Why | Status |
|---|------|-----|--------|
| 4 | **Global error boundary** — every command surfaces clean one-line errors like `check` does; no raw traceback / locals dump | A mistyped profile dumped a full stack trace on `view` but a clean line on `check`. `main.py` | ✅ |
| 5 | **Kill silent `except ClientError: pass`** in status/read paths — distinguish "disabled" from "access denied" | ~13 sites in `security_services.py` + `sso.py` + `scp.py:175` + `notifications.py` make permission gaps look identical to "feature off" | ✅ (security probes, sso list, scp audit all surface access-denied; remaining swallows are benign enrichment fallbacks) |
| 6 | **Correct exit codes & timeout semantics** — non-zero on partial failure; distinguish "still running" from "failed" | `sso assign` exits 0 on poll timeout; blueprints report "failed" while a stack is still creating | ✅ (sso + blueprint return exit 2 "not confirmed" on timeout, distinct from exit 1 failure; sso poll tolerates transient throttles) |
| 7 | **Operations journal: refresh status in place** or label as last-known | `operations list` always shows stale `IN_PROGRESS`. `operations.py:49` | ✅ (labeled last-known) |
| 10 | **Resolve the single-region limitation** — implement multi-region or hard-guard + document | `security`/`recorder` configure only the home region despite org-wide framing → users believe they're covered when they aren't | 🚧 (`security apply --regions` loops per region; status/assess + recorder still single-region but now documented as such) |

## P2 — Test integrity

Today's green coverage hid a fully-broken domain.

| # | Item | Why | Status |
|---|------|-----|--------|
| 8a | **Replace mock-the-wrapper tests with moto / botocore Stubber** on AWS-facing paths (esp. accounts) | The Accounts domain was 100% "tested" yet cannot run — the mock-everything strategy validated phantom APIs | ⬜ |
| 8b | **Add `mypy`/`pyright` + `boto3-stubs` as a CI gate** | Type-checking would have caught the phantom-API bug class statically. Biggest single ROI against recurrence | ✅ (mypy gate in CI, zero errors; found + fixed a real missing --account/--ou guard. `boto3-stubs` for typed AWS clients is a follow-up) |
| 8c | **Cover untested write lifecycles** — `sso` assign/unassign poll, `notify setup` wizard, GuardDuty AutoEnable | These mutate prod org state and had zero behavioral coverage | ✅ (sso cmds, notify wizard, guardduty param covered; more legacy modules remain) |

## P3 — CI/CD & supply chain

Port the dredge pipeline.

| # | Item | Why | Status |
|---|------|-----|--------|
| 9 | **Unify CI to the dredge model**: `test`/`security`/`package` → `release`; add `bandit`; SHA-pin actions; packaging smoke test; CycloneDX SBOM; version-detected release. Keep the coverage badge | standstill has no static security scan (ironic), unpinned actions, no artifact validation before publish | ✅ |
| 13 | **Dependency hygiene** — lockfile/constraints + Dependabot/renovate | Reproducible builds; supply-chain posture for a security product | ⬜ |

## P4 — Operational robustness

Running it at scale, safely.

| # | Item | Why | Status |
|---|------|-----|--------|
| 14 | **Audit logging** — structured record of who changed what, when (`--verbose`/log file) | A tool that mutates org-wide security controls must be auditable | ✅ (centralized JSONL invocation log at `~/.standstill/audit.log`; captures command, args, profile, region, exit code) |
| 15 | **Partial-failure & rollback strategy** for multi-account fan-out (blueprints, recorder, security apply) | Sequential deploys with no rollback leave orgs half-configured | ⬜ |
| 16 | **Scale validation** — pagination + concurrency caps verified at hundreds of accounts | The target use case is "dozens to hundreds of accounts" | ⬜ |

## P5 — Product & release polish

| # | Item | Why | Status |
|---|------|-----|--------|
| 17 | Fix stale docstrings (e.g. `catalog_build` claims signed-raw-HTTP), accuracy-audit permissions docs, document single-region | Docs currently describe behavior the code doesn't have | 🚧 (catalog docstring corrected + broadened its error handling; single-region documented; a full docstring sweep remains) |
| 18 | Discoverability — interactive pickers for OU/account IDs beyond `apply --category` | Removes the "must already know ARNs/IDs" barrier | ⬜ |
| 19 | Least-privilege IAM policy doc + threat model + `SECURITY.md` review | Table stakes for a security product going prod | ✅ (SECURITY.md now has a security model, least-privilege guidance, and audit/blast-radius notes) |
| 20 | Semver + CHANGELOG discipline + deprecation policy; validate against a live sandbox org before GA | Release readiness | 🚧 (CHANGELOG updated with the full prod-readiness set; live-org validation still required) |

---

## Critical path

**Ship-blocking (do first):** #1 Accounts rewrite → #2 SNS policy → #3 GuardDuty
AutoEnable → #4 traceback wrap. These four are the difference between "demos
well but breaks in prod" and "trustworthy." (#2, #3, #4 done.)

**Highest-leverage systemic fixes:** #8b (type-checking gate) and #8a (real AWS
mocking) — together they'd have caught the worst bug *and* prevent the whole
class from recurring.
