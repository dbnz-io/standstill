# Changelog

## [Unreleased]

## [0.2.0] - 2026-08-31

### Added

- Global CLI error boundary: expected AWS/runtime failures now surface as a single clean `Error:` line with a non-zero exit instead of a raw traceback.
- Audit log: every invocation is appended as JSON to `~/.standstill/audit.log` (override with `STANDSTILL_AUDIT_LOG`) with command, args, profile, region, and exit code.
- `security apply --regions` configures regional services (GuardDuty, Security Hub, Macie, Inspector) across multiple regions in one run.
- CI: unified pipeline (test / bandit / package → version-detected release) with a `mypy` type-check gate, `bandit` static analysis, SHA-pinned actions, packaging smoke test, and a CycloneDX SBOM on release.

### Fixed

- **Account Factory**: `accounts create` / `enroll` / `deregister` called non-existent Control Tower boto3 methods and failed at runtime; reimplemented against the AWS Service Catalog Account Factory product with `describe_record` polling.
- **Notifications**: `notify setup` now applies the SNS topic policy granting EventBridge `sns:Publish` — previously the rule was created but findings never delivered.
- **GuardDuty**: org auto-enrollment used the deprecated boolean `AutoEnable` param instead of `AutoEnableOrganizationMembers`.
- Security status probes now surface access-denied as an error instead of rendering it as "disabled".
- Exit codes: `sso assign/unassign` and `blueprint apply` return a distinct "not confirmed" code (2) on poll timeout instead of 0 (success) or 1 (failure); SSO polling tolerates transient throttles.
- `operations list` labels its status column as last-known (it is not refreshed in place).
- `blueprint apply` now requires `--account` or `--ou` instead of failing deep in the call.

### Removed

- The cost/FinOps command surface (`cost report/services/forecast/budgets/anomalies/trail/scan/optimize`) — out of scope for an org-security tool and well served by dedicated OSS.

## [0.1.0] - 2026-04-08

Initial public release.

### Added

- Declarative control management via YAML with diff-before-apply workflow
- Bulk enablement of control tiers (preventive, detective, proactive, all) per OU
- Parallel operation submission and polling bounded by the slowest operation
- Pending operations journal for resuming after credential expiry
- Interactive security services wizard (`standstill security init`) covering GuardDuty, Security Hub, Macie, Inspector, and Access Analyzer
- Config recorder audit and configuration across all org accounts
- Organization visibility: OU hierarchy, account listing, control status per OU
- Cross-account role verification (`standstill accounts check-roles`)
- Bundled control catalog with 1,200+ Control Tower controls
- Docker image published to GitHub Container Registry
