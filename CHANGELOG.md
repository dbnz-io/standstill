# Changelog

## [Unreleased]

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
