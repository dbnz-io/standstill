# Security Policy

## Reporting a vulnerability

Do not open a public GitHub issue for security vulnerabilities.

Report security issues by emailing **santi@dbnz.io**. Include:

- A description of the vulnerability and its potential impact
- Steps to reproduce or a proof-of-concept
- Any suggested mitigations you have identified

You will receive an acknowledgement within 48 hours. We aim to release a fix or mitigation within 14 days for critical issues.

## Scope

This policy covers the standstill CLI and its published container image. It does not cover the AWS services that standstill manages — report those directly to AWS.

## Supported versions

Security fixes are applied to the latest release only.

## Security model

standstill runs as a **highly privileged operator tool**, not a service. It runs
with the credentials you give it and makes AWS API calls on your behalf; it has
no server, stores no secrets, and opens no inbound listeners.

- **Credentials** come from the standard AWS resolution chain (profile,
  environment, SSO, instance role). standstill never writes credentials to disk
  except when you explicitly run `accounts set-profile`, which stores an assumed
  short-lived profile in `~/.aws` the same way the AWS CLI does.
- **Privilege**: managing org-level controls requires management-account or
  delegated-admin access. Treat the workstation and role that run standstill as
  Tier-0 — anyone who can run it can change organization-wide security posture.
- **Audit**: every invocation is recorded to `~/.standstill/audit.log`
  (command, args, profile, region, exit code). Ship this log to a central,
  append-only store if you need a tamper-evident trail.
- **Blast radius**: prefer `--dry-run` and the `--regions`/`--ou` scoping flags,
  run from a locked-down CI identity rather than a laptop where practical, and
  gate the PyPI release environment (`environment: pypi`) with required
  reviewers.

## Least privilege

Scope the executing role to only the services you use. `standstill check`
enumerates the permissions it needs; grant read-only permissions for `view`,
`status`, and `assess`, and add mutating permissions
(`controltower:*`, `organizations:*`, `guardduty:*`, `securityhub:*`,
`macie2:*`, `inspector2:*`, `accessanalyzer:*`, `sso:*`, `servicecatalog:*`,
`cloudformation:*`) only for the workflows you run. Grant Account Factory
(`servicecatalog:*`) and blueprint (`cloudformation:*`) permissions only to the
identities that provision accounts.
