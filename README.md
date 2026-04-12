# standstill

[![Tests](https://github.com/dbnz-io/standstill/actions/workflows/tests.yml/badge.svg)](https://github.com/dbnz-io/standstill/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL%202.0-brightgreen)](LICENSE)
[![Coverage](docs/coverage.svg)](docs/coverage.svg)

**standstill** is a CLI for planning and deploying the full AWS security stack at the organizational level — Control Tower controls, security services, and Config recorders — from a single tool.

---

## What problem it solves

AWS provides the building blocks for a strong organizational security posture: over 1,200 Control Tower controls spanning preventive, detective, and proactive behaviors, plus GuardDuty, Security Hub, Macie, Inspector, and Access Analyzer for threat detection and compliance posture. The challenge is not knowing what exists — it is deploying and managing all of it systematically across dozens or hundreds of accounts without a dedicated team.

The AWS console does not scale. Raw SDK scripts do not compose. Terraform modules exist but are not aware of the Control Tower operational model, its async behavior, or the relationship between OU baselines, control enrollment, and the pending operations journal.

standstill is built around that operational model. It treats the desired security state as something that can be declared, planned, diffed, and applied — the same way infrastructure engineers think about Terraform — but specifically for the security controls and services that AWS organizations are built on.

---

## The security layers standstill manages

### Preventive controls — Service Control Policies

SCPs attached to OUs that block non-compliant API calls before they happen. No IAM policy in a member account can override an SCP. Once in place, the control is ambient: it requires no agent, no scheduled evaluation, and no alerting pipeline. It simply denies the action.

### Detective controls — AWS Config rules

Managed Config rules deployed across the organization that continuously evaluate resource configuration. When a resource drifts out of compliance — a security group opens an unrestricted port, an S3 bucket loses its block-public-access setting, a root access key gets created — the rule flags it. Detective controls are the primary mechanism for catching configuration drift that happened before preventive controls were enrolled or that slipped through other gaps.

### Proactive controls — CloudFormation hooks

Hooks that intercept CloudFormation stack deployments before non-compliant resources are created. They operate at the infrastructure-as-code layer, blocking stacks that would provision resources violating the defined security policies before anything is provisioned in AWS.

### Security services — threat detection and posture

- **GuardDuty** — Analyzes CloudTrail, VPC Flow Logs, DNS logs, and runtime environments for active threats: unauthorized access, crypto mining, credential exfiltration, lateral movement. Deploys org-wide via a delegated administrator account with configurable protection plans (S3, RDS, EKS, ECS, EC2 malware scanning, Lambda network logs).
- **Security Hub** — Aggregates findings from GuardDuty, Config, Macie, and Inspector into a unified compliance posture. Standards include AWS Foundational Security Best Practices (FSBP), CIS Benchmarks (v1.4 and v3.0), PCI-DSS, and NIST 800-53. Supports cross-region aggregation.
- **Macie** — Discovers and classifies sensitive data in S3: PII, credentials, financial records. Includes automated discovery with configurable sampling depth and managed identifier sets.
- **Inspector** — Continuous vulnerability scanning for EC2 instances, container images in ECR, and Lambda functions. Surfaces CVEs, network reachability issues, and software package vulnerabilities.
- **Access Analyzer** — Identifies IAM roles, S3 buckets, KMS keys, SQS queues, and other resources with resource-based policies that grant access to external principals. Supports organization-level analyzers and unused access analysis.

---

## Core capabilities

### Declarative control management

Controls are declared in a YAML file that maps OUs to the list of controls that should be active on them. standstill diffs the desired state against what is currently enrolled in Control Tower, skips already-enabled controls, validates that target OUs have an active CT baseline, and applies only the delta.

```yaml
targets:
  - ou_id: ou-ab12-34cd5678
    controls:
      - arn:aws:controltower:us-east-1::control/AWS-GR_RESTRICT_ROOT_USER
      - arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES
      - arn:aws:controltower:us-east-1::control/AWS-GR_CLOUDTRAIL_ENABLED

  - ou_id: ou-cd34-56ef7890
    controls:
      - arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES
      - arn:aws:controltower:us-east-1::control/AWS-GR_S3_BUCKET_PUBLIC_READ_PROHIBITED
```

```bash
standstill apply --file controls.yaml --dry-run   # plan
standstill apply --file controls.yaml             # apply
```

The same file format works for disabling controls:

```bash
standstill disable --file controls.yaml --dry-run
standstill disable --file controls.yaml
```

### Bulk enablement and disable

For bootstrapping a new OU or landing zone, entire control tiers can be enrolled in a single command:

```bash
standstill apply --enable-detective  --ou ou-ab12-34cd5678
standstill apply --enable-preventive --ou ou-ab12-34cd5678
standstill apply --enable-proactive  --ou ou-ab12-34cd5678
standstill apply --enable-all        --ou ou-ab12-34cd5678
```

Disabling by tier works symmetrically:

```bash
standstill disable --disable-detective  --ou ou-ab12-34cd5678
standstill disable --disable-preventive --ou ou-ab12-34cd5678
standstill disable --disable-all        --ou ou-ab12-34cd5678
```

### Interactive control selection

When you want to enable or disable a subset of controls without writing a YAML file, `--category` launches an interactive picker. It prompts for a primary filter dimension (behavior, AWS service, or common control) and then an optional severity filter:

```bash
standstill apply   --category --ou ou-ab12-34cd5678
standstill disable --category --ou ou-ab12-34cd5678
```

The picker only shows behaviors and severities that exist in the loaded catalog, so every selection produces at least one control.

### Parallel apply

Control Tower operations are asynchronous. standstill submits all enable operations concurrently in a configurable thread pool, then polls all of them simultaneously. The total wall-clock time is bounded by the slowest single operation rather than the sum — which makes the difference between hours and minutes when enrolling the full catalog.

```bash
standstill apply --enable-detective --ou ou-ab12-34cd5678 --concurrency 20
```

### Pending operations journal

If AWS credentials expire during a long-running apply, standstill catches the expiry, writes all in-flight operations to a local journal (`~/.standstill/pending_operations.yaml`), and exits cleanly. The journal can be checked in a subsequent session:

```bash
standstill operations list
standstill operations check           # poll status; does not modify the journal
standstill operations check --clear   # poll status and remove completed entries
standstill operations clear           # remove all entries immediately
```

### Security services configuration

An interactive wizard generates a YAML configuration file covering all five security services with cost annotations at each step. The generated file can be version-controlled and applied idempotently:

```bash
standstill security init                                    # interactive wizard → generates YAML
standstill security apply --file security_services.yaml    # deploy org-wide
standstill security status                                  # current state
standstill security assess                                  # member account health
```

If you have security services already deployed and want to bring them under standstill management, `security pull` snapshots the live configuration into a local YAML file:

```bash
standstill security pull --account 123456789012
standstill security apply --file security_services.yaml --dry-run
```

### Config recorder management

Detective controls depend on AWS Config recorders being active in every account. AWS Config is also the most common source of unexpected cost in a Control Tower deployment — the default `allSupported` mode records every resource type AWS supports, including high-volume types like CloudFormation stacks, ENIs, and SSM compliance items, that generate millions of configuration items per month without adding meaningful security coverage.

standstill sidesteps this by configuring recorders in `INCLUSION_BY_RESOURCE_TYPES` mode, recording only the specific types that Security Hub standards and the enrolled detective controls actually evaluate. The bundled list is tuned to exclude high-churn types. It can be inspected and customized before any recorder is touched:

```bash
standstill recorder types list              # show the active inclusion list
standstill recorder types add TYPE          # add a resource type
standstill recorder types remove TYPE       # remove a resource type
standstill recorder types reset             # revert to bundled Security Hub defaults
```

Once the inclusion list reflects what you need, auditing and configuring recorders across the organization is a two-step operation:

```bash
standstill recorder status --all
standstill recorder setup  --all
```

### Organization visibility

```bash
standstill view ous               # OU hierarchy as a tree
standstill view accounts          # all accounts with OU and status
standstill view controls          # enabled controls per OU with status breakdown
standstill accounts check-roles   # verify CT execution role reachability across all accounts
```

---

## Prerequisites

- An AWS organization with a Control Tower landing zone already deployed
- Credentials for the **management account** (or a role that can assume into it)
- The caller needs at least the following IAM permissions:

```
controltower:ListEnabledControls
controltower:EnableControl
controltower:DisableControl
controltower:GetControlOperation
controltower:ListControlOperations
organizations:ListRoots
organizations:ListOrganizationalUnitsForParent
organizations:ListAccountsForParent
organizations:DescribeOrganization
sts:GetCallerIdentity
```

Additional permissions are required for security services commands (`guardduty:*`, `securityhub:*`, `macie2:*`, `inspector2:*`, `accessanalyzer:*`) scoped to the delegated admin account.

Run `standstill check` after installation to verify connectivity and permissions before doing anything else.

---

## Quick start

```bash
# 1. Install
git clone https://github.com/dbnz-io/standstill
cd standstill && pip install -e .

# 2. Verify connectivity
standstill --profile my-mgmt-profile --region us-east-1 check

# 3. Explore your org
standstill view ous
standstill view accounts

# 4. Verify execution roles are reachable in all accounts
standstill accounts check-roles

# 5. Ensure Config recorders are running everywhere (required for detective controls)
standstill recorder status --all
standstill recorder setup  --all

# 6. Dry-run before applying anything
standstill apply --file examples/controls.yaml --dry-run

# 7. Apply
standstill apply --file examples/controls.yaml
```

---

## Installation

```bash
git clone https://github.com/dbnz-io/standstill
cd standstill
pip install -e .
```

Requires Python 3.11+.

---

## Command reference

```
standstill [--profile PROFILE] [--region REGION] [--output table|json] COMMAND

  check                          Verify AWS connectivity and CT permissions

  view ous                       Render the OU hierarchy as a tree
  view accounts                  List all accounts with OU membership and status
  view controls [--ou OU]        Show enabled controls per OU

  apply --file FILE              Apply controls declared in a YAML file
  apply --enable-all      --ou   Enable every control in the catalog
  apply --enable-preventive --ou Enable all Preventive controls
  apply --enable-detective  --ou Enable all Detective controls
  apply --enable-proactive  --ou Enable all Proactive controls
  apply --category        --ou   Interactively select controls to enable
    --dry-run                    Preview changes without applying
    --yes / -y                   Skip confirmation prompt
    --concurrency N              Parallel submissions (default: 10)
    --no-wait                    Submit and return immediately

  disable --file FILE                  Disable controls declared in a YAML file
  disable --disable-all      --ou      Disable every enabled control on the OU
  disable --disable-preventive --ou    Disable all enabled Preventive controls
  disable --disable-detective  --ou    Disable all enabled Detective controls
  disable --disable-proactive  --ou    Disable all enabled Proactive controls
  disable --category           --ou    Interactively select controls to disable
    --dry-run                          Preview changes without applying
    --yes / -y                         Skip confirmation prompt
    --concurrency N                    Parallel submissions (default: 10)
    --no-wait                          Submit and return immediately

  catalog info                   Show catalog metadata
  catalog build                  Refresh catalog from the live CT API

  operations list                Show pending CT operations
  operations check [--clear]     Poll live status; --clear removes completed entries
  operations clear               Remove all entries from the journal

  security init [--output FILE]              Interactive config wizard
  security pull [--account ID]               Snapshot live config to a YAML file
  security apply --file FILE [--dry-run]     Deploy security services org-wide
    --yes / -y                               Skip confirmation prompt
  security status [--account ID | --file F]  Current state of all security services
  security assess [--account ID | --file F]  Member account health across all services

  recorder status --all | --account ID       Show recorder state
  recorder setup  --all | --account ID       Configure and start recorders
  recorder types list                        List recorded resource types
  recorder types add TYPE                    Add a resource type
  recorder types remove TYPE                 Remove a resource type
  recorder types reset                       Revert to bundled Security Hub defaults

  accounts check-roles [--role-name NAME]    Verify CT execution role in every account

  lz status                      Show landing zone status, version, and drift state
  lz reset                       Remediate landing zone drift
  lz update                      Upgrade the landing zone to the latest version
  lz settings                    Show landing zone service settings
  lz settings-set                Update landing zone service settings

  config set-profile PROFILE                 Set the default AWS profile
  config unset-profile                       Remove the default AWS profile
  config set-delegated-admin ACCOUNT_ID      Set the default delegated security admin account
  config unset-delegated-admin               Remove the default delegated security admin account
  config show                                Show current CLI configuration
```

---

## Recommended hardening sequence

```bash
standstill check
standstill view ous
standstill accounts check-roles
standstill recorder status --all && standstill recorder setup --all
standstill apply --file examples/preventive_controls.yaml --dry-run
standstill apply --file examples/preventive_controls.yaml
standstill security init && standstill security apply --file security_services.yaml
standstill view controls && standstill security status
```

---

## Docker

### Building locally

```bash
docker build -t standstill .
```

### Running with AWS credentials

Pass credentials via environment variables or mount your `~/.aws` directory:

```bash
# Environment variables
docker run --rm \
  -e AWS_ACCESS_KEY_ID \
  -e AWS_SECRET_ACCESS_KEY \
  -e AWS_SESSION_TOKEN \
  -e AWS_DEFAULT_REGION=us-east-1 \
  standstill check

# Mounted credentials file
docker run --rm \
  -v "$HOME/.aws:/root/.aws:ro" \
  -e AWS_PROFILE=my-mgmt-profile \
  -e AWS_DEFAULT_REGION=us-east-1 \
  standstill check
```

---

## Development

```bash
pip install -e ".[dev]"
pytest
pytest --cov=standstill --cov-report=term-missing --cov-fail-under=80
ruff check .
```

Tests mock all AWS calls — no real AWS account required. See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

---

## License

[Mozilla Public License 2.0](LICENSE)
