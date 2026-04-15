# standstill

[![Tests](https://github.com/dbnz-io/standstill/actions/workflows/tests.yml/badge.svg)](https://github.com/dbnz-io/standstill/actions/workflows/tests.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/)
[![License: MPL 2.0](https://img.shields.io/badge/license-MPL%202.0-brightgreen)](LICENSE)
[![Coverage](docs/coverage.svg)](docs/coverage.svg)

**standstill** is a CLI designed to manage AWS security at scale.

---

## What problem it solves

AWS provides the building blocks for a strong organizational security posture: over 1,200 Control Tower controls spanning preventive, detective, and proactive behaviors, plus GuardDuty, Security Hub, Macie, Inspector, and Access Analyzer for threat detection and compliance posture. The challenge is not knowing what exists — it is deploying and managing all of it systematically across dozens or hundreds of accounts without a dedicated team.

The AWS console does not scale. Raw SDK scripts do not compose. Terraform modules exist but are not aware of the Control Tower operational model, its async behavior, or the relationship between OU baselines, control enrollment, and the pending operations journal.

standstill is built around that operational model. It treats the desired security state as something that can be declared, planned, diffed, and applied — the same way infrastructure engineers think about Terraform — but specifically for the security controls and services that AWS organizations are built on.

Security operations also have a financial dimension. The services that protect your organization — CloudTrail, Config, GuardDuty, Security Hub, CloudWatch — generate real AWS spend that grows with account count and usage. Understanding where that money goes, catching unexpected spikes before the invoice arrives, and ensuring commitments like Savings Plans are actually being used are as much part of running a security team as enrolling controls. standstill treats cost visibility as a first-class operational concern, not a separate tool.

---

## Account maturity model

Mature AWS organizations separate account infrastructure into layers with distinct ownership
boundaries. standstill is designed around this model: each layer has a dedicated tool and a
dedicated team, and lower layers are treated as immutable by the layers above them.

| Layer | Name | What it contains | Managed by | Owned by |
|-------|------|-----------------|------------|----------|
| 0 | Organization & security controls | CT controls (SCPs, detective, proactive), GuardDuty, Security Hub, Macie, Inspector, Access Analyzer, Config recorders | standstill | Security / platform team |
| 1 | Account foundation | VPC, subnets, route tables, Transit Gateway attachment, DNS resolver rules, default security groups, break-glass IAM roles | standstill blueprints | DevOps / platform team |
| 2 | Application infrastructure | Compute (ECS/EKS/Lambda), databases, storage, application-specific resources | Terraform / CloudFormation / CDK | Dev / DevOps teams |

Layer 0 and Layer 1 are set once per account and treated as immutable by Layer 2. Application
teams reference foundation resources via data sources or SSM Parameter Store — they never own or
modify them. A `terraform plan` will see the VPC already exists and has no opinion about it.

CloudFormation is used for Layer 1 rather than Terraform precisely because it creates a hard
governance boundary: foundation resources do not exist in any application state file, cannot be
drifted by a `terraform apply`, and can be protected with stack termination protection and a
deny-delete SCP. GuardDuty, CloudTrail, and Config belong to Layer 0 — they are org-wide services
managed centrally by standstill, not per-account Terraform resources. Application infrastructure
has to live with both layers, which is the intended design.

Layer 1 is applied via blueprints — YAML files that describe one or more CloudFormation stacks to
deploy into a new account at creation time:

```bash
standstill blueprint apply --file blueprints/networking.yaml --account 123456789012
standstill accounts create --name "ClientA" --email a@client.com --ou ou-xxx --blueprint blueprints/networking.yaml
```

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

### Cost reporting and forecasting

Security infrastructure generates measurable AWS spend. `cost report` breaks that spend down by any dimension — service, usage type, account, region, or cost allocation tag — and supports the full filter and grouping vocabulary of Cost Explorer. All cost commands accept `--output table` (default), `--output json`, and `--output csv`.

```bash
# All services this month
standstill cost report

# Last quarter, compare to the prior equivalent period
standstill cost report -s 2024-01-01 -e 2024-04-01 --compare

# Break down CloudTrail spend by usage type with correlated API calls
standstill cost report --group-by usage-type --service cloudtrail

# Multi-account spend, names resolved from Organizations
standstill cost report --group-by account --top 10

# Group by cost allocation tag, filter by another
standstill cost report --group-by tag:Team --filter tag:Environment=production

# Daily EC2 spend for a specific week
standstill cost report --group-by usage-type --filter service=ec2 \
  --granularity daily -s 2024-03-01 -e 2024-03-08

# Export
standstill -o csv cost report -s 2024-01-01 -e 2024-04-01 > costs.csv
```

`cost services` lists every service with charges ordered by cost, including its short filter alias and total spend — the natural starting point before drilling into `cost report`:

```bash
standstill cost services
standstill cost services -s 2024-01-01 -e 2024-04-01
```

`cost forecast` projects future spend using the CE ML model, with an optional per-service breakdown driven by parallel fan-out calls:

```bash
standstill cost forecast --months 6
standstill cost forecast --by-service --top 5
```

**`--group-by` options:** `service` · `usage-type` · `account` · `region` · `tag:KEY`

**`--filter KEY=VALUE` keys:** `service` · `region` · `account` · `usage-type` · `az` · `instance-type` · `operation` · `platform` · `purchase-type` · `tag:KEY`

Service filters accept short aliases (`ec2`, `s3`, `rds`, `eks`, `lambda`, …) and resolve them to the exact CE service names for the period. `region=all` is a no-op that includes all regions.

### Cost anomalies and budgets

Two commands provide continuous spend awareness without manual investigation:

```bash
# Anomalies detected by CE's ML model, sorted by total impact
standstill cost anomalies
standstill cost anomalies --days 7 --min-impact 50

# All AWS Budgets with current spend, forecast, and status
standstill cost budgets
```

`cost anomalies` shows the service, region, account, impact vs expected spend, and CE's root cause attribution for each spike. `cost budgets` flags every budget at `OK`, `WARNING` (≥80%), or `EXCEEDED` status so over-runs are visible before the invoice closes.

### Usage attribution — connecting charges to callers

When a usage type charge appears in Cost Explorer, `cost scan` answers the next question: which IAM identities, in which accounts, are making the API calls that generate it.

```bash
# Configure a log source once (event history needs no configuration)
standstill cost trail set \
  --s3-bucket my-org-cloudtrail-bucket \
  --s3-prefix AWSLogs/o-xxxxxxxxxxxx/CloudTrail
standstill cost trail set --log-group /aws/cloudtrail/management-events

# Scan against the CloudTrail event history API (last 90 days)
standstill cost scan usage-type CW:Requests

# Region-prefixed types are stripped automatically
standstill cost scan usage-type USE1-CW:Requests

# Widen the window; query the S3 trail or CloudWatch Logs instead
standstill cost scan usage-type S3-Requests-Tier1 \
  --target s3 --start 2024-03-01 --end 2024-04-01

standstill cost scan usage-type CloudTrail-DataEvent-S3 --target cloudwatch

# Export all events
standstill -o csv cost scan usage-type Lambda-Requests > callers.csv
```

The scan result leads with an **Identity Attribution** table — grouped by account, identity type, and name with call count, error count, and active regions — followed by an API call summary and the 20 most recent events. The three `--target` options are:

| Target | Source | Notes |
|--------|--------|-------|
| `event-history` | CloudTrail management events API | Default; last 90 days; no setup |
| `s3` | `.json.gz` files in a configured S3 bucket | All event types; any retention |
| `cloudwatch` | CloudWatch Logs Insights query | All event types; any retention |

### Commitment optimization

Three subcommands surface whether existing cost commitments are working efficiently:

```bash
# Savings Plans: utilization and coverage, with over/under-commitment warnings
standstill cost optimize savings-plans
standstill cost optimize savings-plans -s 2024-01-01 -e 2024-02-01

# Reserved Instances: utilization and coverage per service
standstill cost optimize reserved

# EC2 rightsizing: instances to downsize or terminate, with monthly savings estimate
standstill cost optimize rightsizing

standstill -o json cost optimize rightsizing
```

**savings-plans** flags utilization below 80% (over-committed — you are paying for capacity you do not use) and coverage below 70% (under-committed — on-demand spend that could be committed). **reserved** shows the same metrics per RI-eligible service. **rightsizing** uses 14 days of CloudWatch utilization data to identify EC2 instances ready to be downsized or terminated, sorted by estimated monthly savings.

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
organizations:ListAccounts
organizations:DescribeOrganization
sts:GetCallerIdentity
```

Additional permissions are required for security services commands (`guardduty:*`, `securityhub:*`, `macie2:*`, `inspector2:*`, `accessanalyzer:*`) scoped to the delegated admin account.

Cost commands require:

```
ce:GetCostAndUsage
ce:GetDimensionValues
ce:GetCostForecast
ce:GetAnomalies
ce:GetSavingsPlansUtilization
ce:GetSavingsPlansCoverage
ce:GetReservationUtilization
ce:GetReservationCoverage
ce:GetRightsizingRecommendation
budgets:DescribeBudgets
cloudtrail:LookupEvents          # cost scan --target event-history
s3:GetObject, s3:ListBucket      # cost scan --target s3
logs:StartQuery, logs:GetQueryResults  # cost scan --target cloudwatch
```

`organizations:ListAccounts` is only needed when using `cost report --group-by account` to resolve account IDs to names.

Run `standstill check` after installation to verify connectivity and permissions before doing anything else.

---

## Quick start

```bash
# 1. Install
git clone https://github.com/dbnz-io/standstill
cd standstill && pip install -e .

# 2. Configure your management account profile (stored in ~/.standstill/config.yaml)
standstill config set-profile my-mgmt-profile
standstill config set-delegated-admin 123456789012   # your security tooling account

# 3. Verify connectivity
standstill check

# 4. Explore your org
standstill view ous
standstill view accounts

# 5. Verify execution roles are reachable in all accounts
standstill accounts check-roles

# 6. Ensure Config recorders are running everywhere (required for detective controls)
standstill recorder status --all
standstill recorder setup  --all

# 7. Dry-run before applying anything
standstill apply --file examples/controls.yaml --dry-run

# 8. Apply
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
standstill [--profile PROFILE] [--region REGION] [--output table|json|csv] COMMAND

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
  accounts list                              List all accounts with OU membership and status
  accounts describe --account ID             Show account details and parent OU
  accounts create --name N --email E --ou OU Create a new account via CT Account Factory
    --blueprint FILE                         Apply a blueprint after the account is ready
    --no-wait                                Submit and return immediately (skips blueprint)
  accounts enroll --account ID --ou OU       Enroll an existing account into Control Tower
    --blueprint FILE                         Apply a blueprint after enrollment completes
    --no-wait                                Submit and return immediately (skips blueprint)
  accounts deregister --account ID           Deregister an account from Control Tower
  accounts move --account ID --ou OU         Move an account to a different OU

  ou create --parent ID --name NAME          Create a new OU
  ou delete --ou OU                          Delete an empty OU
  ou rename --ou OU --name NAME              Rename an OU
  ou describe --ou OU                        Show OU details, child OUs, and accounts

  blueprint list                             List blueprints in ~/.standstill/blueprints/
  blueprint validate --file FILE             Validate a blueprint YAML without deploying
  blueprint apply --file FILE                Apply a blueprint to accounts
    --account ACCOUNT_ID                     Target a single account
    --ou OU_ID                               Target all active accounts in an OU
    --dry-run                                Preview stacks without deploying
    --param KEY=VALUE                        Override a parameter (repeatable)
    --role-name NAME                         IAM role to assume (default: AWSControlTowerExecution)
    --yes / -y                               Skip confirmation prompt

  lz status                      Show landing zone status, version, and drift state
  lz reset                       Remediate landing zone drift
  lz update                      Upgrade the landing zone to the latest version
  lz settings                    Show landing zone service settings
  lz settings-set                Update landing zone service settings

  cost report                    Cost breakdown by service, usage type, account, region, or tag
    -s / --start DATE            Start date YYYY-MM-DD (default: first of month)
    -e / --end DATE              End date YYYY-MM-DD exclusive (default: today)
    -g / --group-by DIM          service | usage-type | account | region | tag:KEY
    -S / --service NAME          Shortcut for --filter service=NAME (accepts short names)
    -f / --filter KEY=VALUE      Dimension filter, repeatable, ANDed together
                                   service · region · account · usage-type · az
                                   instance-type · operation · platform · purchase-type · tag:KEY
                                   region=all is a no-op (include all regions)
    --granularity                monthly (default) | daily
    -n / --top N                 Keep only top N groups per period
    --min-cost FLOAT             Exclude groups below this USD threshold (default: 0.01)
    -m / --metric                unblended (default) | blended | amortized
    --compare                    Side-by-side delta table vs the prior equivalent period

  cost services [-s DATE] [-e DATE] [-m METRIC]
                                 All services with costs ordered by spend, with alias and cost columns

  cost forecast                  Projected monthly spend
    --months N                   Months ahead to forecast (default: 3)
    --metric METRIC              unblended | blended | amortized
    --by-service                 Per-service forecast matrix via parallel CE calls
    -n / --top N                 Number of services when --by-service (default: 10)

  cost budgets                   All AWS Budgets with status (OK / WARNING / EXCEEDED)

  cost anomalies                 Cost spikes detected by CE Anomaly Detection
    -d / --days N                Look-back window in days, max 90 (default: 30)
    --min-impact FLOAT           Minimum total USD impact to include

  cost trail set                 Configure the CloudTrail log source used by cost scan
    --s3-bucket BUCKET           S3 bucket containing CloudTrail logs
    --s3-prefix PREFIX           Key prefix up to (not including) the date component
    --log-group GROUP            CloudWatch Logs log group name
  cost trail show                Show configured log source(s)
  cost trail clear --s3 / --cloudwatch
                                 Remove a configured log source

  cost scan usage-type TYPE      Attribute a CE usage type charge to the callers generating it
    -s / --start DATE            Start date (default: 7 days ago)
    -e / --end DATE              End date (default: today)
    -l / --limit N               Max events to retrieve (default: 200)
    -t / --target TARGET         event-history (default) | s3 | cloudwatch
                                 Output: Identity Attribution · API Call Summary · Recent Events

  cost optimize savings-plans [-s DATE] [-e DATE]
                                 SP utilization and coverage with over/under-commitment warnings
  cost optimize reserved [-s DATE] [-e DATE]
                                 RI utilization and coverage by service
  cost optimize rightsizing      EC2 rightsizing recommendations sorted by estimated savings

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

Once controls and services are in place, establish a cost baseline:

```bash
standstill cost services
standstill cost report --compare
standstill cost anomalies
standstill cost optimize savings-plans && standstill cost optimize rightsizing
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
