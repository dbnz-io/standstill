from __future__ import annotations

import random
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from botocore.exceptions import ClientError

from standstill import state as _state

if TYPE_CHECKING:
    from standstill.aws.organizations import OUNode

_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED"}
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestThrottled"}
_BUNDLED_CATALOG_PATH = Path(__file__).parent.parent / "data" / "controls_catalog.yaml"
_USER_CATALOG_PATH = Path.home() / ".ct-cli" / "catalog.yaml"
_PENDING_OPS_PATH = Path.home() / ".ct-cli" / "pending_operations.yaml"

BEHAVIORS = ("PREVENTIVE", "DETECTIVE", "PROACTIVE")

_pending_ops_lock = threading.Lock()


@dataclass
class Control:
    arn: str
    full_name: str
    description: str
    behavior: str              # DETECTIVE | PROACTIVE | PREVENTIVE
    severity: str              # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    service: str | None = None                          # e.g. "S3", "EC2", "IAM"
    common_controls: list[str] = field(default_factory=list)  # common control objective names


@dataclass
class EnabledControl:
    control_arn: str
    ou_arn: str
    status: str     # SUCCEEDED | FAILED | IN_PROGRESS | UNKNOWN


# ---------------------------------------------------------------------------
# Control catalog (bundled)
# ---------------------------------------------------------------------------

def load_catalog(
    region: str,
    behavior: str | None = None,
    service: str | None = None,
    common_control: str | None = None,
) -> dict[str, Control]:
    """
    Load the controls catalog.
    Prefers ~/.ct-cli/catalog.yaml (built by 'catalog build') over the bundled fallback.
    Substitutes {region} in ARNs.  Optionally filters by behavior, service, or common_control name.
    Returns: {resolved_arn: Control}
    """
    source = _USER_CATALOG_PATH if _USER_CATALOG_PATH.exists() else _BUNDLED_CATALOG_PATH
    data = yaml.safe_load(source.read_text())
    catalog: dict[str, Control] = {}
    for entry in data.get("controls", []):
        b = entry.get("behavior", "UNKNOWN").upper()
        if behavior and b != behavior.upper():
            continue
        svc = entry.get("service") or None
        if service and (not svc or svc.upper() != service.upper()):
            continue
        ccs: list[str] = entry.get("common_controls") or []
        if common_control and common_control not in ccs:
            continue
        arn = entry["arn"].replace("{region}", region)
        catalog[arn] = Control(
            arn=arn,
            full_name=entry.get("name", entry.get("full_name", "")),
            description=entry.get("description", ""),
            behavior=b,
            severity=entry.get("severity", "UNKNOWN").upper(),
            service=svc,
            common_controls=ccs,
        )
    return catalog


def _resolve_ct_arn(aliases: list[str], fallback_arn: str, region: str) -> str:
    """Return a controltower ARN for CT-native controls, otherwise the catalog ARN."""
    ct_alias = next(
        (a for a in aliases if a.startswith("CT.") or a.startswith("AWS-GR_")),
        None,
    )
    return (
        f"arn:aws:controltower:{region}::control/{ct_alias}"
        if ct_alias
        else fallback_arn
    )


def _extract_service(aliases: list[str]) -> str | None:
    """
    Extract the AWS service name from a CT-format alias.
    CT.S3.PR.1 → 'S3', CT.IAM.PR.1 → 'IAM', CT.CLOUDTRAIL.PR.1 → 'CloudTrail', etc.
    Falls back to None for legacy AWS-GR_* aliases that don't encode a service.
    """
    _normalize: dict[str, str] = {
        "CLOUDTRAIL": "CloudTrail",
        "CLOUDWATCH": "CloudWatch",
        "CLOUDFORMATION": "CloudFormation",
        "CODEBUILD": "CodeBuild",
        "DYNAMODB": "DynamoDB",
        "ELASTICACHE": "ElastiCache",
        "GUARDDUTY": "GuardDuty",
        "INSPECTOR": "Inspector",
        "LAMBDA": "Lambda",
        "MACIE": "Macie",
        "NETWORKFIREWALL": "Network Firewall",
        "OPENSEARCH": "OpenSearch",
        "REDSHIFT": "Redshift",
        "ROUTE53": "Route 53",
        "SAGEMAKER": "SageMaker",
        "SECRETSMANAGER": "Secrets Manager",
        "SECURITYHUB": "Security Hub",
        "SERVICECATALOG": "Service Catalog",
        "STEPFUNCTIONS": "Step Functions",
        "SYSTEMSMANAGER": "Systems Manager",
        "WAF": "WAF",
    }
    for alias in aliases:
        if alias.startswith("CT."):
            parts = alias.split(".")
            if len(parts) >= 2:
                raw = parts[1].upper()
                return _normalize.get(raw, raw)
    return None


def fetch_controls_from_api(region: str) -> list[dict]:
    """
    Fetch the full AWS Control Catalog (all 1,200+ controls) via the controlcatalog client.

    ARN strategy:
    - Controls with CT.* or AWS-GR_* aliases → arn:aws:controltower:{region}::control/{alias}
    - All other controls → controlcatalog ARN as-is

    Service is extracted from CT-format aliases (CT.S3.PR.1 → 'S3').
    common_controls is populated separately by fetch_common_control_mapping().

    Returns a list of dicts ready for save_user_catalog / the YAML writers.
    """
    cc = _state.state.get_client("controlcatalog")
    paginator = cc.get_paginator("list_controls")

    controls: list[dict] = []
    for page in paginator.paginate():
        for c in page.get("Controls", []):
            aliases = c.get("Aliases", [])
            arn = _resolve_ct_arn(aliases, c["Arn"], region)
            controls.append({
                "arn": arn,
                "fullName": c.get("Name", ""),
                "description": c.get("Description", ""),
                "behavior": c.get("Behavior", "UNKNOWN"),
                "severity": c.get("Severity", "UNKNOWN"),
                "implementation_type": c.get("Implementation", {}).get("Type", "Unknown"),
                "service": _extract_service(aliases),
                "common_controls": [],
            })

    return controls


def fetch_common_control_mapping(region: str) -> dict[str, list[str]]:
    """
    Build a mapping of resolved control ARN → list of common control names.

    Flow:
    1. list_common_controls() → all common controls with their Objective ARNs
    2. For each unique objective, list_controls(Filter={Objectives: [obj_arn]}) → implementing controls
    3. Invert: control_arn → [common_control_names sharing that objective]

    Note: the AWS Control Catalog API only supports filtering controls by Objective (the parent
    of common controls), not by individual common control. Controls within the same objective
    receive all common control names of that objective — a slight over-attribution when an
    objective has multiple common controls, but it is the finest granularity the API allows.

    Returns {control_arn: [common_control_name, ...]}
    """
    cc = _state.state.get_client("controlcatalog")

    # Step 1: fetch all common controls, group by objective ARN
    cc_by_objective: dict[str, list[str]] = {}  # {obj_arn: [cc_name, ...]}
    paginator = cc.get_paginator("list_common_controls")
    for page in paginator.paginate():
        for item in page.get("CommonControls", []):
            obj_arn = item.get("Objective", {}).get("Arn", "")
            if obj_arn:
                cc_by_objective.setdefault(obj_arn, []).append(item["Name"])

    # Step 2: for each unique objective, get the CT controls that implement it
    result: dict[str, list[str]] = {}
    for obj_arn, cc_names in cc_by_objective.items():
        try:
            obj_paginator = cc.get_paginator("list_controls")
            for page in obj_paginator.paginate(
                Filter={"Objectives": [{"Identifier": obj_arn}]}
            ):
                for c in page.get("Controls", []):
                    aliases = c.get("Aliases", [])
                    ctrl_arn = _resolve_ct_arn(aliases, c["Arn"], region)
                    existing = result.setdefault(ctrl_arn, [])
                    for name in cc_names:
                        if name not in existing:
                            existing.append(name)
        except ClientError:
            # If a specific objective filter fails, skip it gracefully
            continue

    return result


def save_user_catalog(controls: list[dict], region: str) -> Path:
    """
    Persist a fetched and enriched controls list to ~/.ct-cli/catalog.yaml.
    Returns the path written.
    """
    _USER_CATALOG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    entries = []
    for c in controls:
        entry: dict = {
            "arn": c.get("arn", ""),
            "name": c.get("fullName", ""),
            "description": c.get("description", ""),
            "behavior": c.get("behavior", "UNKNOWN"),
            "severity": c.get("severity", "UNKNOWN"),
        }
        if c.get("service"):
            entry["service"] = c["service"]
        if c.get("common_controls"):
            entry["common_controls"] = c["common_controls"]
        entries.append(entry)
    payload = {
        "_meta": {
            "region": region,
            "total": len(entries),
        },
        "controls": entries,
    }
    _USER_CATALOG_PATH.write_text(yaml.dump(payload, default_flow_style=False, sort_keys=False))
    _USER_CATALOG_PATH.chmod(0o600)
    return _USER_CATALOG_PATH


# ---------------------------------------------------------------------------
# Baseline checks
# ---------------------------------------------------------------------------

def check_ou_baseline(ou_arn: str) -> tuple[bool, str]:
    """
    Check whether an OU has an active CT baseline enrolled.

    An OU must have at least one enabled baseline with status SUCCEEDED before
    controls can be applied to it. Attempting to enable controls on an un-enrolled
    OU will fail immediately with a CT API error.

    Returns (ok: bool, message: str).
    """
    ct = _state.state.get_client("controltower")
    try:
        resp = ct.list_enabled_baselines(
            filter={"targetIdentifiers": [ou_arn]},
            maxResults=5,
        )
    except ClientError as e:
        return False, f"Could not query baselines: {e.response['Error']['Message']}"

    baselines = resp.get("enabledBaselines", [])
    if not baselines:
        return False, "No baseline enrolled — OU is not registered in Control Tower."

    # At least one must be SUCCEEDED
    succeeded = [
        b for b in baselines
        if b.get("statusSummary", {}).get("status") == "SUCCEEDED"
    ]
    if not succeeded:
        statuses = ", ".join(
            b.get("statusSummary", {}).get("status", "UNKNOWN") for b in baselines
        )
        return False, f"Baseline found but not active (status: {statuses})."

    baseline_id = succeeded[0].get("baselineIdentifier", "").split("/")[-1]
    return True, f"Baseline active: {baseline_id}"


def check_baselines_for_ous(ou_arns: list[str]) -> dict[str, tuple[bool, str]]:
    """
    Check baselines for multiple OUs concurrently.
    Returns {ou_arn: (ok, message)}.
    """
    results: dict[str, tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(check_ou_baseline, arn): arn for arn in ou_arns}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return results


# ---------------------------------------------------------------------------
# Enabled controls
# ---------------------------------------------------------------------------

def list_enabled_for_ou(ou_arn: str) -> list[EnabledControl]:
    """
    Return all enabled controls for a governed OU.
    Returns an empty list for un-governed OUs (CT raises ResourceNotFoundException).
    """
    ct = _state.state.get_client("controltower")
    enabled: list[EnabledControl] = []
    kwargs: dict = {"targetIdentifier": ou_arn}
    try:
        while True:
            resp = ct.list_enabled_controls(**kwargs)
            for ec in resp.get("enabledControls", []):
                status = ec.get("statusSummary", {}).get("status", "UNKNOWN")
                enabled.append(
                    EnabledControl(
                        control_arn=ec["controlIdentifier"],
                        ou_arn=ou_arn,
                        status=status,
                    )
                )
            if "nextToken" not in resp:
                break
            kwargs["nextToken"] = resp["nextToken"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("ResourceNotFoundException", "ValidationException"):
            return []
        raise
    return enabled


def list_enabled_for_all_ous(
    ou_nodes: list[OUNode],
    max_workers: int = 10,
) -> dict[str, list[EnabledControl]]:
    """
    Fetch enabled controls for every OU in the tree concurrently.
    Returns: {ou_arn: [EnabledControl]}
    """
    from standstill.aws.organizations import flatten_ous

    flat = flatten_ous(ou_nodes)
    results: dict[str, list[EnabledControl]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(list_enabled_for_ou, ou.arn): ou for ou in flat}
        for future in as_completed(futures):
            ou = futures[future]
            results[ou.arn] = future.result()
    return results


# ---------------------------------------------------------------------------
# Pending operations journal
# ---------------------------------------------------------------------------

def save_pending_operation(
    operation_id: str,
    control_arn: str,
    ou_arn: str,
) -> None:
    """Append an operation to the pending journal so it can be checked later."""
    with _pending_ops_lock:
        _PENDING_OPS_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        existing: list[dict] = []
        if _PENDING_OPS_PATH.exists():
            existing = yaml.safe_load(_PENDING_OPS_PATH.read_text()) or []
        existing.append({
            "operation_id": operation_id,
            "control_arn": control_arn,
            "ou_arn": ou_arn,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "status": "IN_PROGRESS",
        })
        _PENDING_OPS_PATH.write_text(yaml.dump(existing, default_flow_style=False))
        _PENDING_OPS_PATH.chmod(0o600)


def remove_pending_operation(operation_id: str) -> None:
    """Remove a completed operation from the pending journal."""
    with _pending_ops_lock:
        if not _PENDING_OPS_PATH.exists():
            return
        ops: list[dict] = yaml.safe_load(_PENDING_OPS_PATH.read_text()) or []
        ops = [o for o in ops if o["operation_id"] != operation_id]
        _PENDING_OPS_PATH.write_text(yaml.dump(ops, default_flow_style=False))
        _PENDING_OPS_PATH.chmod(0o600)


def load_pending_operations() -> list[dict]:
    """Return all entries in the pending operations journal."""
    if not _PENDING_OPS_PATH.exists():
        return []
    return yaml.safe_load(_PENDING_OPS_PATH.read_text()) or []


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

def enable_control(control_arn: str, ou_arn: str) -> str:
    """Enable a control on an OU. Returns the async operationIdentifier."""
    ct = _state.state.get_client("controltower")
    resp = ct.enable_control(
        controlIdentifier=control_arn,
        targetIdentifier=ou_arn,
    )
    return resp["operationIdentifier"]


def disable_control(control_arn: str, ou_arn: str) -> str:
    """Disable a control on an OU. Returns the async operationIdentifier."""
    ct = _state.state.get_client("controltower")
    resp = ct.disable_control(
        controlIdentifier=control_arn,
        targetIdentifier=ou_arn,
    )
    return resp["operationIdentifier"]


class SessionExpiredError(Exception):
    """Raised when AWS credentials expire during an in-progress operation."""
    def __init__(self, operation_id: str) -> None:
        self.operation_id = operation_id
        super().__init__(
            f"AWS session expired while polling operation {operation_id}. "
            "The operation may still be running in Control Tower. "
            "Check its status with: standstill operations check"
        )


def poll_operation(
    operation_id: str,
    timeout: int = 1200,
    poll_interval: int = 10,
) -> dict:
    """
    Block until the CT operation reaches a terminal state or timeout expires.
    Returns the final controlOperation dict.

    Throttling is handled with exponential backoff + jitter. An initial random
    jitter sleep spreads concurrent polling threads so they don't all fire at once.

    Raises:
        TimeoutError        — operation did not complete within `timeout` seconds.
        SessionExpiredError — credentials expired; operation status is unknown.
    """
    deadline = time.monotonic() + timeout

    # Spread concurrent polling threads across the first poll interval so they
    # don't all call GetControlOperation simultaneously.
    time.sleep(random.uniform(0, poll_interval))

    throttle_count = 0
    _MAX_BACKOFF = 60  # seconds

    while time.monotonic() < deadline:
        try:
            ct = _state.state.get_client("controltower")
            resp = ct.get_control_operation(operationIdentifier=operation_id)
            op = resp["controlOperation"]
            throttle_count = 0  # reset on success
            if op["status"] in _TERMINAL_STATUSES:
                return op
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _THROTTLE_CODES:
                throttle_count += 1
                backoff = min(poll_interval * (2 ** throttle_count), _MAX_BACKOFF)
                jitter = random.uniform(0, backoff * 0.25)
                time.sleep(backoff + jitter)
                continue
            if code in ("ExpiredTokenException", "RequestExpired"):
                # Attempt session refresh once before giving up.
                _state.state.reset()
                try:
                    ct = _state.state.get_client("controltower")
                    resp = ct.get_control_operation(operationIdentifier=operation_id)
                    op = resp["controlOperation"]
                    if op["status"] in _TERMINAL_STATUSES:
                        return op
                except ClientError as retry_err:
                    if retry_err.response["Error"]["Code"] in ("ExpiredTokenException", "RequestExpired"):
                        raise SessionExpiredError(operation_id) from retry_err
                    raise
            else:
                raise
        time.sleep(poll_interval)
    raise TimeoutError(
        f"Operation {operation_id} did not complete within {timeout}s"
    )
