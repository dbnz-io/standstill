from __future__ import annotations

import random
import time
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from standstill import state as _state

_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED"}
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestThrottled"}


@dataclass
class LzServiceSettings:
    enabled: bool = False
    account_id: str | None = None
    log_retention_days: int | None = None
    access_log_retention_days: int | None = None
    kms_key_arn: str | None = None


@dataclass
class LzSettings:
    governed_regions: list[str] = field(default_factory=list)
    security_ou: str = "Core"
    sandbox_ou: str = "Sandbox"
    logging: LzServiceSettings = field(default_factory=LzServiceSettings)
    config: LzServiceSettings = field(default_factory=LzServiceSettings)
    backup: LzServiceSettings = field(default_factory=LzServiceSettings)
    access_management_enabled: bool = False


@dataclass
class LandingZone:
    arn: str
    status: str              # ACTIVE | PROCESSING | FAILED
    version: str
    latest_version: str
    drift_status: str        # IN_SYNC | DRIFTED | UNKNOWN
    drift_types: list[str]
    settings: LzSettings
    manifest: dict           # raw manifest — used as base for update calls


# ---------------------------------------------------------------------------
# Fetch
# ---------------------------------------------------------------------------

def get_landing_zone() -> LandingZone | None:
    """
    Fetch the active landing zone and return a structured LandingZone object.
    Returns None if no landing zone exists.
    """
    ct = _state.state.get_client("controltower")
    resp = ct.list_landing_zones()
    zones = resp.get("landingZones", [])
    if not zones:
        return None

    lz_arn = zones[0]["arn"]
    detail = ct.get_landing_zone(landingZoneIdentifier=lz_arn)
    lz = detail["landingZone"]
    manifest = lz.get("manifest") or {}

    drift = lz.get("driftStatus") or {}
    version = lz.get("version", "UNKNOWN")

    return LandingZone(
        arn=lz_arn,
        status=lz.get("status", "UNKNOWN"),
        version=version,
        latest_version=lz.get("latestAvailableVersion") or version,
        drift_status=drift.get("status", "UNKNOWN"),
        drift_types=lz.get("remediationTypes") or [],
        settings=_parse_manifest(manifest),
        manifest=manifest,
    )


def _parse_manifest(manifest: dict) -> LzSettings:
    """Parse a landing zone manifest into structured settings."""
    org = manifest.get("organizationStructure") or {}

    # Centralized logging (CloudTrail aggregation)
    cl = manifest.get("centralizedLogging") or {}
    cl_cfg = cl.get("configurations") or {}
    logging = LzServiceSettings(
        enabled=bool(cl.get("enabled", False)),
        account_id=cl.get("accountId") or None,
        log_retention_days=(cl_cfg.get("loggingBucket") or {}).get("retentionDays"),
        access_log_retention_days=(cl_cfg.get("accessLoggingBucket") or {}).get("retentionDays"),
        kms_key_arn=cl_cfg.get("kmsKeyArn") or None,
    )

    # AWS Config
    cfg = manifest.get("config") or {}
    cfg_cfgs = cfg.get("configurations") or {}
    config = LzServiceSettings(
        enabled=bool(cfg.get("enabled", False)),
        account_id=cfg.get("accountId") or None,
        log_retention_days=(cfg_cfgs.get("loggingBucket") or {}).get("retentionDays"),
        access_log_retention_days=(cfg_cfgs.get("accessLoggingBucket") or {}).get("retentionDays"),
        kms_key_arn=cfg_cfgs.get("kmsKeyArn") or None,
    )

    # AWS Backup
    bk = manifest.get("backup") or {}
    bk_cfgs = bk.get("configurations") or {}
    backup = LzServiceSettings(
        enabled=bool(bk.get("enabled", False)),
        account_id=(bk_cfgs.get("centralBackup") or {}).get("accountId") or None,
    )

    return LzSettings(
        governed_regions=manifest.get("governedRegions") or [],
        security_ou=(org.get("security") or {}).get("name", "Core"),
        sandbox_ou=(org.get("sandbox") or {}).get("name", "Sandbox"),
        logging=logging,
        config=config,
        backup=backup,
        access_management_enabled=bool(
            (manifest.get("accessManagement") or {}).get("enabled", False)
        ),
    )


# ---------------------------------------------------------------------------
# Mutations
# ---------------------------------------------------------------------------

def reset_landing_zone(lz_arn: str) -> str:
    """Reset the landing zone. Returns the async operationIdentifier."""
    ct = _state.state.get_client("controltower")
    resp = ct.reset_landing_zone(landingZoneIdentifier=lz_arn)
    return resp["operationIdentifier"]


def update_landing_zone(lz_arn: str, version: str, manifest: dict) -> str:
    """
    Update the landing zone to a new version or apply manifest changes.
    Returns the async operationIdentifier.
    """
    ct = _state.state.get_client("controltower")
    resp = ct.update_landing_zone(
        landingZoneIdentifier=lz_arn,
        version=version,
        manifest=manifest,
    )
    return resp["operationIdentifier"]


def build_updated_manifest(manifest: dict, changes: dict) -> dict:
    """
    Apply a flat dict of targeted changes to a manifest copy.

    Supported keys in `changes`:
      logging_enabled             bool
      logging_log_retention_days  int
      logging_access_retention_days int
      logging_kms_key_arn         str | None
      config_enabled              bool
      config_log_retention_days   int
      config_access_retention_days int
      config_kms_key_arn          str | None
      backup_enabled              bool
      access_management_enabled   bool

    Leaves all other manifest fields untouched.
    """
    import copy
    m = copy.deepcopy(manifest)

    def _set(m, *path, value):
        node = m
        for key in path[:-1]:
            node = node.setdefault(key, {})
        if value is None:
            node.pop(path[-1], None)
        else:
            node[path[-1]] = value

    if "logging_enabled" in changes:
        _set(m, "centralizedLogging", "enabled", value=changes["logging_enabled"])
    if "logging_log_retention_days" in changes:
        _set(m, "centralizedLogging", "configurations", "loggingBucket", "retentionDays",
             value=changes["logging_log_retention_days"])
    if "logging_access_retention_days" in changes:
        _set(m, "centralizedLogging", "configurations", "accessLoggingBucket", "retentionDays",
             value=changes["logging_access_retention_days"])
    if "logging_kms_key_arn" in changes:
        _set(m, "centralizedLogging", "configurations", "kmsKeyArn",
             value=changes["logging_kms_key_arn"])

    if "config_enabled" in changes:
        _set(m, "config", "enabled", value=changes["config_enabled"])
    if "config_log_retention_days" in changes:
        _set(m, "config", "configurations", "loggingBucket", "retentionDays",
             value=changes["config_log_retention_days"])
    if "config_access_retention_days" in changes:
        _set(m, "config", "configurations", "accessLoggingBucket", "retentionDays",
             value=changes["config_access_retention_days"])
    if "config_kms_key_arn" in changes:
        _set(m, "config", "configurations", "kmsKeyArn",
             value=changes["config_kms_key_arn"])

    if "backup_enabled" in changes:
        _set(m, "backup", "enabled", value=changes["backup_enabled"])

    if "access_management_enabled" in changes:
        _set(m, "accessManagement", "enabled", value=changes["access_management_enabled"])

    return m


# ---------------------------------------------------------------------------
# Operation polling
# ---------------------------------------------------------------------------

def poll_lz_operation(
    operation_id: str,
    timeout: int = 3600,
    poll_interval: int = 30,
) -> dict:
    """
    Block until a landing zone operation reaches a terminal state or timeout.
    Returns the final operationDetails dict.

    LZ operations (reset / update) typically take 30–60 minutes.
    Raises TimeoutError if not complete within `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    # Spread initial poll to avoid hammering the API
    time.sleep(random.uniform(5, poll_interval * 0.5))

    throttle_count = 0

    while time.monotonic() < deadline:
        try:
            ct = _state.state.get_client("controltower")
            resp = ct.get_landing_zone_operation(operationIdentifier=operation_id)
            op = resp["operationDetails"]
            throttle_count = 0
            if op["status"] in _TERMINAL_STATUSES:
                return op
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _THROTTLE_CODES:
                throttle_count += 1
                backoff = min(poll_interval * (2 ** throttle_count), 120)
                time.sleep(backoff + random.uniform(0, backoff * 0.25))
                continue
            raise
        time.sleep(poll_interval)

    raise TimeoutError(
        f"Landing zone operation {operation_id} did not complete within {timeout}s. "
        "LZ operations can take 30–60 minutes. "
        "Check status with: standstill lz status"
    )
