from __future__ import annotations

import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import boto3
import yaml
from botocore.exceptions import ClientError

from standstill import state as _state

if TYPE_CHECKING:
    from standstill.aws.organizations import Account

_BUNDLED_TYPES_PATH = Path(__file__).parent.parent / "data" / "securityhub_resource_types.yaml"
_USER_TYPES_PATH = Path.home() / ".standstill" / "securityhub_resource_types.yaml"

RECORDING_FREQUENCIES = ("CONTINUOUS", "DAILY")

# AWS Config resource type format: AWS::<Service>::<ResourceType>
_RESOURCE_TYPE_RE = re.compile(r"^AWS::[A-Za-z0-9]+::[A-Za-z0-9]+$")


# ---------------------------------------------------------------------------
# Resource type catalog
# ---------------------------------------------------------------------------

def load_bundled_resource_types() -> list[str]:
    """Return the bundled Security Hub resource type list (read-only defaults)."""
    data = yaml.safe_load(_BUNDLED_TYPES_PATH.read_text())
    return [str(t) for t in data.get("resource_types", [])]


def load_user_resource_types() -> list[str] | None:
    """Return the user-defined resource types, or None if no override file exists."""
    if not _USER_TYPES_PATH.exists():
        return None
    data = yaml.safe_load(_USER_TYPES_PATH.read_text())
    return [str(t) for t in data.get("resource_types", [])]


def load_resource_types() -> list[str]:
    """
    Return the active resource type list.
    Prefers ~/.standstill/securityhub_resource_types.yaml over the bundled fallback.
    """
    user = load_user_resource_types()
    return user if user is not None else load_bundled_resource_types()


def is_user_override_active() -> bool:
    return _USER_TYPES_PATH.exists()


def save_user_resource_types(types: list[str]) -> None:
    """Persist a resource type list to the user override file."""
    _USER_TYPES_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    header = (
        "# Standstill — custom AWS Config resource types for Security Hub\n"
        "# Managed by: standstill recorder types add/remove\n"
        "# Reset to bundled defaults: standstill recorder types reset\n\n"
    )
    _USER_TYPES_PATH.write_text(
        header + yaml.dump({"resource_types": sorted(types)}, default_flow_style=False)
    )
    _USER_TYPES_PATH.chmod(0o600)


def validate_resource_type(type_str: str) -> bool:
    return bool(_RESOURCE_TYPE_RE.match(type_str))


def add_resource_type(type_str: str) -> tuple[bool, str]:
    """
    Add a resource type to the active list.
    Initialises the user override from the bundled list if it doesn't exist yet.
    Returns (added: bool, message: str).
    """
    if not validate_resource_type(type_str):
        return False, f"Invalid format. Expected AWS::<Service>::<ResourceType>, got: {type_str}"
    current = load_resource_types()
    if type_str in current:
        return False, f"{type_str} is already in the list."
    save_user_resource_types(current + [type_str])
    return True, f"Added {type_str}."


def remove_resource_type(type_str: str) -> tuple[bool, str]:
    """
    Remove a resource type from the active list.
    Initialises the user override from the bundled list if it doesn't exist yet.
    Returns (removed: bool, message: str).
    """
    current = load_resource_types()
    if type_str not in current:
        return False, f"{type_str} is not in the active list."
    save_user_resource_types([t for t in current if t != type_str])
    return True, f"Removed {type_str}."


def reset_resource_types() -> bool:
    """
    Delete the user override file, reverting to bundled defaults.
    Returns True if a file was removed, False if there was nothing to remove.
    """
    if _USER_TYPES_PATH.exists():
        _USER_TYPES_PATH.unlink()
        return True
    return False


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RecorderState:
    account_id: str
    account_name: str = ""
    ou_name: str = ""
    exists: bool = False
    running: bool = False
    recorder_name: str = ""
    role_arn: str = ""
    all_supported: bool = False
    resource_type_count: int = 0
    recording_frequency: str = ""   # CONTINUOUS | DAILY | "" if unknown / not set
    error: str = ""


@dataclass
class RecorderResult:
    account_id: str
    account_name: str = ""
    ou_name: str = ""
    success: bool = False
    noop: bool = False      # True when desired state already matches current state
    message: str = ""
    planned_types: int = 0
    planned_frequency: str = ""


# ---------------------------------------------------------------------------
# Per-account Config client
# ---------------------------------------------------------------------------

def _account_config_client(account_id: str, role_name: str, region: str):
    """Assume the CT execution role in a member account and return a Config client."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = _state.state.get_client("sts")
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"standstill-rec-{os.getpid()}")
    except ClientError as e:
        raise RuntimeError(
            f"Cannot assume {role_arn}: {e.response['Error']['Message']}"
        ) from e
    creds = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    return session.client("config", region_name=region)


# ---------------------------------------------------------------------------
# Read
# ---------------------------------------------------------------------------

def get_recorder_state(account: Account, role_name: str, region: str) -> RecorderState:
    """Fetch the current Config recorder state for a single account."""
    state = RecorderState(
        account_id=account.id,
        account_name=account.name,
        ou_name=account.ou_name,
    )
    try:
        cfg = _account_config_client(account.id, role_name, region)
    except RuntimeError as e:
        state.error = str(e)
        return state

    try:
        recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError as e:
        state.error = e.response["Error"]["Message"]
        return state

    if not recorders:
        return state  # exists=False

    recorder = recorders[0]
    state.exists = True
    state.recorder_name = recorder.get("name", "default")
    state.role_arn = recorder.get("roleARN", "")

    rg = recorder.get("recordingGroup", {})
    state.all_supported = rg.get("allSupported", False)
    state.resource_type_count = len(rg.get("resourceTypes", []))

    # recordingMode was added Nov 2023; older recorders won't have it → default to CONTINUOUS
    mode = recorder.get("recordingMode", {})
    state.recording_frequency = mode.get("recordingFrequency", "CONTINUOUS")

    try:
        statuses = cfg.describe_configuration_recorder_status().get(
            "ConfigurationRecordersStatus", []
        )
        state.running = any(s.get("recording", False) for s in statuses)
    except ClientError:
        pass  # non-fatal — running stays False

    return state


def get_all_recorder_states(
    accounts: list[Account],
    role_name: str,
    region: str,
    max_workers: int = 20,
) -> list[RecorderState]:
    results: list[RecorderState] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(get_recorder_state, acct, role_name, region): acct
            for acct in accounts
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: (r.ou_name, r.account_name))


# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------

def configure_recorder(
    account: Account,
    role_name: str,
    region: str,
    frequency: str,
    resource_types: list[str],
) -> RecorderResult:
    """
    Apply the desired recorder configuration to a single account.

    - Preserves the existing recorder name and IAM role ARN.
    - Skips accounts with no recorder (they aren't enrolled in Control Tower).
    - Detects no-op (desired == current) and skips the API call.
    """
    result = RecorderResult(
        account_id=account.id,
        account_name=account.name,
        ou_name=account.ou_name,
        planned_types=len(resource_types),
        planned_frequency=frequency,
    )

    # Fetch current state to detect no-op and get the existing role ARN
    current = get_recorder_state(account, role_name, region)

    if current.error:
        result.message = current.error
        return result

    if not current.exists:
        result.message = "No recorder found — account may not be enrolled in Control Tower."
        return result

    # No-op check
    already_correct = (
        not current.all_supported
        and current.resource_type_count == len(resource_types)
        and current.recording_frequency == frequency
        and current.running
    )
    if already_correct:
        result.success = True
        result.noop = True
        result.message = "Already up to date."
        return result

    try:
        cfg = _account_config_client(account.id, role_name, region)
        cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": current.recorder_name,
                "roleARN": current.role_arn,
                "recordingGroup": {
                    "allSupported": False,
                    "includeGlobalResourceTypes": False,
                    "resourceTypes": resource_types,
                    "recordingStrategy": {
                        "useOnly": "INCLUSION_BY_RESOURCE_TYPES",
                    },
                },
                "recordingMode": {
                    "recordingFrequency": frequency,
                },
            }
        )
        if not current.running:
            cfg.start_configuration_recorder(
                ConfigurationRecorderName=current.recorder_name
            )
        result.success = True
        result.message = (
            f"{len(resource_types)} types, {frequency.lower()} recording"
            + ("" if current.running else " (recorder started)")
        )
    except ClientError as e:
        result.message = e.response["Error"]["Message"]

    return result


def configure_all_recorders(
    accounts: list[Account],
    role_name: str,
    region: str,
    frequency: str,
    resource_types: list[str],
    max_workers: int = 20,
) -> list[RecorderResult]:
    results: list[RecorderResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                configure_recorder, acct, role_name, region, frequency, resource_types
            ): acct
            for acct in accounts
        }
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda r: (r.ou_name, r.account_name))
