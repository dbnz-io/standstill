from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_CONFIG_PATH = Path.home() / ".standstill" / "config.yaml"


def load() -> dict[str, Any]:
    """Return the full config dict, or {} if the file does not exist yet."""
    if not _CONFIG_PATH.exists():
        return {}
    return yaml.safe_load(_CONFIG_PATH.read_text()) or {}


def save(data: dict[str, Any]) -> None:
    _CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    _CONFIG_PATH.write_text(yaml.dump(data, default_flow_style=False, sort_keys=False))
    _CONFIG_PATH.chmod(0o600)


def get_profile() -> str | None:
    return load().get("profile")


def set_profile(profile: str) -> None:
    data = load()
    data["profile"] = profile
    save(data)


def unset_profile() -> None:
    data = load()
    data.pop("profile", None)
    save(data)


def get_management_role() -> str | None:
    return load().get("management_role_arn")


def set_management_role(role_arn: str) -> None:
    data = load()
    data["management_role_arn"] = role_arn
    save(data)


def unset_management_role() -> None:
    data = load()
    data.pop("management_role_arn", None)
    save(data)


def get_delegated_admin() -> str | None:
    return load().get("delegated_admin_account")


def set_delegated_admin(account_id: str) -> None:
    data = load()
    data["delegated_admin_account"] = account_id
    save(data)


def unset_delegated_admin() -> None:
    data = load()
    data.pop("delegated_admin_account", None)
    save(data)


# ---------------------------------------------------------------------------
# CloudTrail log target
# ---------------------------------------------------------------------------

def get_trail_s3() -> dict | None:
    """Return ``{"bucket": str, "prefix": str}`` or ``None``."""
    return load().get("cost_trail", {}).get("s3")


def set_trail_s3(bucket: str, prefix: str) -> None:
    data = load()
    data.setdefault("cost_trail", {})["s3"] = {"bucket": bucket, "prefix": prefix}
    save(data)


def unset_trail_s3() -> None:
    data = load()
    data.get("cost_trail", {}).pop("s3", None)
    save(data)


def get_trail_cloudwatch() -> str | None:
    """Return the CloudWatch Logs log-group name, or ``None``."""
    return load().get("cost_trail", {}).get("cloudwatch_log_group")


def set_trail_cloudwatch(log_group: str) -> None:
    data = load()
    data.setdefault("cost_trail", {})["cloudwatch_log_group"] = log_group
    save(data)


def unset_trail_cloudwatch() -> None:
    data = load()
    data.get("cost_trail", {}).pop("cloudwatch_log_group", None)
    save(data)
