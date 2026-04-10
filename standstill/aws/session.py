from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError, NoCredentialsError

from standstill import state as _state

if TYPE_CHECKING:
    from standstill.aws.organizations import Account


def get_caller_identity() -> dict:
    """Return STS caller identity dict. Raises RuntimeError on any auth failure."""
    try:
        sts = _state.state.get_client("sts")
        return sts.get_caller_identity()
    except NoCredentialsError:
        raise RuntimeError(
            "No AWS credentials found. "
            "Configure via environment variables, ~/.aws/credentials, or --profile."
        )
    except ClientError as e:
        raise RuntimeError(
            f"AWS authentication failed: {e.response['Error']['Message']}"
        ) from e


def check_ct_permissions() -> dict[str, bool | str]:
    """
    Probe key permissions with safe, read-only API calls.

    Returns a dict mapping permission label → True (granted) or error code string (denied/error).
    """
    results: dict[str, bool | str] = {}

    # --- AWS Organizations ---
    org = _state.state.get_client("organizations")

    for label, call in [
        ("organizations:DescribeOrganization", lambda: org.describe_organization()),
        ("organizations:ListRoots", lambda: org.list_roots()),
        ("organizations:ListOUsForParent", lambda: org.list_organizational_units_for_parent(ParentId="r-0000")),
        ("organizations:ListAccountsForParent", lambda: org.list_accounts_for_parent(ParentId="r-0000")),
    ]:
        try:
            call()
            results[label] = True
        except ClientError as e:
            code = e.response["Error"]["Code"]
            # A targeted "not found" means the call reached the service — permission is OK
            results[label] = True if code in ("ParentNotFoundException", "TargetNotFoundException") else code

    # --- AWS Control Tower ---
    ct = _state.state.get_client("controltower")

    # list_landing_zones is a lightweight read-only call that confirms CT API access
    try:
        ct.list_landing_zones()
        results["controltower:ListLandingZones"] = True
    except ClientError as e:
        results["controltower:ListLandingZones"] = e.response["Error"]["Code"]

    # These require a governed OU target or an in-flight operation — verified at runtime
    results["controltower:ListEnabledControls"] = "(verified at runtime)"
    results["controltower:EnableControl"] = "(verified at runtime)"
    results["controltower:GetControlOperation"] = "(verified at runtime)"

    return results


# ---------------------------------------------------------------------------
# Account role reachability
# ---------------------------------------------------------------------------

def _check_one_account_role(account_id: str, role_name: str) -> tuple[bool, str]:
    """
    Try to assume `role_name` in `account_id`.
    Returns (reachable: bool, detail: str).
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        sts = _state.state.get_client("sts")
        sts.assume_role(RoleArn=role_arn, RoleSessionName="standstill-check")
        return True, role_arn
    except ClientError as e:
        return False, e.response["Error"]["Message"]
    except Exception as e:
        return False, str(e)


def check_all_account_roles(
    accounts: list[Account],
    role_name: str,
    max_workers: int = 20,
) -> dict[str, tuple[bool, str]]:
    """
    Concurrently probe every account for assume-role reachability.
    Returns {account_id: (reachable, detail)}.
    """
    results: dict[str, tuple[bool, str]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_check_one_account_role, acct.id, role_name): acct
            for acct in accounts
        }
        for future in as_completed(futures):
            acct = futures[future]
            results[acct.id] = future.result()
    return results
