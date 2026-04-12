from __future__ import annotations

import random
import time

from botocore.exceptions import ClientError

from standstill import state as _state

_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED"}
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestThrottled"}


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _get_org_root_id() -> str:
    """Return the organization root ID."""
    org = _state.state.get_client("organizations")
    roots = org.list_roots().get("Roots", [])
    if not roots:
        raise RuntimeError("No AWS Organizations root found.")
    return roots[0]["Id"]


def _get_parent_id(child_id: str) -> str:
    """Return the parent OU or root ID for an account or OU."""
    org = _state.state.get_client("organizations")
    resp = org.list_parents(ChildId=child_id)
    parents = resp.get("Parents", [])
    if not parents:
        raise RuntimeError(f"No parent found for {child_id}.")
    return parents[0]["Id"]


# ---------------------------------------------------------------------------
# Account operation polling
# ---------------------------------------------------------------------------

def poll_account_operation(
    operation_id: str,
    timeout: int = 1800,
    poll_interval: int = 15,
) -> dict:
    """
    Block until a CT account management operation reaches a terminal state.

    Account operations (create / register / deregister) are polled via
    get_landing_zone_operation — the same endpoint used for LZ operations.
    Account factory operations typically complete in 10–30 minutes.

    Raises TimeoutError if not complete within `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    time.sleep(random.uniform(5, poll_interval * 0.5))

    throttle_count = 0
    _MAX_BACKOFF = 120

    while time.monotonic() < deadline:
        try:
            ct = _state.state.get_client("controltower")
            resp = ct.get_landing_zone_operation(operationIdentifier=operation_id)
            op = resp.get("operationDetails", {})
            throttle_count = 0
            if op.get("status") in _TERMINAL_STATUSES:
                return op
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in _THROTTLE_CODES:
                throttle_count += 1
                backoff = min(poll_interval * (2 ** throttle_count), _MAX_BACKOFF)
                time.sleep(backoff + random.uniform(0, backoff * 0.25))
                continue
            raise
        time.sleep(poll_interval)

    raise TimeoutError(
        f"Account operation {operation_id} did not complete within {timeout}s. "
        "Account factory operations can take 10–30 minutes."
    )


# ---------------------------------------------------------------------------
# CT Account Factory
# ---------------------------------------------------------------------------

def create_managed_account(name: str, email: str, ou_id: str) -> str:
    """
    Create a new account via the Control Tower Account Factory.
    Returns the operationIdentifier for async polling.

    Requires Control Tower 3.0+ and management-account credentials.
    The account is provisioned, baselined, and placed in the target OU.
    """
    ct = _state.state.get_client("controltower")
    resp = ct.create_managed_account(
        accountName=name,
        accountEmail=email,
        organizationalUnitId=ou_id,
    )
    return resp["operationIdentifier"]


def register_managed_account(account_id: str, ou_id: str) -> str:
    """
    Enroll an existing AWS account into Control Tower.
    Returns the operationIdentifier for async polling.

    The account must already be a member of the organization and must NOT
    be currently enrolled in Control Tower (no active CT baseline).
    """
    ct = _state.state.get_client("controltower")
    resp = ct.register_managed_account(
        accountId=account_id,
        organizationalUnitId=ou_id,
    )
    return resp["operationIdentifier"]


def deregister_managed_account(account_id: str) -> str:
    """
    Deregister an account from Control Tower management.
    Returns the operationIdentifier for async polling.

    The account remains in the organization but is no longer CT-governed.
    All enrolled controls are removed and the CT execution role is deleted.
    """
    ct = _state.state.get_client("controltower")
    resp = ct.deregister_managed_account(accountId=account_id)
    return resp["operationIdentifier"]


# ---------------------------------------------------------------------------
# Organizations account operations
# ---------------------------------------------------------------------------

def get_org_root_id() -> str:
    """Return the organization root ID."""
    return _get_org_root_id()


def move_account(account_id: str, dest_ou_id: str) -> str:
    """
    Move an account to a different OU or root.
    Resolves the current parent automatically and calls move_account.
    Returns the source parent ID.

    Raises ValueError if the account is already in the destination.
    Raises ClientError if the destination OU does not exist.
    """
    source_id = _get_parent_id(account_id)
    if source_id == dest_ou_id:
        raise ValueError(f"Account {account_id} is already in {dest_ou_id}.")
    org = _state.state.get_client("organizations")
    org.move_account(
        AccountId=account_id,
        SourceParentId=source_id,
        DestinationParentId=dest_ou_id,
    )
    return source_id


def describe_account(account_id: str) -> dict:
    """
    Return detailed account information from the Organizations API.
    Adds a ParentId key with the current parent OU (or root) ID.
    """
    org = _state.state.get_client("organizations")
    resp = org.describe_account(AccountId=account_id)
    account = resp["Account"]
    try:
        account["ParentId"] = _get_parent_id(account_id)
    except Exception:
        account["ParentId"] = "unknown"
    return account


# ---------------------------------------------------------------------------
# Organizations OU operations
# ---------------------------------------------------------------------------

def create_ou(parent_id: str, name: str) -> dict:
    """
    Create a new OU under the given parent (root ID or OU ID).
    Returns the new OU dict: {Id, Arn, Name}.
    """
    org = _state.state.get_client("organizations")
    resp = org.create_organizational_unit(ParentId=parent_id, Name=name)
    return resp["OrganizationalUnit"]


def delete_ou(ou_id: str) -> None:
    """
    Delete an OU. The OU must be empty (no child OUs or accounts).
    Raises ClientError(OrganizationalUnitNotEmptyException) if not empty.
    """
    org = _state.state.get_client("organizations")
    org.delete_organizational_unit(OrganizationalUnitId=ou_id)


def rename_ou(ou_id: str, new_name: str) -> dict:
    """
    Rename an OU. Returns the updated OU dict: {Id, Arn, Name}.
    """
    org = _state.state.get_client("organizations")
    resp = org.update_organizational_unit(
        OrganizationalUnitId=ou_id,
        Name=new_name,
    )
    return resp["OrganizationalUnit"]


def find_account_by_email(email: str, ou_id: str) -> str | None:
    """
    Search for an account in the given OU by email address (case-insensitive, paginated).
    Returns the account ID if found, None otherwise.
    Only searches direct members of ou_id — does not recurse into child OUs.
    """
    org = _state.state.get_client("organizations")
    kwargs: dict = {"ParentId": ou_id}
    while True:
        resp = org.list_accounts_for_parent(**kwargs)
        for acct in resp.get("Accounts", []):
            if acct.get("Email", "").lower() == email.lower():
                return acct["Id"]
        if "NextToken" not in resp:
            break
        kwargs["NextToken"] = resp["NextToken"]
    return None


def describe_ou(ou_id: str) -> dict:
    """
    Return detailed information for an OU.

    Adds:
      ParentId    — direct parent (OU or root ID)
      ChildOUs    — list of direct child OU dicts
      Accounts    — list of direct member account dicts
    """
    org = _state.state.get_client("organizations")
    resp = org.describe_organizational_unit(OrganizationalUnitId=ou_id)
    ou = resp["OrganizationalUnit"]

    try:
        ou["ParentId"] = _get_parent_id(ou_id)
    except Exception:
        ou["ParentId"] = "unknown"

    child_ous: list[dict] = []
    kwargs: dict = {"ParentId": ou_id}
    while True:
        r = org.list_organizational_units_for_parent(**kwargs)
        child_ous.extend(r.get("OrganizationalUnits", []))
        if "NextToken" not in r:
            break
        kwargs["NextToken"] = r["NextToken"]
    ou["ChildOUs"] = child_ous

    child_accounts: list[dict] = []
    kwargs = {"ParentId": ou_id}
    while True:
        r = org.list_accounts_for_parent(**kwargs)
        child_accounts.extend(r.get("Accounts", []))
        if "NextToken" not in r:
            break
        kwargs["NextToken"] = r["NextToken"]
    ou["Accounts"] = child_accounts

    return ou
