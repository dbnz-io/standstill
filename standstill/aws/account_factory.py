from __future__ import annotations

import random
import re
import time

from botocore.exceptions import ClientError

from standstill import state as _state

_TERMINAL_STATUSES = {"SUCCEEDED", "FAILED"}
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestThrottled"}

# Control Tower does NOT expose account create/enroll/deregister as first-class
# boto3 APIs. Account Factory is published as a Service Catalog product named
# "AWS Control Tower Account Factory"; provisioning, enrolling, and unmanaging
# accounts are Service Catalog provision/terminate operations, each tracked by a
# RecordId and polled via describe_record.
_ACCOUNT_FACTORY_PRODUCT_NAME = "AWS Control Tower Account Factory"


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

def normalize_record(detail: dict) -> dict:
    """Normalize a Service Catalog RecordDetail to the shape the command layer
    expects: {status, statusMessage, operationType}."""
    errors = detail.get("RecordErrors", []) or []
    message = "; ".join(
        e.get("Description", "") for e in errors if e.get("Description")
    )
    return {
        "status": detail.get("Status", ""),
        "statusMessage": message or detail.get("Status", ""),
        "operationType": detail.get("RecordType", "PROVISION_PRODUCT"),
    }


def poll_account_operation(
    record_id: str,
    timeout: int = 1800,
    poll_interval: int = 15,
) -> dict:
    """
    Block until an Account Factory (Service Catalog) record reaches a terminal
    state, then return its normalized details.

    Account operations (create / enroll / deregister) are Service Catalog
    provision/terminate records polled via describe_record. They typically
    complete in 10–30 minutes.

    Raises TimeoutError if not complete within `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    time.sleep(random.uniform(5, poll_interval * 0.5))

    throttle_count = 0
    _MAX_BACKOFF = 120

    while time.monotonic() < deadline:
        try:
            sc = _sc_client()
            resp = sc.describe_record(Id=record_id)
            detail = resp.get("RecordDetail", {})
            throttle_count = 0
            if detail.get("Status") in _TERMINAL_STATUSES:
                return normalize_record(detail)
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
        f"Account operation {record_id} did not complete within {timeout}s. "
        "Account factory operations can take 10–30 minutes."
    )


# ---------------------------------------------------------------------------
# CT Account Factory (via AWS Service Catalog)
# ---------------------------------------------------------------------------

def _sc_client():
    return _state.state.get_client("servicecatalog")


def _find_account_factory() -> dict:
    """Resolve the Account Factory product, an active provisioning artifact, and
    a launch path. Returns {product_id, artifact_id, path_id}."""
    sc = _sc_client()

    products = sc.search_products(
        Filters={"FullTextSearch": [_ACCOUNT_FACTORY_PRODUCT_NAME]}
    ).get("ProductViewSummaries", [])
    product_id = next(
        (p["ProductId"] for p in products if p.get("Name") == _ACCOUNT_FACTORY_PRODUCT_NAME),
        None,
    )
    if not product_id:
        raise RuntimeError(
            "Could not find the 'AWS Control Tower Account Factory' Service "
            "Catalog product. Ensure Control Tower is deployed and the calling "
            "principal has access to the Account Factory portfolio."
        )

    # Prefer the DEFAULT-guidance active artifact; fall back to the newest active.
    artifacts = sc.describe_product(Id=product_id).get("ProvisioningArtifacts", [])
    active = [a for a in artifacts if a.get("Active", True)]
    artifact_id = next(
        (a["Id"] for a in active if a.get("Guidance") == "DEFAULT"),
        active[-1]["Id"] if active else None,
    )
    if artifact_id is None:
        raise RuntimeError("Account Factory product has no active provisioning artifact.")

    paths = sc.list_launch_paths(ProductId=product_id).get("LaunchPathSummaries", [])
    if not paths:
        raise RuntimeError("No launch path available for the Account Factory product.")

    return {"product_id": product_id, "artifact_id": artifact_id, "path_id": paths[0]["Id"]}


def _managed_ou_parameter(ou_id: str) -> str:
    """Account Factory's ManagedOrganizationalUnit parameter expects
    'OUName (ou-id)'. Resolve the OU name from its id."""
    org = _state.state.get_client("organizations")
    name = org.describe_organizational_unit(
        OrganizationalUnitId=ou_id
    )["OrganizationalUnit"]["Name"]
    return f"{name} ({ou_id})"


def _sanitize_provisioned_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "-", name).strip("-")
    return cleaned or "account"


def _provision_account(
    account_name: str,
    account_email: str,
    ou_id: str,
    sso_email: str,
    sso_first_name: str,
    sso_last_name: str,
) -> str:
    """Provision (create or enroll) an account through Account Factory.
    Returns the Service Catalog RecordId."""
    af = _find_account_factory()
    managed_ou = _managed_ou_parameter(ou_id)
    sc = _sc_client()
    resp = sc.provision_product(
        ProductId=af["product_id"],
        ProvisioningArtifactId=af["artifact_id"],
        PathId=af["path_id"],
        ProvisionedProductName=_sanitize_provisioned_name(account_name),
        ProvisioningParameters=[
            {"Key": "AccountName", "Value": account_name},
            {"Key": "AccountEmail", "Value": account_email},
            {"Key": "ManagedOrganizationalUnit", "Value": managed_ou},
            {"Key": "SSOUserEmail", "Value": sso_email},
            {"Key": "SSOUserFirstName", "Value": sso_first_name},
            {"Key": "SSOUserLastName", "Value": sso_last_name},
        ],
    )
    return resp["RecordDetail"]["RecordId"]


def create_managed_account(
    name: str,
    email: str,
    ou_id: str,
    sso_email: str | None = None,
    sso_first_name: str = "Account",
    sso_last_name: str = "Admin",
) -> str:
    """
    Create a new account via the Control Tower Account Factory.
    Returns the Service Catalog RecordId for async polling.

    The account is provisioned, baselined, and placed in the target OU.
    SSO parameters default to the root email and generic admin names.
    """
    return _provision_account(
        account_name=name,
        account_email=email,
        ou_id=ou_id,
        sso_email=sso_email or email,
        sso_first_name=sso_first_name,
        sso_last_name=sso_last_name,
    )


def register_managed_account(
    account_id: str,
    ou_id: str,
    sso_email: str | None = None,
    sso_first_name: str = "Account",
    sso_last_name: str = "Admin",
) -> str:
    """
    Enroll an existing organization account into Control Tower.
    Returns the Service Catalog RecordId for async polling.

    Account Factory enrolls (rather than creates) when the AccountEmail matches
    an account that already exists in the organization, so the account's email
    and name are resolved from Organizations first.
    """
    org = _state.state.get_client("organizations")
    acct = org.describe_account(AccountId=account_id)["Account"]
    return _provision_account(
        account_name=acct.get("Name") or account_id,
        account_email=acct["Email"],
        ou_id=ou_id,
        sso_email=sso_email or acct["Email"],
        sso_first_name=sso_first_name,
        sso_last_name=sso_last_name,
    )


def _find_provisioned_product_for_account(account_id: str) -> str:
    """Locate the Service Catalog provisioned product managing account_id by
    matching the AccountId output of each Account Factory provisioned product.
    Returns the ProvisionedProductId; raises RuntimeError if not found."""
    sc = _sc_client()
    kwargs: dict = {"AccessLevelFilter": {"Key": "Account", "Value": "self"}}
    while True:
        resp = sc.search_provisioned_products(**kwargs)
        for pp in resp.get("ProvisionedProducts", []):
            try:
                outputs = sc.get_provisioned_product_outputs(
                    ProvisionedProductId=pp["Id"]
                ).get("Outputs", [])
            except ClientError:
                continue
            for o in outputs:
                if o.get("OutputKey") == "AccountId" and o.get("OutputValue") == account_id:
                    return pp["Id"]
        token = resp.get("NextPageToken")
        if not token:
            break
        kwargs["PageToken"] = token
    raise RuntimeError(
        f"No Account Factory provisioned product found for account {account_id}. "
        "It may have been created outside Account Factory and cannot be "
        "unmanaged this way."
    )


def deregister_managed_account(account_id: str) -> str:
    """
    Unmanage an account by terminating its Account Factory provisioned product.
    Returns the Service Catalog RecordId for async polling.

    The account remains in the organization but leaves Control Tower governance.
    """
    pp_id = _find_provisioned_product_for_account(account_id)
    sc = _sc_client()
    resp = sc.terminate_provisioned_product(ProvisionedProductId=pp_id)
    return resp["RecordDetail"]["RecordId"]


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
