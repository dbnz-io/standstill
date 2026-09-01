from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from standstill import state as _state

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SSOInstance:
    instance_arn: str
    identity_store_id: str
    name: str | None


@dataclass
class PermissionSet:
    arn: str
    name: str
    description: str
    session_duration: str
    created_date: str | None
    managed_policies: list[str] = field(default_factory=list)  # list of managed policy ARNs
    inline_policy: str | None = None  # JSON string or None


@dataclass
class AccountAssignment:
    account_id: str
    account_name: str  # may be "" if not resolved
    permission_set_arn: str
    permission_set_name: str  # may be "" if not resolved
    principal_id: str
    principal_name: str  # may be "" if not resolved
    principal_type: str  # "USER" | "GROUP"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_instance() -> SSOInstance | None:
    """Return the first SSO instance or None."""
    client = _state.state.get_client("sso-admin")
    try:
        resp = client.list_instances()
        instances = resp.get("Instances", [])
        if not instances:
            return None
        inst = instances[0]
        return SSOInstance(
            instance_arn=inst["InstanceArn"],
            identity_store_id=inst["IdentityStoreId"],
            name=inst.get("Name"),
        )
    except ClientError:
        return None


def _describe_permission_set(instance_arn: str, ps_arn: str) -> PermissionSet:
    """Fetch full details for a single permission set ARN."""
    client = _state.state.get_client("sso-admin")

    resp = client.describe_permission_set(
        InstanceArn=instance_arn,
        PermissionSetArn=ps_arn,
    )
    raw = resp["PermissionSet"]

    # Managed policies
    managed: list[str] = []
    kwargs: dict = {"InstanceArn": instance_arn, "PermissionSetArn": ps_arn}
    while True:
        mp_resp = client.list_managed_policies_in_permission_set(**kwargs)
        for mp in mp_resp.get("AttachedManagedPolicies", []):
            managed.append(mp.get("Arn", ""))
        token = mp_resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token

    # Inline policy
    inline: str | None = None
    try:
        ip_resp = client.get_inline_policy_for_permission_set(
            InstanceArn=instance_arn,
            PermissionSetArn=ps_arn,
        )
        inline_doc = ip_resp.get("InlinePolicy", "")
        inline = inline_doc if inline_doc else None
    except ClientError:
        pass

    created = raw.get("CreatedDate")
    created_str = str(created) if created else None

    return PermissionSet(
        arn=ps_arn,
        name=raw.get("Name", ""),
        description=raw.get("Description", ""),
        session_duration=raw.get("SessionDuration", ""),
        created_date=created_str,
        managed_policies=managed,
        inline_policy=inline,
    )


def list_permission_sets(instance_arn: str) -> list[PermissionSet]:
    """List all permission sets for an SSO instance."""
    client = _state.state.get_client("sso-admin")
    arns: list[str] = []
    kwargs: dict = {"InstanceArn": instance_arn}
    while True:
        resp = client.list_permission_sets(**kwargs)
        arns.extend(resp.get("PermissionSets", []))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token

    results: list[PermissionSet] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {
            pool.submit(_describe_permission_set, instance_arn, arn): arn
            for arn in arns
        }
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    return sorted(results, key=lambda ps: ps.name)


def resolve_principal_name(
    identity_store_id: str,
    principal_id: str,
    principal_type: str,
) -> str:
    """Resolve a principal ID to a display name. Returns principal_id on error."""
    client = _state.state.get_client("identitystore")
    try:
        if principal_type.upper() == "USER":
            resp = client.describe_user(
                IdentityStoreId=identity_store_id,
                UserId=principal_id,
            )
            return resp.get("DisplayName") or resp.get("UserName") or principal_id
        else:
            resp = client.describe_group(
                IdentityStoreId=identity_store_id,
                GroupId=principal_id,
            )
            return resp.get("DisplayName") or resp.get("GroupName") or principal_id
    except ClientError:
        return principal_id


def resolve_principal_id(
    identity_store_id: str,
    name: str,
    principal_type: str,
) -> str | None:
    """Search for a principal by display name. Returns None if not found."""
    client = _state.state.get_client("identitystore")
    try:
        if principal_type.upper() == "USER":
            resp = client.list_users(
                IdentityStoreId=identity_store_id,
                Filters=[{"AttributePath": "DisplayName", "AttributeValue": name}],
            )
            users = resp.get("Users", [])
            if users:
                return users[0].get("UserId")
        else:
            resp = client.list_groups(
                IdentityStoreId=identity_store_id,
                Filters=[{"AttributePath": "DisplayName", "AttributeValue": name}],
            )
            groups = resp.get("Groups", [])
            if groups:
                return groups[0].get("GroupId")
    except ClientError:
        pass
    return None


_ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedException",
    "AuthorizationError",
}
_THROTTLE_CODES = {"ThrottlingException", "Throttling", "RequestThrottled", "TooManyRequestsException"}


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def list_all_assignments(
    instance_arn: str,
    identity_store_id: str,
    ps_list: list[PermissionSet],
    account_name_map: dict[str, str],
) -> list[AccountAssignment]:
    """
    List all account assignments across all permission sets.
    Resolves principal names concurrently.

    Raises ClientError on an access-denied error rather than returning a silent
    partial listing — a truncated result that looks complete is worse than a
    loud failure for an audit view.
    """
    client = _state.state.get_client("sso-admin")
    raw_assignments: list[tuple[str, str, str, str, str]] = []  # (account_id, ps_arn, ps_name, principal_id, principal_type)

    for ps in ps_list:
        # Get accounts provisioned with this PS
        account_ids: list[str] = []
        kwargs: dict = {"InstanceArn": instance_arn, "PermissionSetArn": ps.arn}
        while True:
            try:
                resp = client.list_accounts_for_provisioned_permission_set(**kwargs)
                account_ids.extend(resp.get("AccountIds", []))
                token = resp.get("NextToken")
                if not token:
                    break
                kwargs["NextToken"] = token
            except ClientError as exc:
                if _error_code(exc) in _ACCESS_DENIED_CODES:
                    raise
                break

        for account_id in account_ids:
            assign_kwargs: dict = {
                "InstanceArn": instance_arn,
                "AccountId": account_id,
                "PermissionSetArn": ps.arn,
            }
            while True:
                try:
                    resp = client.list_account_assignments(**assign_kwargs)
                    for a in resp.get("AccountAssignments", []):
                        raw_assignments.append((
                            account_id,
                            ps.arn,
                            ps.name,
                            a["PrincipalId"],
                            a["PrincipalType"],
                        ))
                    token = resp.get("NextToken")
                    if not token:
                        break
                    assign_kwargs["NextToken"] = token
                except ClientError as exc:
                    if _error_code(exc) in _ACCESS_DENIED_CODES:
                        raise
                    break

    # Resolve principal names concurrently
    def _resolve(item: tuple) -> AccountAssignment:
        account_id, ps_arn, ps_name, principal_id, principal_type = item
        principal_name = resolve_principal_name(identity_store_id, principal_id, principal_type)
        return AccountAssignment(
            account_id=account_id,
            account_name=account_name_map.get(account_id, ""),
            permission_set_arn=ps_arn,
            permission_set_name=ps_name,
            principal_id=principal_id,
            principal_name=principal_name,
            principal_type=principal_type,
        )

    results: list[AccountAssignment] = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(_resolve, item) for item in raw_assignments]
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass

    return sorted(results, key=lambda a: (a.account_name or a.account_id, a.permission_set_name))


def create_assignment(
    instance_arn: str,
    account_id: str,
    ps_arn: str,
    principal_type: str,
    principal_id: str,
) -> dict:
    """Create an account assignment. Returns RequestId and Status."""
    client = _state.state.get_client("sso-admin")
    resp = client.create_account_assignment(
        InstanceArn=instance_arn,
        TargetId=account_id,
        TargetType="AWS_ACCOUNT",
        PermissionSetArn=ps_arn,
        PrincipalType=principal_type,
        PrincipalId=principal_id,
    )
    status = resp.get("AccountAssignmentCreationStatus", {})
    return {
        "RequestId": status.get("RequestId", ""),
        "Status": status.get("Status", ""),
    }


def delete_assignment(
    instance_arn: str,
    account_id: str,
    ps_arn: str,
    principal_type: str,
    principal_id: str,
) -> dict:
    """Delete an account assignment. Returns RequestId and Status."""
    client = _state.state.get_client("sso-admin")
    resp = client.delete_account_assignment(
        InstanceArn=instance_arn,
        TargetId=account_id,
        TargetType="AWS_ACCOUNT",
        PermissionSetArn=ps_arn,
        PrincipalType=principal_type,
        PrincipalId=principal_id,
    )
    status = resp.get("AccountAssignmentDeletionStatus", {})
    return {
        "RequestId": status.get("RequestId", ""),
        "Status": status.get("Status", ""),
    }


def find_permission_set_by_name(instance_arn: str, name: str) -> PermissionSet | None:
    """Find a permission set by name."""
    ps_list = list_permission_sets(instance_arn)
    for ps in ps_list:
        if ps.name == name:
            return ps
    return None


def poll_assignment_status(
    instance_arn: str,
    request_id: str,
    operation: str = "creation",
    max_wait: int = 60,
    interval: int = 2,
) -> str:
    """
    Poll for assignment creation/deletion completion.
    Returns final status string: "SUCCEEDED", "FAILED", or "IN_PROGRESS".
    """
    client = _state.state.get_client("sso-admin")
    elapsed = 0
    while elapsed < max_wait:
        try:
            if operation == "deletion":
                resp = client.describe_account_assignment_deletion_status(
                    InstanceArn=instance_arn,
                    AccountAssignmentDeletionRequestId=request_id,
                )
                status_obj = resp.get("AccountAssignmentDeletionStatus", {})
            else:
                resp = client.describe_account_assignment_creation_status(
                    InstanceArn=instance_arn,
                    AccountAssignmentCreationRequestId=request_id,
                )
                status_obj = resp.get("AccountAssignmentCreationStatus", {})

            status = status_obj.get("Status", "IN_PROGRESS")
            if status in ("SUCCEEDED", "FAILED"):
                return status
        except ClientError as exc:
            # A transient throttle mid-poll is not a real failure — keep waiting.
            if _error_code(exc) not in _THROTTLE_CODES:
                return "FAILED"

        time.sleep(interval)
        elapsed += interval

    return "IN_PROGRESS"
