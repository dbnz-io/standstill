from __future__ import annotations

from dataclasses import dataclass

from botocore.exceptions import ClientError

from standstill import state as _state

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class SCPPolicy:
    id: str
    arn: str
    name: str
    description: str
    aws_managed: bool  # True for AWS-managed policies like FullAWSAccess


@dataclass
class SCPTarget:
    target_id: str  # account ID or OU ID or root ID
    arn: str
    name: str
    type: str  # "ACCOUNT" | "ORGANIZATIONAL_UNIT" | "ROOT"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _policy_from_raw(raw: dict) -> SCPPolicy:
    summary = raw.get("PolicySummary", raw)
    return SCPPolicy(
        id=summary.get("Id", ""),
        arn=summary.get("Arn", ""),
        name=summary.get("Name", ""),
        description=summary.get("Description", ""),
        aws_managed=summary.get("AwsManaged", False),
    )


def _target_from_raw(raw: dict) -> SCPTarget:
    return SCPTarget(
        target_id=raw.get("TargetId", ""),
        arn=raw.get("Arn", ""),
        name=raw.get("Name", ""),
        type=raw.get("Type", ""),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_scps() -> list[SCPPolicy]:
    """List all SCPs in the organization."""
    client = _state.state.get_client("organizations")
    policies: list[SCPPolicy] = []
    kwargs: dict = {"Filter": "SERVICE_CONTROL_POLICY"}
    while True:
        resp = client.list_policies(**kwargs)
        for p in resp.get("Policies", []):
            policies.append(_policy_from_raw(p))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return policies


def describe_scp(policy_id: str) -> tuple[SCPPolicy, str]:
    """Describe an SCP, returning (policy, content_json)."""
    client = _state.state.get_client("organizations")
    resp = client.describe_policy(PolicyId=policy_id)
    raw = resp["Policy"]
    policy = _policy_from_raw(raw)
    content = raw.get("Content", "{}")
    return policy, content


def list_targets(policy_id: str) -> list[SCPTarget]:
    """List targets attached to an SCP."""
    client = _state.state.get_client("organizations")
    targets: list[SCPTarget] = []
    kwargs: dict = {"PolicyId": policy_id}
    while True:
        resp = client.list_targets_for_policy(**kwargs)
        for t in resp.get("Targets", []):
            targets.append(_target_from_raw(t))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return targets


def list_scps_for_target(target_id: str) -> list[SCPPolicy]:
    """List SCPs attached to a specific target (account, OU, or root)."""
    client = _state.state.get_client("organizations")
    policies: list[SCPPolicy] = []
    kwargs: dict = {"TargetId": target_id, "Filter": "SERVICE_CONTROL_POLICY"}
    while True:
        resp = client.list_policies_for_target(**kwargs)
        for p in resp.get("Policies", []):
            policies.append(_policy_from_raw(p))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return policies


def attach_scp(policy_id: str, target_id: str) -> None:
    """Attach an SCP to a target."""
    client = _state.state.get_client("organizations")
    client.attach_policy(PolicyId=policy_id, TargetId=target_id)


def detach_scp(policy_id: str, target_id: str) -> None:
    """Detach an SCP from a target."""
    client = _state.state.get_client("organizations")
    client.detach_policy(PolicyId=policy_id, TargetId=target_id)


def create_scp(name: str, description: str, content: str) -> SCPPolicy:
    """Create a new SCP."""
    client = _state.state.get_client("organizations")
    resp = client.create_policy(
        Name=name,
        Description=description,
        Content=content,
        Type="SERVICE_CONTROL_POLICY",
    )
    return _policy_from_raw(resp["Policy"])


def delete_scp(policy_id: str) -> None:
    """Delete an SCP."""
    client = _state.state.get_client("organizations")
    client.delete_policy(PolicyId=policy_id)


def find_scp(name_or_id: str) -> SCPPolicy | None:
    """Look up an SCP by name or ID."""
    # If it looks like an ID (p- prefix), try direct describe
    if name_or_id.startswith("p-"):
        try:
            policy, _ = describe_scp(name_or_id)
            return policy
        except ClientError:
            return None
    # Otherwise search by name
    policies = list_scps()
    for p in policies:
        if p.name == name_or_id:
            return p
    return None


_ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedException",
    "AuthorizationError",
}


def build_target_scp_map() -> dict[str, list[SCPPolicy]]:
    """
    Build a reverse map of {target_id: [SCPPolicy, ...]} by iterating
    all SCPs and their targets.

    Raises ClientError on an access-denied error rather than silently dropping
    the policy from the audit — an incomplete audit that looks complete is worse
    than a loud failure.
    """
    policies = list_scps()
    result: dict[str, list[SCPPolicy]] = {}
    for policy in policies:
        try:
            targets = list_targets(policy.id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code", "") in _ACCESS_DENIED_CODES:
                raise
            continue
        for target in targets:
            result.setdefault(target.target_id, []).append(policy)
    return result
