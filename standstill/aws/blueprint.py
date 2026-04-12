from __future__ import annotations

import os
import time
from dataclasses import dataclass, field
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from standstill import state as _state
from standstill.models.blueprint_config import Blueprint, BlueprintStack

_TERMINAL_SUCCESS = {"CREATE_COMPLETE", "UPDATE_COMPLETE"}
_TERMINAL_FAILURE = {
    "CREATE_FAILED",
    "UPDATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_FAILED",
}
_TERMINAL_ALL = _TERMINAL_SUCCESS | _TERMINAL_FAILURE


@dataclass
class StackResult:
    stack_name: str
    action: str       # "created" | "updated" | "skipped" | "dry-run" | "failed"
    status: str = ""
    error: str = ""


# ---------------------------------------------------------------------------
# Cross-account session
# ---------------------------------------------------------------------------

def assume_account_session(account_id: str, role_name: str, region: str) -> boto3.Session:
    """
    Assume the CT execution role in a member account and return a boto3 Session.
    Mirrors the pattern in config_recorder._account_config_client.

    Raises RuntimeError with a hint to run 'accounts check-roles' if the role
    cannot be assumed.
    """
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = _state.state.get_client("sts")
    try:
        resp = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName=f"standstill-bp-{os.getpid()}",
        )
    except ClientError as e:
        raise RuntimeError(
            f"Cannot assume {role_arn}: {e.response['Error']['Message']}\n"
            "Hint: run 'standstill accounts check-roles' to verify role availability."
        ) from e
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


# ---------------------------------------------------------------------------
# Template loading
# ---------------------------------------------------------------------------

def load_template_body(stack: BlueprintStack, blueprint_path: Path) -> str:
    """Return the CloudFormation template body string for a stack."""
    if stack.template is not None:
        return stack.template
    return (blueprint_path.parent / stack.template_file).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# CloudFormation operations
# ---------------------------------------------------------------------------

def get_stack_status(cfn_client, stack_name: str) -> str | None:
    """
    Return the current stack status, or None if the stack does not exist.
    Handles the ValidationError CloudFormation raises for non-existent stacks.
    """
    try:
        resp = cfn_client.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        return stacks[0]["StackStatus"] if stacks else None
    except ClientError as e:
        if e.response["Error"]["Code"] == "ValidationError":
            return None
        raise


def deploy_stack(
    cfn_client,
    stack_name: str,
    template_body: str,
    parameters: dict[str, str],
    capabilities: list[str],
    tags: dict[str, str],
    termination_protection: bool = True,
) -> dict:
    """
    Create or update a CloudFormation stack. Returns immediately without polling.

    Returns {"action": "created"|"updated"|"skipped", "stack_name": stack_name}.

    - "created" — stack did not exist; create_stack submitted.
    - "updated" — stack existed in CREATE_COMPLETE; update_stack submitted.
    - "skipped" — stack existed and template/parameters are identical (no-op).

    Raises RuntimeError if the stack is in a failure or transitional state.
    """
    cfn_params = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    cfn_tags = [{"Key": k, "Value": v} for k, v in tags.items()]
    kwargs: dict = dict(
        StackName=stack_name,
        TemplateBody=template_body,
        Parameters=cfn_params,
        Capabilities=capabilities,
        Tags=cfn_tags,
    )

    current = get_stack_status(cfn_client, stack_name)

    if current is None:
        cfn_client.create_stack(
            **kwargs,
            EnableTerminationProtection=termination_protection,
        )
        return {"action": "created", "stack_name": stack_name}

    if current == "CREATE_COMPLETE":
        try:
            cfn_client.update_stack(**kwargs)
            return {"action": "updated", "stack_name": stack_name}
        except ClientError as e:
            if (
                e.response["Error"]["Code"] == "ValidationError"
                and "No updates are to be performed" in e.response["Error"]["Message"]
            ):
                return {"action": "skipped", "stack_name": stack_name}
            raise

    if current in _TERMINAL_FAILURE:
        raise RuntimeError(
            f"Stack '{stack_name}' is in status {current} and cannot be updated. "
            "Manual remediation is required before re-applying this blueprint."
        )

    raise RuntimeError(
        f"Stack '{stack_name}' is currently in status {current}. "
        "Wait for it to reach a stable state before applying."
    )


def poll_stack(
    cfn_client,
    stack_name: str,
    timeout: int = 600,
    poll_interval: int = 10,
) -> dict:
    """
    Poll until the stack reaches a terminal status. Returns the stack dict.

    Raises RuntimeError  — stack landed in a failure status.
    Raises TimeoutError  — not complete within `timeout` seconds.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        status = get_stack_status(cfn_client, stack_name)
        if status is None:
            raise RuntimeError(f"Stack '{stack_name}' disappeared during polling.")
        if status in _TERMINAL_SUCCESS:
            resp = cfn_client.describe_stacks(StackName=stack_name)
            return resp["Stacks"][0]
        if status in _TERMINAL_FAILURE:
            raise RuntimeError(
                f"Stack '{stack_name}' reached failure status: {status}. "
                "Check CloudFormation events in the target account for details."
            )
        time.sleep(poll_interval)

    last = get_stack_status(cfn_client, stack_name)
    raise TimeoutError(
        f"Stack '{stack_name}' did not complete within {timeout}s "
        f"(last status: {last})."
    )


# ---------------------------------------------------------------------------
# High-level orchestration
# ---------------------------------------------------------------------------

def apply_blueprint_to_account(
    blueprint: Blueprint,
    blueprint_path: Path,
    account_id: str,
    role_name: str,
    region: str,
    param_overrides: dict[str, str],
    dry_run: bool = False,
    stack_timeout: int = 600,
) -> list[StackResult]:
    """
    Deploy all stacks in a blueprint to a single account.

    param_overrides are merged on top of each stack's parameters dict so CLI
    --param flags always win: {**stack.parameters, **param_overrides}.

    In dry-run mode the account role is never assumed and no AWS calls are made.
    Returns a StackResult for every stack in the blueprint.
    """
    if not dry_run:
        try:
            session = assume_account_session(account_id, role_name, region)
        except RuntimeError as e:
            return [
                StackResult(stack_name=s.stack_name, action="failed", error=str(e))
                for s in blueprint.stacks
            ]

    results: list[StackResult] = []
    for stack in blueprint.stacks:
        effective_region = stack.region or region
        merged_params = {**stack.parameters, **param_overrides}

        if dry_run:
            results.append(StackResult(stack_name=stack.stack_name, action="dry-run"))
            continue

        cfn = session.client("cloudformation", region_name=effective_region)
        try:
            template_body = load_template_body(stack, blueprint_path)
            deploy_result = deploy_stack(
                cfn_client=cfn,
                stack_name=stack.stack_name,
                template_body=template_body,
                parameters=merged_params,
                capabilities=stack.capabilities,
                tags=stack.tags,
                termination_protection=stack.termination_protection,
            )
            if deploy_result["action"] == "skipped":
                results.append(StackResult(
                    stack_name=stack.stack_name,
                    action="skipped",
                    status="CREATE_COMPLETE",
                ))
            else:
                polled = poll_stack(cfn, stack.stack_name, timeout=stack_timeout)
                results.append(StackResult(
                    stack_name=stack.stack_name,
                    action=deploy_result["action"],
                    status=polled.get("StackStatus", ""),
                ))
        except (RuntimeError, TimeoutError, ClientError) as e:
            results.append(StackResult(
                stack_name=stack.stack_name,
                action="failed",
                error=str(e),
            ))

    return results
