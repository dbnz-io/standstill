"""Tests for standstill/aws/sso.py and standstill/commands/sso.py"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

import standstill.aws.sso as sso_mod
from standstill import state as _state
from standstill.aws.sso import AccountAssignment, PermissionSet, SSOInstance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

runner = CliRunner()


def _client_error(code, message="Some error"):
    response = {"Error": {"Code": code, "Message": message}}
    return ClientError(response, "TestOp")


def _make_instance():
    return {
        "InstanceArn": "arn:aws:sso:::instance/ssoins-test",
        "IdentityStoreId": "d-test12345",
        "Name": "TestInstance",
    }


def _make_ps_arn(n=1):
    return f"arn:aws:sso:::permissionSet/ssoins-test/ps-test{n:03d}"


# ---------------------------------------------------------------------------
# get_instance
# ---------------------------------------------------------------------------

class TestGetInstance:
    def test_returns_instance(self):
        mock_client = MagicMock()
        mock_client.list_instances.return_value = {"Instances": [_make_instance()]}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.get_instance()
        assert result is not None
        assert result.identity_store_id == "d-test12345"

    def test_returns_none_when_empty(self):
        mock_client = MagicMock()
        mock_client.list_instances.return_value = {"Instances": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.get_instance()
        assert result is None

    def test_returns_none_on_error(self):
        mock_client = MagicMock()
        mock_client.list_instances.side_effect = _client_error("AccessDeniedException")
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.get_instance()
        assert result is None


# ---------------------------------------------------------------------------
# list_permission_sets
# ---------------------------------------------------------------------------

class TestListPermissionSets:
    def test_returns_permission_sets(self):
        mock_client = MagicMock()
        mock_client.list_permission_sets.return_value = {
            "PermissionSets": [_make_ps_arn(1), _make_ps_arn(2)]
        }
        mock_client.describe_permission_set.return_value = {
            "PermissionSet": {
                "PermissionSetArn": _make_ps_arn(1),
                "Name": "TestPS",
                "Description": "Test",
                "SessionDuration": "PT1H",
                "CreatedDate": None,
            }
        }
        mock_client.list_managed_policies_in_permission_set.return_value = {"AttachedManagedPolicies": []}
        mock_client.get_inline_policy_for_permission_set.return_value = {"InlinePolicy": ""}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.list_permission_sets("arn:aws:sso:::instance/ssoins-test")
        assert len(result) == 2

    def test_empty_list(self):
        mock_client = MagicMock()
        mock_client.list_permission_sets.return_value = {"PermissionSets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.list_permission_sets("arn:aws:sso:::instance/test")
        assert result == []

    def test_pagination(self):
        mock_client = MagicMock()
        mock_client.list_permission_sets.side_effect = [
            {"PermissionSets": [_make_ps_arn(1)], "NextToken": "tok"},
            {"PermissionSets": [_make_ps_arn(2)]},
        ]
        mock_client.describe_permission_set.return_value = {
            "PermissionSet": {
                "PermissionSetArn": _make_ps_arn(1),
                "Name": "PS",
                "Description": "",
                "SessionDuration": "PT1H",
            }
        }
        mock_client.list_managed_policies_in_permission_set.return_value = {"AttachedManagedPolicies": []}
        mock_client.get_inline_policy_for_permission_set.return_value = {"InlinePolicy": ""}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.list_permission_sets("arn:aws:sso:::instance/test")
        assert len(result) == 2

    def test_includes_managed_policies(self):
        mock_client = MagicMock()
        ps_arn = _make_ps_arn(1)
        mock_client.list_permission_sets.return_value = {"PermissionSets": [ps_arn]}
        mock_client.describe_permission_set.return_value = {
            "PermissionSet": {
                "PermissionSetArn": ps_arn,
                "Name": "AdminPS",
                "Description": "",
                "SessionDuration": "PT8H",
            }
        }
        mock_client.list_managed_policies_in_permission_set.return_value = {
            "AttachedManagedPolicies": [
                {"Arn": "arn:aws:iam::aws:policy/AdministratorAccess", "Name": "AdministratorAccess"}
            ]
        }
        mock_client.get_inline_policy_for_permission_set.return_value = {"InlinePolicy": ""}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.list_permission_sets("arn:aws:sso:::instance/test")
        assert len(result[0].managed_policies) == 1


# ---------------------------------------------------------------------------
# resolve_principal_name
# ---------------------------------------------------------------------------

class TestResolvePrincipalName:
    def test_resolves_user(self):
        mock_client = MagicMock()
        mock_client.describe_user.return_value = {"DisplayName": "John Doe", "UserName": "john"}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            name = sso_mod.resolve_principal_name("d-test", "user-id-123", "USER")
        assert name == "John Doe"

    def test_resolves_group(self):
        mock_client = MagicMock()
        mock_client.describe_group.return_value = {"DisplayName": "Admins", "GroupName": "admins"}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            name = sso_mod.resolve_principal_name("d-test", "group-id-123", "GROUP")
        assert name == "Admins"

    def test_returns_id_on_error(self):
        mock_client = MagicMock()
        mock_client.describe_user.side_effect = _client_error("ResourceNotFoundException")
        with patch.object(_state.state, "get_client", return_value=mock_client):
            name = sso_mod.resolve_principal_name("d-test", "user-123", "USER")
        assert name == "user-123"


# ---------------------------------------------------------------------------
# create_assignment / delete_assignment
# ---------------------------------------------------------------------------

class TestCreateDeleteAssignment:
    def test_create_returns_request_id(self):
        mock_client = MagicMock()
        mock_client.create_account_assignment.return_value = {
            "AccountAssignmentCreationStatus": {
                "RequestId": "req-123",
                "Status": "IN_PROGRESS",
            }
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.create_assignment(
                "arn:aws:sso:::instance/test",
                "123456789012",
                _make_ps_arn(1),
                "USER",
                "user-id",
            )
        assert result["RequestId"] == "req-123"

    def test_delete_returns_request_id(self):
        mock_client = MagicMock()
        mock_client.delete_account_assignment.return_value = {
            "AccountAssignmentDeletionStatus": {
                "RequestId": "req-456",
                "Status": "IN_PROGRESS",
            }
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.delete_assignment(
                "arn:aws:sso:::instance/test",
                "123456789012",
                _make_ps_arn(1),
                "GROUP",
                "group-id",
            )
        assert result["RequestId"] == "req-456"

    def test_create_calls_correct_api(self):
        mock_client = MagicMock()
        mock_client.create_account_assignment.return_value = {
            "AccountAssignmentCreationStatus": {"RequestId": "r", "Status": "IN_PROGRESS"}
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            sso_mod.create_assignment("arn", "acct-id", "ps-arn", "USER", "uid")
        call_kwargs = mock_client.create_account_assignment.call_args[1]
        assert call_kwargs["TargetType"] == "AWS_ACCOUNT"
        assert call_kwargs["PrincipalType"] == "USER"


# ---------------------------------------------------------------------------
# list_all_assignments
# ---------------------------------------------------------------------------

class TestListAllAssignments:
    def test_returns_assignments(self):
        mock_client = MagicMock()
        mock_client.list_accounts_for_provisioned_permission_set.return_value = {
            "AccountIds": ["123456789012"]
        }
        mock_client.list_account_assignments.return_value = {
            "AccountAssignments": [
                {
                    "AccountId": "123456789012",
                    "PermissionSetArn": _make_ps_arn(1),
                    "PrincipalId": "user-id",
                    "PrincipalType": "USER",
                }
            ]
        }
        mock_id_client = MagicMock()
        mock_id_client.describe_user.return_value = {"DisplayName": "Alice", "UserName": "alice"}

        def mock_get_client(service, **kwargs):
            if service == "identitystore":
                return mock_id_client
            return mock_client

        ps = PermissionSet(
            arn=_make_ps_arn(1),
            name="AdminPS",
            description="",
            session_duration="PT1H",
            created_date=None,
        )
        with patch.object(_state.state, "get_client", side_effect=mock_get_client):
            result = sso_mod.list_all_assignments(
                "arn:aws:sso:::instance/test",
                "d-test",
                [ps],
                {"123456789012": "TestAccount"},
            )
        assert len(result) == 1
        assert result[0].account_name == "TestAccount"

    def test_empty_when_no_accounts(self):
        mock_client = MagicMock()
        mock_client.list_accounts_for_provisioned_permission_set.return_value = {"AccountIds": []}
        ps = PermissionSet(arn=_make_ps_arn(1), name="PS", description="", session_duration="PT1H", created_date=None)
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = sso_mod.list_all_assignments("arn", "d-test", [ps], {})
        assert result == []


# ---------------------------------------------------------------------------
# Command tests
# ---------------------------------------------------------------------------

class TestSsoCommands:
    def test_status_no_instance(self):
        from standstill.commands.sso import app as sso_app

        mock_client = MagicMock()
        mock_client.list_instances.return_value = {"Instances": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(sso_app, ["status"])
        # Should exit gracefully when no instance
        assert result.exit_code == 0

    def test_list_permission_sets_no_instance(self):
        from standstill.commands.sso import app as sso_app

        mock_client = MagicMock()
        mock_client.list_instances.return_value = {"Instances": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(sso_app, ["list-permission-sets"])
        assert result.exit_code == 1

    def test_list_assignments_no_instance(self):
        from standstill.commands.sso import app as sso_app

        mock_client = MagicMock()
        mock_client.list_instances.return_value = {"Instances": []}

        # build_ou_tree will also be called but fails gracefully
        with patch.object(_state.state, "get_client", return_value=mock_client):
            with patch("standstill.aws.organizations.build_ou_tree", side_effect=Exception("no org")):
                result = runner.invoke(sso_app, ["list-assignments"])
        assert result.exit_code == 1
