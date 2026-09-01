"""Tests for standstill/aws/scp.py and standstill/commands/scp.py"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

import standstill.aws.scp as scp_mod
from standstill import state as _state

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

runner = CliRunner()


def _client_error(code, message="Some error"):
    response = {"Error": {"Code": code, "Message": message}}
    return ClientError(response, "TestOp")


def _make_policy_raw(pid="p-abc123", name="TestSCP", aws_managed=False):
    return {
        "Id": pid,
        "Arn": f"arn:aws:organizations::aws:policy/service_control_policy/{pid}",
        "Name": name,
        "Description": "Test SCP",
        "AwsManaged": aws_managed,
    }


# ---------------------------------------------------------------------------
# list_scps
# ---------------------------------------------------------------------------

class TestListScps:
    def test_returns_all_policies(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001", "SCP1"), _make_policy_raw("p-002", "SCP2")],
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.list_scps()
        assert len(result) == 2
        assert result[0].id == "p-001"
        assert result[1].name == "SCP2"

    def test_empty_list(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {"Policies": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.list_scps()
        assert result == []

    def test_pagination(self):
        mock_client = MagicMock()
        mock_client.list_policies.side_effect = [
            {"Policies": [_make_policy_raw("p-001")], "NextToken": "tok1"},
            {"Policies": [_make_policy_raw("p-002")], "NextToken": None},
        ]
        # Fix: side_effect with None NextToken won't be in resp
        mock_client.list_policies.side_effect = [
            {"Policies": [_make_policy_raw("p-001")], "NextToken": "tok1"},
            {"Policies": [_make_policy_raw("p-002")]},
        ]
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.list_scps()
        assert len(result) == 2
        assert mock_client.list_policies.call_count == 2

    def test_includes_aws_managed(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-full", "FullAWSAccess", aws_managed=True)]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.list_scps()
        assert result[0].aws_managed is True


# ---------------------------------------------------------------------------
# describe_scp
# ---------------------------------------------------------------------------

class TestDescribeScp:
    def test_returns_policy_and_content(self):
        mock_client = MagicMock()
        mock_client.describe_policy.return_value = {
            "Policy": {
                **_make_policy_raw("p-abc"),
                "Content": '{"Version": "2012-10-17", "Statement": []}',
                "PolicySummary": _make_policy_raw("p-abc"),
            }
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            policy, content = scp_mod.describe_scp("p-abc")
        assert policy.id == "p-abc"
        assert "Statement" in content

    def test_raises_client_error(self):
        mock_client = MagicMock()
        mock_client.describe_policy.side_effect = _client_error("NoSuchPolicyException")
        with patch.object(_state.state, "get_client", return_value=mock_client):
            with pytest.raises(ClientError):
                scp_mod.describe_scp("p-notexist")


# ---------------------------------------------------------------------------
# list_targets
# ---------------------------------------------------------------------------

class TestListTargets:
    def test_returns_targets(self):
        mock_client = MagicMock()
        mock_client.list_targets_for_policy.return_value = {
            "Targets": [
                {"TargetId": "ou-abc-123", "Arn": "arn:...", "Name": "TestOU", "Type": "ORGANIZATIONAL_UNIT"},
                {"TargetId": "123456789012", "Arn": "arn:...", "Name": "TestAcct", "Type": "ACCOUNT"},
            ]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            targets = scp_mod.list_targets("p-abc")
        assert len(targets) == 2
        assert targets[0].type == "ORGANIZATIONAL_UNIT"

    def test_empty_targets(self):
        mock_client = MagicMock()
        mock_client.list_targets_for_policy.return_value = {"Targets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            targets = scp_mod.list_targets("p-abc")
        assert targets == []

    def test_pagination(self):
        mock_client = MagicMock()
        mock_client.list_targets_for_policy.side_effect = [
            {"Targets": [{"TargetId": "ou-1", "Arn": "", "Name": "OU1", "Type": "ORGANIZATIONAL_UNIT"}], "NextToken": "tok"},
            {"Targets": [{"TargetId": "ou-2", "Arn": "", "Name": "OU2", "Type": "ORGANIZATIONAL_UNIT"}]},
        ]
        with patch.object(_state.state, "get_client", return_value=mock_client):
            targets = scp_mod.list_targets("p-abc")
        assert len(targets) == 2


# ---------------------------------------------------------------------------
# attach_scp / detach_scp
# ---------------------------------------------------------------------------

class TestAttachDetachScp:
    def test_attach_calls_api(self):
        mock_client = MagicMock()
        with patch.object(_state.state, "get_client", return_value=mock_client):
            scp_mod.attach_scp("p-abc", "ou-test-123")
        mock_client.attach_policy.assert_called_once_with(PolicyId="p-abc", TargetId="ou-test-123")

    def test_detach_calls_api(self):
        mock_client = MagicMock()
        with patch.object(_state.state, "get_client", return_value=mock_client):
            scp_mod.detach_scp("p-abc", "ou-test-123")
        mock_client.detach_policy.assert_called_once_with(PolicyId="p-abc", TargetId="ou-test-123")


# ---------------------------------------------------------------------------
# create_scp / delete_scp
# ---------------------------------------------------------------------------

class TestCreateDeleteScp:
    def test_create_returns_policy(self):
        mock_client = MagicMock()
        mock_client.create_policy.return_value = {
            "Policy": {
                **_make_policy_raw("p-new", "NewSCP"),
                "PolicySummary": _make_policy_raw("p-new", "NewSCP"),
            }
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            policy = scp_mod.create_scp("NewSCP", "desc", '{"Statement": []}')
        assert policy.name == "NewSCP"
        mock_client.create_policy.assert_called_once()

    def test_delete_calls_api(self):
        mock_client = MagicMock()
        with patch.object(_state.state, "get_client", return_value=mock_client):
            scp_mod.delete_scp("p-abc")
        mock_client.delete_policy.assert_called_once_with(PolicyId="p-abc")

    def test_create_with_type_service_control_policy(self):
        mock_client = MagicMock()
        mock_client.create_policy.return_value = {
            "Policy": {**_make_policy_raw("p-x"), "PolicySummary": _make_policy_raw("p-x")}
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            scp_mod.create_scp("X", "desc", '{}')
        call_kwargs = mock_client.create_policy.call_args[1]
        assert call_kwargs.get("Type") == "SERVICE_CONTROL_POLICY"


# ---------------------------------------------------------------------------
# find_scp
# ---------------------------------------------------------------------------

class TestFindScp:
    def test_find_by_id_prefix(self):
        mock_client = MagicMock()
        mock_client.describe_policy.return_value = {
            "Policy": {**_make_policy_raw("p-abc"), "PolicySummary": _make_policy_raw("p-abc")}
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.find_scp("p-abc")
        assert result is not None
        assert result.id == "p-abc"

    def test_find_by_name(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-123", "MySCP")]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.find_scp("MySCP")
        assert result is not None
        assert result.id == "p-123"

    def test_find_by_name_not_found(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {"Policies": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.find_scp("NonExistent")
        assert result is None

    def test_find_by_id_not_found(self):
        mock_client = MagicMock()
        mock_client.describe_policy.side_effect = _client_error("NoSuchPolicyException")
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.find_scp("p-notexist")
        assert result is None


# ---------------------------------------------------------------------------
# build_target_scp_map
# ---------------------------------------------------------------------------

class TestBuildTargetScpMap:
    def test_builds_map(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001", "SCP1")]
        }
        mock_client.list_targets_for_policy.return_value = {
            "Targets": [
                {"TargetId": "ou-abc", "Arn": "", "Name": "OU1", "Type": "ORGANIZATIONAL_UNIT"}
            ]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.build_target_scp_map()
        assert "ou-abc" in result
        assert len(result["ou-abc"]) == 1
        assert result["ou-abc"][0].id == "p-001"

    def test_empty_when_no_scps(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {"Policies": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.build_target_scp_map()
        assert result == {}

    def test_skips_policy_on_benign_error(self):
        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001")]
        }
        # A non-permission error (e.g. a policy in a transient state) is skipped.
        mock_client.list_targets_for_policy.side_effect = _client_error("ServiceException")
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = scp_mod.build_target_scp_map()
        assert result == {}

    def test_raises_on_access_denied(self):
        import pytest
        from botocore.exceptions import ClientError

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001")]
        }
        # Access-denied must NOT be swallowed — a partial audit that looks
        # complete is worse than a loud failure.
        mock_client.list_targets_for_policy.side_effect = _client_error("AccessDeniedException")
        with patch.object(_state.state, "get_client", return_value=mock_client):
            with pytest.raises(ClientError):
                scp_mod.build_target_scp_map()


# ---------------------------------------------------------------------------
# Command tests
# ---------------------------------------------------------------------------

class TestScpCommands:
    def test_list_command(self):
        from standstill.commands.scp import app as scp_app

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001", "SCP1")]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(scp_app, ["list"])
        assert result.exit_code == 0

    def test_show_not_found(self):
        from standstill.commands.scp import app as scp_app

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {"Policies": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(scp_app, ["show", "--name", "NonExistent"])
        assert result.exit_code == 1

    def test_show_found(self):
        from standstill.commands.scp import app as scp_app

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001", "MySCP")]
        }
        mock_client.describe_policy.return_value = {
            "Policy": {
                **_make_policy_raw("p-001", "MySCP"),
                "Content": '{"Statement": []}',
                "PolicySummary": _make_policy_raw("p-001", "MySCP"),
            }
        }
        mock_client.list_targets_for_policy.return_value = {"Targets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(scp_app, ["show", "--name", "MySCP"])
        assert result.exit_code == 0

    def test_attach_with_yes_flag(self):
        from standstill.commands.scp import app as scp_app

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001", "MySCP")]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(scp_app, ["attach", "--name", "MySCP", "--target", "ou-abc", "--yes"])
        assert result.exit_code == 0
        mock_client.attach_policy.assert_called_once()

    def test_detach_not_found(self):
        from standstill.commands.scp import app as scp_app

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {"Policies": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(scp_app, ["detach", "--name", "NoSCP", "--target", "ou-abc", "--yes"])
        assert result.exit_code == 1

    def test_delete_with_yes_flag(self):
        from standstill.commands.scp import app as scp_app

        mock_client = MagicMock()
        mock_client.list_policies.return_value = {
            "Policies": [_make_policy_raw("p-001", "MySCP")]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(scp_app, ["delete", "--name", "MySCP", "--yes"])
        assert result.exit_code == 0
        mock_client.delete_policy.assert_called_once()
