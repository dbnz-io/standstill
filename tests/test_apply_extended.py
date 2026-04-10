"""Extended tests for commands/apply.py and aws/controltower.py poll/fetch paths."""
from __future__ import annotations

import time
from unittest.mock import MagicMock, patch, call

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

import standstill.aws.controltower as ct_api
from standstill.aws.controltower import (
    Control,
    EnabledControl,
    SessionExpiredError,
    _extract_service,
    _resolve_ct_arn,
    poll_operation,
)
from standstill.aws.organizations import OUNode
from standstill.aws.session import check_ct_permissions, check_all_account_roles, get_caller_identity
from standstill.aws.organizations import Account
from standstill.main import app

runner = CliRunner()


def _make_ou(ou_id="ou-ab12-34cd5678"):
    return OUNode(
        id=ou_id,
        arn=f"arn:aws:organizations:::ou/o-1/{ou_id}",
        name="TestOU",
        parent_id=None,
    )


def _make_control(behavior="DETECTIVE"):
    arn = "arn:aws:controltower:us-east-1::control/AWS-GR_TEST"
    return {arn: Control(arn=arn, full_name="Test", description="", behavior=behavior, severity="HIGH")}


# ---------------------------------------------------------------------------
# controltower — _resolve_ct_arn / _extract_service
# ---------------------------------------------------------------------------

class TestInternalHelpers:
    def test_resolve_ct_alias(self):
        arn = _resolve_ct_arn(["CT.S3.PR.1", "OTHER"], "arn:fallback", "us-east-1")
        assert "CT.S3.PR.1" in arn
        assert "us-east-1" in arn

    def test_resolve_gr_alias(self):
        arn = _resolve_ct_arn(["AWS-GR_ENCRYPTED_VOLUMES"], "arn:fallback", "us-east-1")
        assert "AWS-GR_ENCRYPTED_VOLUMES" in arn

    def test_resolve_fallback(self):
        arn = _resolve_ct_arn(["UNRELATED"], "arn:fallback", "us-east-1")
        assert arn == "arn:fallback"

    def test_extract_service_ct_format(self):
        assert _extract_service(["CT.S3.PR.1"]) == "S3"
        assert _extract_service(["CT.IAM.PR.1"]) == "IAM"
        assert _extract_service(["CT.CLOUDTRAIL.PR.1"]) == "CloudTrail"
        assert _extract_service(["CT.GUARDDUTY.PR.1"]) == "GuardDuty"
        assert _extract_service(["CT.LAMBDA.PR.1"]) == "Lambda"

    def test_extract_service_gr_alias_returns_none(self):
        assert _extract_service(["AWS-GR_ENCRYPTED_VOLUMES"]) is None

    def test_extract_service_empty(self):
        assert _extract_service([]) is None

    def test_extract_service_short_alias(self):
        # Only one part after CT. — shouldn't crash
        result = _extract_service(["CT.X"])
        assert result is not None or result is None  # no crash


# ---------------------------------------------------------------------------
# controltower — fetch_controls_from_api
# ---------------------------------------------------------------------------

class TestFetchControlsFromApi:
    def test_fetch_returns_controls(self):
        mock_cc = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{
            "Controls": [{
                "Arn": "arn:aws:controlcatalog:::control/abc",
                "Aliases": ["CT.S3.PR.1"],
                "Name": "S3 Preventive",
                "Description": "Prevents bad S3 things",
                "Behavior": "PREVENTIVE",
                "Severity": "HIGH",
                "Implementation": {"Type": "SERVICE_CONTROL_POLICY"},
            }]
        }]
        mock_cc.get_paginator.return_value = mock_paginator
        with patch.object(ct_api._state.state, "get_client", return_value=mock_cc):
            controls = ct_api.fetch_controls_from_api("us-east-1")
        assert len(controls) == 1
        assert "CT.S3.PR.1" in controls[0]["arn"]
        assert controls[0]["service"] == "S3"

    def test_fetch_with_gr_alias(self):
        mock_cc = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{
            "Controls": [{
                "Arn": "arn:aws:controlcatalog:::control/xyz",
                "Aliases": ["AWS-GR_ENCRYPTED_VOLUMES"],
                "Name": "Encrypted Volumes",
                "Description": "Detective control",
                "Behavior": "DETECTIVE",
                "Severity": "MEDIUM",
                "Implementation": {"Type": "AWS::Config::ManagedRule"},
            }]
        }]
        mock_cc.get_paginator.return_value = mock_paginator
        with patch.object(ct_api._state.state, "get_client", return_value=mock_cc):
            controls = ct_api.fetch_controls_from_api("us-east-1")
        assert "AWS-GR_ENCRYPTED_VOLUMES" in controls[0]["arn"]


# ---------------------------------------------------------------------------
# controltower — fetch_common_control_mapping
# ---------------------------------------------------------------------------

class TestFetchCommonControlMapping:
    def test_empty_common_controls(self):
        mock_cc = MagicMock()
        cc_pag = MagicMock()
        cc_pag.paginate.return_value = [{"CommonControls": []}]
        mock_cc.get_paginator.return_value = cc_pag
        with patch.object(ct_api._state.state, "get_client", return_value=mock_cc):
            result = ct_api.fetch_common_control_mapping("us-east-1")
        assert result == {}

    def test_maps_controls_to_common_controls(self):
        mock_cc = MagicMock()

        def get_pag(name):
            if name == "list_common_controls":
                p = MagicMock()
                p.paginate.return_value = [{
                    "CommonControls": [{
                        "Name": "Data Encryption",
                        "Objective": {"Arn": "arn:obj/1"},
                    }]
                }]
                return p
            else:  # list_controls
                p = MagicMock()
                p.paginate.return_value = [{
                    "Controls": [{
                        "Arn": "arn:aws:controlcatalog:::control/abc",
                        "Aliases": ["CT.S3.PR.1"],
                    }]
                }]
                return p

        mock_cc.get_paginator.side_effect = get_pag
        with patch.object(ct_api._state.state, "get_client", return_value=mock_cc):
            result = ct_api.fetch_common_control_mapping("us-east-1")
        assert any("Data Encryption" in v for v in result.values())

    def test_skips_failed_objectives(self):
        mock_cc = MagicMock()

        def get_pag(name):
            if name == "list_common_controls":
                p = MagicMock()
                p.paginate.return_value = [{
                    "CommonControls": [{"Name": "CC1", "Objective": {"Arn": "arn:obj/fail"}}]
                }]
                return p
            else:
                p = MagicMock()
                p.paginate.side_effect = ClientError(
                    {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
                    "ListControls"
                )
                return p

        mock_cc.get_paginator.side_effect = get_pag
        with patch.object(ct_api._state.state, "get_client", return_value=mock_cc):
            result = ct_api.fetch_common_control_mapping("us-east-1")
        assert result == {}


# ---------------------------------------------------------------------------
# controltower — poll_operation
# ---------------------------------------------------------------------------

class TestPollOperation:
    def test_succeeds_first_poll(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.return_value = {
            "controlOperation": {"status": "SUCCEEDED", "statusMessage": "done"}
        }
        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
        ):
            result = poll_operation("op-1", timeout=60, poll_interval=1)
        assert result["status"] == "SUCCEEDED"

    def test_polls_until_succeeded(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.side_effect = [
            {"controlOperation": {"status": "IN_PROGRESS"}},
            {"controlOperation": {"status": "IN_PROGRESS"}},
            {"controlOperation": {"status": "SUCCEEDED"}},
        ]
        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
        ):
            result = poll_operation("op-2", timeout=60, poll_interval=1)
        assert result["status"] == "SUCCEEDED"

    def test_failed_terminal_status(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.return_value = {
            "controlOperation": {"status": "FAILED", "statusMessage": "error occurred"}
        }
        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
        ):
            result = poll_operation("op-3", timeout=60, poll_interval=1)
        assert result["status"] == "FAILED"

    def test_throttle_retries(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.side_effect = [
            ClientError({"Error": {"Code": "ThrottlingException", "Message": "throttled"}}, "op"),
            {"controlOperation": {"status": "SUCCEEDED"}},
        ]
        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
        ):
            result = poll_operation("op-4", timeout=60, poll_interval=1)
        assert result["status"] == "SUCCEEDED"

    def test_session_expired_raises(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.side_effect = ClientError(
            {"Error": {"Code": "ExpiredTokenException", "Message": "token expired"}},
            "GetControlOperation"
        )
        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
            patch.object(ct_api._state.state, "reset"),
        ):
            with pytest.raises(SessionExpiredError) as exc_info:
                poll_operation("op-5", timeout=60, poll_interval=1)
        assert exc_info.value.operation_id == "op-5"

    def test_session_expired_retry_succeeds(self):
        """First call raises ExpiredToken, retry after reset succeeds."""
        mock_ct = MagicMock()
        mock_ct2 = MagicMock()
        mock_ct2.get_control_operation.return_value = {
            "controlOperation": {"status": "SUCCEEDED"}
        }

        call_count = {"n": 0}
        def get_client_side_effect(service):
            call_count["n"] += 1
            if call_count["n"] == 1:
                c = MagicMock()
                c.get_control_operation.side_effect = ClientError(
                    {"Error": {"Code": "ExpiredTokenException", "Message": "expired"}},
                    "GetControlOperation"
                )
                return c
            return mock_ct2

        with (
            patch.object(ct_api._state.state, "get_client", side_effect=get_client_side_effect),
            patch.object(ct_api._state.state, "reset"),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
        ):
            result = poll_operation("op-6", timeout=60, poll_interval=1)
        assert result["status"] == "SUCCEEDED"

    def test_timeout_raises(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.return_value = {
            "controlOperation": {"status": "IN_PROGRESS"}
        }
        call_count = {"n": 0}

        def fake_monotonic():
            call_count["n"] += 1
            return call_count["n"] * 100

        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
            patch("standstill.aws.controltower.time.monotonic", fake_monotonic),
        ):
            with pytest.raises(TimeoutError):
                poll_operation("op-timeout", timeout=1, poll_interval=1)

    def test_non_throttle_client_error_raises(self):
        mock_ct = MagicMock()
        mock_ct.get_control_operation.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "GetControlOperation"
        )
        with (
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.controltower.time.sleep"),
            patch("standstill.aws.controltower.random.uniform", return_value=0),
        ):
            with pytest.raises(ClientError):
                poll_operation("op-err", timeout=60, poll_interval=1)

    def test_disable_control(self):
        mock_ct = MagicMock()
        mock_ct.disable_control.return_value = {"operationIdentifier": "op-dis-1"}
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            op_id = ct_api.disable_control("arn:...", "arn:ou")
        assert op_id == "op-dis-1"

    def test_session_expired_error_message(self):
        err = SessionExpiredError("op-xyz")
        assert "op-xyz" in str(err)
        assert err.operation_id == "op-xyz"


# ---------------------------------------------------------------------------
# aws/session.py — get_caller_identity errors
# ---------------------------------------------------------------------------

class TestSessionErrors:
    def test_get_caller_identity_no_credentials(self):
        from botocore.exceptions import NoCredentialsError
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = NoCredentialsError()
        import standstill.aws.session as session_module
        with patch.object(session_module._state.state, "get_client", return_value=mock_sts):
            with pytest.raises(RuntimeError, match="No AWS credentials"):
                get_caller_identity()

    def test_get_caller_identity_client_error(self):
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            {"Error": {"Code": "InvalidClientTokenId", "Message": "invalid token"}},
            "GetCallerIdentity"
        )
        import standstill.aws.session as session_module
        with patch.object(session_module._state.state, "get_client", return_value=mock_sts):
            with pytest.raises(RuntimeError, match="authentication failed"):
                get_caller_identity()

    def test_check_ct_permissions_ct_denied(self):
        import standstill.aws.session as session_module
        mock_org = MagicMock()
        mock_org.describe_organization.return_value = {}
        mock_org.list_roots.return_value = {}
        mock_org.list_organizational_units_for_parent.side_effect = ClientError(
            {"Error": {"Code": "ParentNotFoundException", "Message": "nf"}}, "op"
        )
        mock_org.list_accounts_for_parent.side_effect = ClientError(
            {"Error": {"Code": "ParentNotFoundException", "Message": "nf"}}, "op"
        )
        mock_ct = MagicMock()
        mock_ct.list_landing_zones.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, "op"
        )

        def get_client(service):
            return mock_org if service == "organizations" else mock_ct

        with patch.object(session_module._state.state, "get_client", side_effect=get_client):
            result = check_ct_permissions()
        assert result["controltower:ListLandingZones"] == "AccessDeniedException"

    def test_check_all_account_roles_concurrent(self):
        import standstill.aws.session as session_module
        accounts = [
            Account(id="111111111111", arn="arn:...", name="A1", email="a@b.com",
                    status="ACTIVE", ou_id="ou-1", ou_name="OU"),
            Account(id="222222222222", arn="arn:...", name="A2", email="b@b.com",
                    status="ACTIVE", ou_id="ou-1", ou_name="OU"),
        ]
        mock_sts = MagicMock()
        mock_sts.assume_role.return_value = {"Credentials": {}}

        with patch.object(session_module._state.state, "get_client", return_value=mock_sts):
            result = check_all_account_roles(accounts, "AWSControlTowerExecution")
        assert "111111111111" in result
        assert "222222222222" in result
        assert result["111111111111"][0] is True

    def test_check_all_account_roles_failure(self):
        import standstill.aws.session as session_module
        accounts = [
            Account(id="333333333333", arn="arn:...", name="A3", email="c@b.com",
                    status="ACTIVE", ou_id="ou-1", ou_name="OU"),
        ]
        mock_sts = MagicMock()
        mock_sts.assume_role.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "denied"}}, "AssumeRole"
        )
        with patch.object(session_module._state.state, "get_client", return_value=mock_sts):
            result = check_all_account_roles(accounts, "SomeRole")
        assert result["333333333333"][0] is False


# ---------------------------------------------------------------------------
# commands/apply.py — extended paths
# ---------------------------------------------------------------------------

class TestApplyExtended:
    def test_mutually_exclusive_modes(self):
        result = runner.invoke(app, ["apply", "--enable-all", "--enable-detective", "--ou", "ou-1"])
        assert result.exit_code == 1
        assert "mutually" in result.output

    def test_concurrency_out_of_range(self):
        result = runner.invoke(app, [
            "apply", "--enable-detective", "--ou", "ou-ab12-34cd5678", "--concurrency", "0"
        ])
        assert result.exit_code == 1
        assert "concurrency" in result.output

    def test_enable_all_dry_run(self):
        ou = _make_ou()
        catalog = _make_control("DETECTIVE")
        with (
            patch("standstill.commands.apply.ct_api.load_catalog", return_value=catalog),
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
        ):
            result = runner.invoke(
                app, ["apply", "--enable-all", "--ou", "ou-ab12-34cd5678", "--dry-run"]
            )
        assert result.exit_code == 0

    def test_apply_baseline_blocked(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        f_content = f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f_content)
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (False, "No baseline enrolled")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 1
        assert "Baseline check failed" in result.output

    def test_apply_file_too_large(self, tmp_path):
        f = tmp_path / "big.yaml"
        f.write_bytes(b"x" * (10_000_001))
        result = runner.invoke(app, ["apply", "--file", str(f)])
        assert result.exit_code == 1
        assert "10 MB" in result.output

    def test_apply_ou_not_found_in_run(self):
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        # Use a valid-format OU ID that simply won't exist in the empty mocked org tree
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: ou-ab12-99zz9999\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[]),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 1
        assert "OU not found" in result.output

    def test_apply_nothing_to_enable(self):
        """Control already enabled — nothing to do."""
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        already_enabled = [EnabledControl(control_arn=ctrl_arn, ou_arn=ou.arn, status="SUCCEEDED")]
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous",
                  return_value={ou.arn: already_enabled}),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 0
        assert "Nothing to do" in result.output

    def test_apply_no_wait(self):
        """Submit operations without waiting for them to complete."""
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
            patch("standstill.commands.apply.ct_api.enable_control", return_value="op-nowait-1"),
            patch("standstill.commands.apply.ct_api.save_pending_operation"),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath, "--no-wait"])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 0
        assert "submitted" in result.output

    def test_apply_waits_and_succeeds(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
            patch("standstill.commands.apply.ct_api.enable_control", return_value="op-wait-1"),
            patch("standstill.commands.apply.ct_api.save_pending_operation"),
            patch("standstill.commands.apply.ct_api.poll_operation",
                  return_value={"status": "SUCCEEDED"}),
            patch("standstill.commands.apply.ct_api.remove_pending_operation"),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 0
        assert "successfully" in result.output

    def test_apply_poll_fails(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
            patch("standstill.commands.apply.ct_api.enable_control", return_value="op-fail-1"),
            patch("standstill.commands.apply.ct_api.save_pending_operation"),
            patch("standstill.commands.apply.ct_api.poll_operation",
                  return_value={"status": "FAILED", "statusMessage": "control conflict"}),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 1

    def test_apply_session_expired_during_poll(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
            patch("standstill.commands.apply.ct_api.enable_control", return_value="op-exp-1"),
            patch("standstill.commands.apply.ct_api.save_pending_operation"),
            patch("standstill.commands.apply.ct_api.poll_operation",
                  side_effect=SessionExpiredError("op-exp-1")),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 1
        assert "expired" in result.output.lower() or "journal" in result.output.lower()

    def test_apply_submit_client_error(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
            patch("standstill.commands.apply.ct_api.enable_control",
                  side_effect=ClientError(
                      {"Error": {"Code": "ValidationException", "Message": "invalid"}},
                      "EnableControl"
                  )),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath, "--no-wait"])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 1

    def test_apply_timeout_during_poll(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        import tempfile, pathlib
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n")
            fpath = f.name
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
            patch("standstill.commands.apply.ct_api.enable_control", return_value="op-to-1"),
            patch("standstill.commands.apply.ct_api.save_pending_operation"),
            patch("standstill.commands.apply.ct_api.poll_operation",
                  side_effect=TimeoutError("timed out")),
        ):
            result = runner.invoke(app, ["apply", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# controltower — list_enabled_for_ou ValidationException
# ---------------------------------------------------------------------------

class TestListEnabledValidationException:
    def test_validation_exception_returns_empty(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.side_effect = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "invalid target"}},
            "ListEnabledControls"
        )
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            result = ct_api.list_enabled_for_ou("arn:invalid")
        assert result == []

    def test_other_client_error_raises(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListEnabledControls"
        )
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            with pytest.raises(ClientError):
                ct_api.list_enabled_for_ou("arn:ou")

    def test_list_enabled_for_all_ous(self):
        ou1 = _make_ou("ou-1111-aaaabbbb")
        ou2 = _make_ou("ou-2222-ccccdddd")
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.return_value = {"enabledControls": []}
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            result = ct_api.list_enabled_for_all_ous([ou1, ou2])
        assert ou1.arn in result
        assert ou2.arn in result
