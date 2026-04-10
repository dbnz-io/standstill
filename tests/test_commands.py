"""CLI integration tests using typer.testing.CliRunner."""
from __future__ import annotations

from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws
from typer.testing import CliRunner

import standstill.aws.config_recorder as rec_module
import standstill.config as cfg_module
from standstill.aws.config_recorder import RecorderResult, RecorderState
from standstill.aws.organizations import Account, OUNode
from standstill.aws.security_services import (
    AccountAssessment,
    DelegationStatus,
    MemberServiceStatus,
    ServiceApplyResult,
    ServiceStatus,
)
from standstill.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(cfg_module, "_CONFIG_PATH", config_path)
    return config_path


@pytest.fixture
def isolated_types(tmp_path, monkeypatch):
    types_path = tmp_path / "securityhub_resource_types.yaml"
    monkeypatch.setattr(rec_module, "_USER_TYPES_PATH", types_path)
    return types_path


def _account(aid="123456789012", name="TestAcct", ou="Security"):
    return Account(id=aid, arn="arn:...", name=name, email="t@t.com",
                   status="ACTIVE", ou_id="ou-1", ou_name=ou)


def _ou(name="SecurityOU"):
    n = OUNode(id="ou-abc", arn="arn:aws:organizations:::ou/o-1/ou-abc", name=name, parent_id=None)
    n.accounts = [_account()]
    return n


# ---------------------------------------------------------------------------
# standstill check
# ---------------------------------------------------------------------------

class TestCheckCommand:
    @mock_aws
    def test_check_runs(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        result = runner.invoke(app, ["check"])
        # May exit 1 due to missing CT permissions but should not crash
        assert result.exit_code in (0, 1)
        assert "Identity" in result.output or "Error" in result.output

    @mock_aws
    def test_check_all_permissions_ok(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        with patch("standstill.commands.check.aws_session.check_ct_permissions") as mock_perms:
            mock_perms.return_value = {
                "organizations:DescribeOrganization": True,
                "organizations:ListRoots": True,
                "controltower:ListLandingZones": True,
            }
            result = runner.invoke(app, ["check"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# standstill view
# ---------------------------------------------------------------------------

class TestViewCommand:
    @mock_aws
    def test_view_ous_empty(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        result = runner.invoke(app, ["view", "ous"])
        assert result.exit_code == 0

    @mock_aws
    def test_view_accounts_empty(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        result = runner.invoke(app, ["view", "accounts"])
        assert result.exit_code == 0

    @mock_aws
    def test_view_controls(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        with patch("standstill.commands.view.ct_api.list_enabled_for_all_ous", return_value={}):
            result = runner.invoke(app, ["view", "controls"])
        assert result.exit_code == 0

    @mock_aws
    def test_view_controls_ou_not_found(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        result = runner.invoke(app, ["view", "controls", "--ou", "ou-nonexistent"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# standstill config
# ---------------------------------------------------------------------------

class TestConfigCommand:
    def test_set_profile(self, isolated_config):
        result = runner.invoke(app, ["config", "set-profile", "my-mgmt-profile"])
        assert result.exit_code == 0
        assert cfg_module.get_profile() == "my-mgmt-profile"

    def test_unset_profile(self, isolated_config):
        cfg_module.set_profile("my-mgmt-profile")
        result = runner.invoke(app, ["config", "unset-profile"])
        assert result.exit_code == 0
        assert cfg_module.get_profile() is None

    def test_show_no_profile(self, isolated_config):
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "not set" in result.output

    def test_show_with_profile(self, isolated_config):
        cfg_module.set_profile("my-mgmt-profile")
        result = runner.invoke(app, ["config", "show"])
        assert result.exit_code == 0
        assert "my-mgmt-profile" in result.output


# ---------------------------------------------------------------------------
# standstill accounts check-roles
# ---------------------------------------------------------------------------

class TestAccountsCommand:
    @mock_aws
    def test_check_roles_no_accounts(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        result = runner.invoke(app, ["accounts", "check-roles"])
        assert result.exit_code == 0
        assert "No accounts" in result.output

    @mock_aws
    def test_check_roles_with_failures(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        accounts = [_account()]
        check_results = {"123456789012": (False, "Access denied")}
        with (
            patch("standstill.commands.accounts.org_api.build_ou_tree", return_value=[_ou()]),
            patch("standstill.commands.accounts.org_api.all_accounts", return_value=accounts),
            patch("standstill.commands.accounts.aws_session.check_all_account_roles",
                  return_value=check_results),
        ):
            result = runner.invoke(app, ["accounts", "check-roles"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# standstill recorder types
# ---------------------------------------------------------------------------

class TestRecorderTypesCommand:
    def test_types_list(self, isolated_types):
        result = runner.invoke(app, ["recorder", "types", "list"])
        assert result.exit_code == 0

    def test_types_list_show_removed(self, isolated_types):
        result = runner.invoke(app, ["recorder", "types", "list", "--show-removed"])
        assert result.exit_code == 0

    def test_types_add_valid(self, isolated_types):
        result = runner.invoke(app, ["recorder", "types", "add", "AWS::XYZ::NotReal"])
        assert result.exit_code == 0
        assert "Added" in result.output

    def test_types_add_invalid(self, isolated_types):
        result = runner.invoke(app, ["recorder", "types", "add", "invalid-type"])
        assert result.exit_code == 1

    def test_types_remove_existing(self, isolated_types):
        rec_module.add_resource_type("AWS::XYZ::NotReal")
        result = runner.invoke(app, ["recorder", "types", "remove", "AWS::XYZ::NotReal"])
        assert result.exit_code == 0

    def test_types_remove_not_found(self, isolated_types):
        # "AWS::Custom::Gone" is not in the bundled list → remove should fail
        result = runner.invoke(app, ["recorder", "types", "remove", "AWS::Custom::Gone"])
        assert result.exit_code == 1

    def test_types_reset_no_override(self, isolated_types):
        result = runner.invoke(app, ["recorder", "types", "reset", "--yes"])
        assert result.exit_code == 0
        assert "bundled defaults" in result.output

    def test_types_reset_with_override(self, isolated_types):
        rec_module.add_resource_type("AWS::XYZ::NotReal")
        assert isolated_types.exists()
        result = runner.invoke(app, ["recorder", "types", "reset", "--yes"])
        assert result.exit_code == 0
        assert "Reverted" in result.output


# ---------------------------------------------------------------------------
# standstill recorder status / setup
# ---------------------------------------------------------------------------

class TestRecorderCommand:
    @mock_aws
    def test_recorder_status_all(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        mock_state = RecorderState("123456789012", "Acct", "OU", exists=False)
        with (
            patch("standstill.commands.recorder.org_api.build_ou_tree", return_value=[_ou()]),
            patch("standstill.commands.recorder.org_api.all_accounts", return_value=[_account()]),
            patch("standstill.commands.recorder.rec_api.get_all_recorder_states", return_value=[mock_state]),
        ):
            result = runner.invoke(app, ["recorder", "status", "--all"])
        assert result.exit_code == 0

    @mock_aws
    def test_recorder_setup_dry_run(self):
        boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
        mock_state = RecorderState("123456789012", "Acct", "OU", exists=True, running=True,
                                   recording_frequency="CONTINUOUS", resource_type_count=5)
        with (
            patch("standstill.commands.recorder.org_api.build_ou_tree", return_value=[_ou()]),
            patch("standstill.commands.recorder.org_api.all_accounts", return_value=[_account()]),
            patch("standstill.commands.recorder.rec_api.get_all_recorder_states", return_value=[mock_state]),
            patch("standstill.commands.recorder.rec_api.load_resource_types",
                  return_value=["AWS::S3::Bucket"]),
        ):
            result = runner.invoke(app, ["recorder", "setup", "--all", "--dry-run"])
        assert result.exit_code == 0

    def test_recorder_setup_applies(self):
        mock_result = RecorderResult("123456789012", "Acct", "OU", success=True,
                                     message="ok", planned_types=1, planned_frequency="DAILY")
        with (
            patch("standstill.commands.recorder.org_api.build_ou_tree", return_value=[_ou()]),
            patch("standstill.commands.recorder.org_api.all_accounts", return_value=[_account()]),
            patch("standstill.commands.recorder.rec_api.load_resource_types",
                  return_value=["AWS::S3::Bucket"]),
            patch("standstill.commands.recorder.rec_api.configure_all_recorders",
                  return_value=[mock_result]),
        ):
            result = runner.invoke(app, ["recorder", "setup", "--all"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# standstill security init
# ---------------------------------------------------------------------------

class TestSecurityInitCommand:
    def test_init_all_disabled(self, tmp_path):
        output_file = tmp_path / "sec.yaml"
        # Answer: account, then n for all 5 services
        user_input = "123456789012\nn\nn\nn\nn\nn\n"
        result = runner.invoke(
            app,
            ["security", "init", "--output", str(output_file)],
            input=user_input,
        )
        assert result.exit_code == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "123456789012" in content

    def test_init_invalid_account_then_valid(self, tmp_path):
        output_file = tmp_path / "sec.yaml"
        # First bad account, then valid, then n for all services
        user_input = "badaccount\n123456789012\nn\nn\nn\nn\nn\n"
        result = runner.invoke(
            app,
            ["security", "init", "--output", str(output_file)],
            input=user_input,
        )
        assert result.exit_code == 0

    def test_init_all_enabled_defaults(self, tmp_path):
        output_file = tmp_path / "sec.yaml"
        # Each prompt gets one \n (accept default).
        # Sequence: account, GD(y), GD-freq, GD-auto, s3, rds, eks, malware, lambda-net,
        # SH(y), SH-auto, fsbp, cis14, cis30, pci, nist, cross_region,
        # Macie(y), macie-freq, discovery,
        # Inspector(y), ec2, ecr, lambda,
        # AA(y), unused
        user_input = "123456789012\n" + "\n" * 25
        result = runner.invoke(
            app,
            ["security", "init", "--output", str(output_file)],
            input=user_input,
        )
        assert result.exit_code == 0
        content = output_file.read_text()
        assert "guardduty" in content
        assert "security_hub" in content


# ---------------------------------------------------------------------------
# standstill security apply
# ---------------------------------------------------------------------------

class TestSecurityApplyCommand:
    def test_apply_file_not_found(self):
        result = runner.invoke(app, ["security", "apply", "--file", "/nonexistent.yaml"])
        assert result.exit_code == 1

    def test_apply_dry_run(self, tmp_path):
        cfg_file = tmp_path / "sec.yaml"
        cfg_file.write_text(
            "version: '1'\ndelegated_admin_account: '123456789012'\nservices:\n  guardduty:\n    enabled: true\n"
        )
        delegations = [
            DelegationStatus("guardduty", "guardduty.amazonaws.com",
                             None, "123456789012", "register")
        ]
        with patch("standstill.commands.security.sec_api.check_delegated_admins",
                   return_value=delegations):
            result = runner.invoke(
                app, ["security", "apply", "--file", str(cfg_file), "--dry-run"]
            )
        assert result.exit_code == 0
        assert "Dry run" in result.output

    def test_apply_executes(self, tmp_path):
        cfg_file = tmp_path / "sec.yaml"
        cfg_file.write_text(
            "version: '1'\ndelegated_admin_account: '123456789012'\nservices:\n  guardduty:\n    enabled: false\n"
        )
        delegations = [
            DelegationStatus("guardduty", "guardduty.amazonaws.com",
                             None, "123456789012", "register")
        ]
        p1 = [ServiceApplyResult("guardduty", "delegation", True, "ok")]
        p2 = [ServiceApplyResult("guardduty", "configuration", True, "ok")]
        with (
            patch("standstill.commands.security.sec_api.check_delegated_admins",
                  return_value=delegations),
            patch("standstill.commands.security.sec_api.apply_services", return_value=(p1, p2)),
        ):
            result = runner.invoke(
                app, ["security", "apply", "--file", str(cfg_file), "--yes"]
            )
        assert result.exit_code == 0

    def test_apply_phase1_failure_exits_nonzero(self, tmp_path):
        cfg_file = tmp_path / "sec.yaml"
        cfg_file.write_text(
            "version: '1'\ndelegated_admin_account: '123456789012'\nservices:\n  guardduty:\n    enabled: true\n"
        )
        delegations = [
            DelegationStatus("guardduty", "guardduty.amazonaws.com",
                             None, "123456789012", "register")
        ]
        p1 = [ServiceApplyResult("guardduty", "delegation", False, "Access denied")]
        p2 = []
        with (
            patch("standstill.commands.security.sec_api.check_delegated_admins",
                  return_value=delegations),
            patch("standstill.commands.security.sec_api.apply_services", return_value=(p1, p2)),
        ):
            result = runner.invoke(
                app, ["security", "apply", "--file", str(cfg_file), "--yes"]
            )
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# standstill security status
# ---------------------------------------------------------------------------

class TestSecurityStatusCommand:
    def test_status_no_args(self):
        result = runner.invoke(app, ["security", "status"])
        assert result.exit_code == 1

    def test_status_invalid_account(self):
        result = runner.invoke(app, ["security", "status", "--account", "notanaccount"])
        assert result.exit_code == 1

    def test_status_with_account(self):
        statuses = [
            ServiceStatus("guardduty", "123456789012", True, "ALL", {})
        ]
        with patch("standstill.commands.security.sec_api.get_service_statuses",
                   return_value=statuses):
            result = runner.invoke(app, ["security", "status", "--account", "123456789012"])
        assert result.exit_code == 0

    def test_status_from_file(self, tmp_path):
        cfg_file = tmp_path / "sec.yaml"
        cfg_file.write_text(
            "version: '1'\ndelegated_admin_account: '123456789012'\nservices: {}\n"
        )
        with patch("standstill.commands.security.sec_api.get_service_statuses", return_value=[]):
            result = runner.invoke(app, ["security", "status", "--file", str(cfg_file)])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# standstill security assess
# ---------------------------------------------------------------------------

class TestSecurityAssessCommand:
    def test_assess_no_args(self):
        result = runner.invoke(app, ["security", "assess"])
        assert result.exit_code == 1

    def test_assess_invalid_account(self):
        result = runner.invoke(app, ["security", "assess", "--account", "badid"])
        assert result.exit_code == 1

    def test_assess_all_healthy(self):
        assessments = [
            AccountAssessment(
                account_id="111111111111", account_name="Acct1", ou_name="Dev",
                services={
                    svc: MemberServiceStatus(True, "Enabled")
                    for svc in ["guardduty", "security_hub", "macie", "inspector"]
                },
            )
        ]
        assessments[0].services["access_analyzer"] = MemberServiceStatus(True, "org_wide")
        with patch("standstill.commands.security.sec_api.assess_member_accounts",
                   return_value=assessments):
            result = runner.invoke(app, ["security", "assess", "--account", "123456789012"])
        assert result.exit_code == 0

    def test_assess_with_gaps(self):
        assessments = [
            AccountAssessment(
                account_id="111111111111", account_name="Acct1", ou_name="Dev",
                services={"guardduty": MemberServiceStatus(False, "not_member")},
            )
        ]
        with patch("standstill.commands.security.sec_api.assess_member_accounts",
                   return_value=assessments):
            result = runner.invoke(app, ["security", "assess", "--account", "123456789012"])
        assert result.exit_code == 0

    def test_assess_api_error(self):
        with patch("standstill.commands.security.sec_api.assess_member_accounts",
                   side_effect=RuntimeError("API error")):
            result = runner.invoke(app, ["security", "assess", "--account", "123456789012"])
        assert result.exit_code == 1

    def test_assess_from_file(self, tmp_path):
        cfg_file = tmp_path / "sec.yaml"
        cfg_file.write_text(
            "version: '1'\ndelegated_admin_account: '123456789012'\nservices: {}\n"
        )
        with patch("standstill.commands.security.sec_api.assess_member_accounts", return_value=[]):
            result = runner.invoke(
                app, ["security", "assess", "--file", str(cfg_file), "--all"]
            )
        assert result.exit_code == 0
