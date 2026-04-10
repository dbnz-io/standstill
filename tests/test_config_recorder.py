"""Tests for standstill/aws/config_recorder.py"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

import standstill.aws.config_recorder as rec
from standstill.aws.organizations import Account

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_user_types(tmp_path, monkeypatch):
    """Point the user override path at a temp directory."""
    user_path = tmp_path / "securityhub_resource_types.yaml"
    monkeypatch.setattr(rec, "_USER_TYPES_PATH", user_path)
    return user_path


def _account(account_id="123456789012", name="test-account", ou="Security"):
    return Account(id=account_id, arn=f"arn:aws:organizations:::{account_id}",
                   name=name, email="test@test.com", status="ACTIVE",
                   ou_id="ou-test", ou_name=ou)


# ---------------------------------------------------------------------------
# Resource type catalog
# ---------------------------------------------------------------------------

class TestLoadResourceTypes:
    def test_bundled_loads(self):
        types = rec.load_bundled_resource_types()
        assert len(types) > 0
        assert all(t.startswith("AWS::") for t in types)

    def test_user_override_returns_none_when_missing(self, isolated_user_types):
        assert rec.load_user_resource_types() is None

    def test_user_override_loads(self, isolated_user_types):
        import yaml
        isolated_user_types.write_text(
            yaml.dump({"resource_types": ["AWS::EC2::Instance", "AWS::S3::Bucket"]})
        )
        result = rec.load_user_resource_types()
        assert result == ["AWS::EC2::Instance", "AWS::S3::Bucket"]

    def test_load_resource_types_prefers_user(self, isolated_user_types):
        import yaml
        isolated_user_types.write_text(
            yaml.dump({"resource_types": ["AWS::EC2::Instance"]})
        )
        assert rec.load_resource_types() == ["AWS::EC2::Instance"]

    def test_load_resource_types_falls_back_to_bundled(self, isolated_user_types):
        types = rec.load_resource_types()
        assert len(types) > 1  # bundled has many

    def test_is_user_override_active(self, isolated_user_types):
        assert not rec.is_user_override_active()
        isolated_user_types.write_text("resource_types: []")
        assert rec.is_user_override_active()


class TestValidateResourceType:
    def test_valid(self):
        assert rec.validate_resource_type("AWS::EC2::Instance") is True
        assert rec.validate_resource_type("AWS::S3::Bucket") is True
        assert rec.validate_resource_type("AWS::IAM::Role") is True

    def test_invalid(self):
        assert rec.validate_resource_type("ec2::instance") is False
        assert rec.validate_resource_type("AWS::") is False
        assert rec.validate_resource_type("AWS::EC2") is False
        assert rec.validate_resource_type("not-aws") is False


class TestAddRemoveReset:
    def test_add_new_type(self, isolated_user_types):
        ok, msg = rec.add_resource_type("AWS::XYZ::NotReal")
        assert ok
        assert "Added" in msg
        assert "AWS::XYZ::NotReal" in rec.load_resource_types()

    def test_add_duplicate(self, isolated_user_types):
        rec.add_resource_type("AWS::XYZ::NotReal")
        ok, msg = rec.add_resource_type("AWS::XYZ::NotReal")
        assert not ok
        assert "already" in msg

    def test_add_invalid_format(self, isolated_user_types):
        ok, msg = rec.add_resource_type("invalid-type")
        assert not ok
        assert "Invalid" in msg

    def test_remove_existing(self, isolated_user_types):
        rec.add_resource_type("AWS::XYZ::NotReal")
        ok, msg = rec.remove_resource_type("AWS::XYZ::NotReal")
        assert ok
        assert "Removed" in msg
        assert "AWS::XYZ::NotReal" not in rec.load_resource_types()

    def test_remove_not_in_list(self, isolated_user_types):
        ok, msg = rec.remove_resource_type("AWS::XYZ::NotReal")
        assert not ok
        assert "not in" in msg

    def test_reset_removes_file(self, isolated_user_types):
        rec.add_resource_type("AWS::XYZ::NotReal")
        assert isolated_user_types.exists()
        removed = rec.reset_resource_types()
        assert removed is True
        assert not isolated_user_types.exists()

    def test_reset_when_no_file(self, isolated_user_types):
        removed = rec.reset_resource_types()
        assert removed is False

    def test_save_creates_dirs(self, isolated_user_types):
        rec.save_user_resource_types(["AWS::S3::Bucket"])
        assert isolated_user_types.exists()
        types = rec.load_user_resource_types()
        assert "AWS::S3::Bucket" in types


# ---------------------------------------------------------------------------
# get_recorder_state (mock _account_config_client)
# ---------------------------------------------------------------------------

class TestGetRecorderState:
    def test_assume_role_failure(self):
        acct = _account()
        with patch.object(rec, "_account_config_client",
                          side_effect=RuntimeError("Cannot assume role")):
            state = rec.get_recorder_state(acct, "SomeRole", "us-east-1")
        assert state.error == "Cannot assume role"
        assert not state.exists

    def test_no_recorders(self):
        acct = _account()
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            state = rec.get_recorder_state(acct, "SomeRole", "us-east-1")
        assert not state.exists
        assert state.error == ""

    def test_recorder_present_running(self):
        acct = _account()
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {
                    "allSupported": False,
                    "resourceTypes": ["AWS::EC2::Instance", "AWS::S3::Bucket"],
                },
                "recordingMode": {"recordingFrequency": "DAILY"},
            }]
        }
        mock_cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": True}]
        }
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            state = rec.get_recorder_state(acct, "SomeRole", "us-east-1")
        assert state.exists
        assert state.running
        assert state.recording_frequency == "DAILY"
        assert state.resource_type_count == 2
        assert not state.all_supported

    def test_recorder_all_supported(self):
        acct = _account()
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": True, "resourceTypes": []},
                "recordingMode": {},
            }]
        }
        mock_cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": False}]
        }
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            state = rec.get_recorder_state(acct, "SomeRole", "us-east-1")
        assert state.all_supported
        assert not state.running
        assert state.recording_frequency == "CONTINUOUS"  # default


# ---------------------------------------------------------------------------
# configure_recorder
# ---------------------------------------------------------------------------

class TestConfigureRecorder:
    def test_no_recorder_skips(self):
        acct = _account()
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            result = rec.configure_recorder(acct, "Role", "us-east-1", "DAILY", ["AWS::S3::Bucket"])
        assert not result.success
        assert "No recorder" in result.message

    def test_assume_role_error(self):
        acct = _account()
        with patch.object(rec, "_account_config_client",
                          side_effect=RuntimeError("no creds")):
            result = rec.configure_recorder(acct, "Role", "us-east-1", "DAILY", ["AWS::S3::Bucket"])
        assert not result.success
        assert "no creds" in result.message

    def test_noop_when_already_correct(self):
        acct = _account()
        mock_cfg = MagicMock()
        resource_types = ["AWS::S3::Bucket", "AWS::EC2::Instance"]
        mock_cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": False, "resourceTypes": resource_types},
                "recordingMode": {"recordingFrequency": "DAILY"},
            }]
        }
        mock_cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": True}]
        }
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            result = rec.configure_recorder(acct, "Role", "us-east-1", "DAILY", resource_types)
        assert result.success
        assert result.noop
        mock_cfg.put_configuration_recorder.assert_not_called()

    def test_applies_change(self):
        acct = _account()
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": True, "resourceTypes": []},
                "recordingMode": {"recordingFrequency": "CONTINUOUS"},
            }]
        }
        mock_cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": True}]
        }
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            result = rec.configure_recorder(acct, "Role", "us-east-1", "DAILY", ["AWS::S3::Bucket"])
        assert result.success
        mock_cfg.put_configuration_recorder.assert_called_once()

    def test_starts_recorder_if_stopped(self):
        acct = _account()
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {
            "ConfigurationRecorders": [{
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/ConfigRole",
                "recordingGroup": {"allSupported": True, "resourceTypes": []},
                "recordingMode": {"recordingFrequency": "CONTINUOUS"},
            }]
        }
        mock_cfg.describe_configuration_recorder_status.return_value = {
            "ConfigurationRecordersStatus": [{"recording": False}]
        }
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            result = rec.configure_recorder(acct, "Role", "us-east-1", "DAILY", ["AWS::S3::Bucket"])
        assert result.success
        mock_cfg.start_configuration_recorder.assert_called_once_with(
            ConfigurationRecorderName="default"
        )
        assert "started" in result.message


# ---------------------------------------------------------------------------
# get_all_recorder_states / configure_all_recorders (concurrency)
# ---------------------------------------------------------------------------

class TestConcurrentFunctions:
    def test_get_all_recorder_states_two_accounts(self):
        accounts = [_account("111111111111", "Acct1"), _account("222222222222", "Acct2")]
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            states = rec.get_all_recorder_states(accounts, "Role", "us-east-1")
        assert len(states) == 2

    def test_configure_all_recorders(self):
        accounts = [_account("111111111111", "Acct1")]
        mock_cfg = MagicMock()
        mock_cfg.describe_configuration_recorders.return_value = {"ConfigurationRecorders": []}
        with patch.object(rec, "_account_config_client", return_value=mock_cfg):
            results = rec.configure_all_recorders(accounts, "Role", "us-east-1", "DAILY", [])
        assert len(results) == 1
        assert "No recorder" in results[0].message
