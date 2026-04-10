"""Tests for aws/landing_zone.py and commands/lz.py."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

import standstill.aws.landing_zone as lz_api
from standstill.aws.landing_zone import (
    LandingZone,
    LzSettings,
    _parse_manifest,
    build_updated_manifest,
)
from standstill.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_lz(
    status="ACTIVE",
    version="3.3",
    latest="3.3",
    drift_status="IN_SYNC",
    drift_types=None,
    manifest=None,
):
    return LandingZone(
        arn="arn:aws:controltower:us-east-1::landingzone/abc123",
        status=status,
        version=version,
        latest_version=latest,
        drift_status=drift_status,
        drift_types=drift_types or [],
        settings=LzSettings(),
        manifest=manifest or {},
    )


def _ct_client(lz=None):
    """Return a mock controltower client that returns lz on get_landing_zone."""
    mock = MagicMock()
    if lz is None:
        mock.list_landing_zones.return_value = {"landingZones": []}
    else:
        mock.list_landing_zones.return_value = {
            "landingZones": [{"arn": lz.arn}]
        }
        mock.get_landing_zone.return_value = {
            "landingZone": {
                "arn": lz.arn,
                "status": lz.status,
                "version": lz.version,
                "latestAvailableVersion": lz.latest_version,
                "driftStatus": {"status": lz.drift_status},
                "manifest": lz.manifest,
            }
        }
    return mock


# ---------------------------------------------------------------------------
# aws/landing_zone.py — get_landing_zone
# ---------------------------------------------------------------------------

class TestGetLandingZone:
    def test_no_landing_zone(self):
        with patch.object(lz_api._state.state, "get_client", return_value=_ct_client()):
            result = lz_api.get_landing_zone()
        assert result is None

    def test_returns_landing_zone(self):
        lz = _make_lz()
        with patch.object(lz_api._state.state, "get_client", return_value=_ct_client(lz)):
            result = lz_api.get_landing_zone()
        assert result is not None
        assert result.status == "ACTIVE"
        assert result.version == "3.3"
        assert result.drift_status == "IN_SYNC"

    def test_with_drift_types(self):
        lz = _make_lz(drift_status="DRIFTED", drift_types=["SCHEMA_UPGRADE_REQUIRED"])
        mock_ct = _ct_client(lz)
        mock_ct.get_landing_zone.return_value["landingZone"]["remediationTypes"] = ["SCHEMA_UPGRADE_REQUIRED"]
        with patch.object(lz_api._state.state, "get_client", return_value=mock_ct):
            result = lz_api.get_landing_zone()
        assert result is not None


# ---------------------------------------------------------------------------
# aws/landing_zone.py — _parse_manifest
# ---------------------------------------------------------------------------

class TestParseManifest:
    def test_empty_manifest(self):
        s = _parse_manifest({})
        assert s.governed_regions == []
        assert s.logging.enabled is False
        assert s.config.enabled is False
        assert s.backup.enabled is False
        assert s.access_management_enabled is False

    def test_full_manifest(self):
        manifest = {
            "governedRegions": ["us-east-1", "eu-west-1"],
            "organizationStructure": {
                "security": {"name": "Security"},
                "sandbox": {"name": "Sandbox"},
            },
            "centralizedLogging": {
                "enabled": True,
                "accountId": "111111111111",
                "configurations": {
                    "loggingBucket": {"retentionDays": 365},
                    "accessLoggingBucket": {"retentionDays": 90},
                    "kmsKeyArn": "arn:aws:kms:us-east-1::key/abc",
                },
            },
            "config": {
                "enabled": True,
                "accountId": "222222222222",
                "configurations": {
                    "loggingBucket": {"retentionDays": 180},
                    "accessLoggingBucket": {"retentionDays": 30},
                },
            },
            "backup": {
                "enabled": True,
                "configurations": {
                    "centralBackup": {"accountId": "333333333333"},
                },
            },
            "accessManagement": {"enabled": True},
        }
        s = _parse_manifest(manifest)
        assert "us-east-1" in s.governed_regions
        assert s.logging.enabled is True
        assert s.logging.account_id == "111111111111"
        assert s.logging.log_retention_days == 365
        assert s.logging.access_log_retention_days == 90
        assert s.logging.kms_key_arn == "arn:aws:kms:us-east-1::key/abc"
        assert s.config.enabled is True
        assert s.config.log_retention_days == 180
        assert s.backup.enabled is True
        assert s.backup.account_id == "333333333333"
        assert s.access_management_enabled is True


# ---------------------------------------------------------------------------
# aws/landing_zone.py — mutations
# ---------------------------------------------------------------------------

class TestLzMutations:
    def test_reset_landing_zone(self):
        mock_ct = MagicMock()
        mock_ct.reset_landing_zone.return_value = {"operationIdentifier": "op-reset-1"}
        with patch.object(lz_api._state.state, "get_client", return_value=mock_ct):
            op_id = lz_api.reset_landing_zone("arn:aws:controltower:::landingzone/x")
        assert op_id == "op-reset-1"

    def test_update_landing_zone(self):
        mock_ct = MagicMock()
        mock_ct.update_landing_zone.return_value = {"operationIdentifier": "op-update-1"}
        with patch.object(lz_api._state.state, "get_client", return_value=mock_ct):
            op_id = lz_api.update_landing_zone("arn:...", "3.4", {})
        assert op_id == "op-update-1"


# ---------------------------------------------------------------------------
# aws/landing_zone.py — build_updated_manifest
# ---------------------------------------------------------------------------

class TestBuildUpdatedManifest:
    def test_no_changes(self):
        manifest = {"centralizedLogging": {"enabled": True}}
        result = build_updated_manifest(manifest, {})
        assert result == manifest
        assert result is not manifest  # deep copy

    def test_logging_changes(self):
        result = build_updated_manifest({}, {
            "logging_enabled": True,
            "logging_log_retention_days": 365,
            "logging_access_retention_days": 90,
            "logging_kms_key_arn": "arn:aws:kms:::key/x",
        })
        assert result["centralizedLogging"]["enabled"] is True
        assert result["centralizedLogging"]["configurations"]["loggingBucket"]["retentionDays"] == 365
        assert result["centralizedLogging"]["configurations"]["accessLoggingBucket"]["retentionDays"] == 90
        assert result["centralizedLogging"]["configurations"]["kmsKeyArn"] == "arn:aws:kms:::key/x"

    def test_logging_kms_none_removes_key(self):
        manifest = {"centralizedLogging": {"configurations": {"kmsKeyArn": "arn:..."}}}
        result = build_updated_manifest(manifest, {"logging_kms_key_arn": None})
        assert "kmsKeyArn" not in result["centralizedLogging"]["configurations"]

    def test_config_changes(self):
        result = build_updated_manifest({}, {
            "config_enabled": True,
            "config_log_retention_days": 180,
            "config_access_retention_days": 30,
            "config_kms_key_arn": "arn:aws:kms:::key/y",
        })
        assert result["config"]["enabled"] is True
        assert result["config"]["configurations"]["loggingBucket"]["retentionDays"] == 180

    def test_backup_and_access_management(self):
        result = build_updated_manifest({}, {
            "backup_enabled": False,
            "access_management_enabled": True,
        })
        assert result["backup"]["enabled"] is False
        assert result["accessManagement"]["enabled"] is True


# ---------------------------------------------------------------------------
# aws/landing_zone.py — poll_lz_operation
# ---------------------------------------------------------------------------

class TestPollLzOperation:
    def test_succeeds_immediately(self):
        mock_ct = MagicMock()
        mock_ct.get_landing_zone_operation.return_value = {
            "operationDetails": {"status": "SUCCEEDED", "operationType": "UPDATE"}
        }
        with (
            patch.object(lz_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.landing_zone.time.sleep"),
            patch("standstill.aws.landing_zone.random.uniform", return_value=0),
        ):
            result = lz_api.poll_lz_operation("op-lz-1", timeout=60)
        assert result["status"] == "SUCCEEDED"

    def test_polls_until_succeeded(self):
        mock_ct = MagicMock()
        mock_ct.get_landing_zone_operation.side_effect = [
            {"operationDetails": {"status": "IN_PROGRESS", "operationType": "RESET"}},
            {"operationDetails": {"status": "SUCCEEDED", "operationType": "RESET"}},
        ]
        with (
            patch.object(lz_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.landing_zone.time.sleep"),
            patch("standstill.aws.landing_zone.random.uniform", return_value=0),
        ):
            result = lz_api.poll_lz_operation("op-lz-2", timeout=60, poll_interval=1)
        assert result["status"] == "SUCCEEDED"

    def test_timeout_raises(self):
        mock_ct = MagicMock()
        mock_ct.get_landing_zone_operation.return_value = {
            "operationDetails": {"status": "IN_PROGRESS", "operationType": "UPDATE"}
        }
        call_count = 0

        def fake_monotonic():
            nonlocal call_count
            call_count += 1
            return call_count * 100  # jumps past deadline fast

        with (
            patch.object(lz_api._state.state, "get_client", return_value=mock_ct),
            patch("standstill.aws.landing_zone.time.sleep"),
            patch("standstill.aws.landing_zone.random.uniform", return_value=0),
            patch("standstill.aws.landing_zone.time.monotonic", fake_monotonic),
        ):
            with pytest.raises(TimeoutError):
                lz_api.poll_lz_operation("op-lz-3", timeout=1, poll_interval=1)


# ---------------------------------------------------------------------------
# commands/lz.py — status
# ---------------------------------------------------------------------------

class TestLzStatusCommand:
    def test_status_no_lz(self):
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=None):
            result = runner.invoke(app, ["lz", "status"])
        assert result.exit_code == 1
        assert "No landing zone" in result.output

    def test_status_active_in_sync(self):
        lz = _make_lz()
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "status"])
        assert result.exit_code == 0

    def test_status_drifted_shows_warning(self):
        lz = _make_lz(drift_status="DRIFTED")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "status"])
        assert result.exit_code == 0
        assert "drifted" in result.output.lower() or "lz reset" in result.output

    def test_status_upgrade_available(self):
        lz = _make_lz(version="3.2", latest="3.3")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "status"])
        assert result.exit_code == 0
        assert "3.3" in result.output

    def test_status_failed_state(self):
        lz = _make_lz(status="FAILED")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "status"])
        assert result.exit_code == 0
        assert "FAILED" in result.output or "failed" in result.output.lower()


# ---------------------------------------------------------------------------
# commands/lz.py — reset
# ---------------------------------------------------------------------------

class TestLzResetCommand:
    def test_reset_no_lz(self):
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=None):
            result = runner.invoke(app, ["lz", "reset", "--yes"])
        assert result.exit_code == 1

    def test_reset_already_processing(self):
        lz = _make_lz(status="PROCESSING")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "reset", "--yes"])
        assert result.exit_code == 1
        assert "processing" in result.output.lower()

    def test_reset_no_wait(self):
        lz = _make_lz()
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.reset_landing_zone", return_value="op-r-1"),
        ):
            result = runner.invoke(app, ["lz", "reset", "--yes", "--no-wait"])
        assert result.exit_code == 0
        assert "op-r-1" in result.output

    def test_reset_wait_succeeds(self):
        lz = _make_lz()
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.reset_landing_zone", return_value="op-r-2"),
            patch("standstill.commands.lz._poll_with_progress",
                  return_value={"status": "SUCCEEDED", "operationType": "RESET"}),
        ):
            result = runner.invoke(app, ["lz", "reset", "--yes"])
        assert result.exit_code == 0
        assert "successfully" in result.output

    def test_reset_wait_fails(self):
        lz = _make_lz()
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.reset_landing_zone", return_value="op-r-3"),
            patch("standstill.commands.lz._poll_with_progress",
                  return_value={"status": "FAILED", "statusMessage": "something broke"}),
        ):
            result = runner.invoke(app, ["lz", "reset", "--yes"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# commands/lz.py — update
# ---------------------------------------------------------------------------

class TestLzUpdateCommand:
    def test_update_no_lz(self):
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=None):
            result = runner.invoke(app, ["lz", "update", "--yes"])
        assert result.exit_code == 1

    def test_update_already_at_version(self):
        lz = _make_lz(version="3.3", latest="3.3")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "update", "--yes"])
        assert result.exit_code == 0
        assert "Nothing to do" in result.output

    def test_update_processing(self):
        lz = _make_lz(version="3.2", latest="3.3", status="PROCESSING")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "update", "--yes"])
        assert result.exit_code == 1

    def test_update_no_wait(self):
        lz = _make_lz(version="3.2", latest="3.3")
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.update_landing_zone", return_value="op-u-1"),
        ):
            result = runner.invoke(app, ["lz", "update", "--yes", "--no-wait"])
        assert result.exit_code == 0
        assert "op-u-1" in result.output

    def test_update_succeeds(self):
        lz = _make_lz(version="3.2", latest="3.3")
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.update_landing_zone", return_value="op-u-2"),
            patch("standstill.commands.lz._poll_with_progress",
                  return_value={"status": "SUCCEEDED", "operationType": "UPDATE"}),
        ):
            result = runner.invoke(app, ["lz", "update", "--yes"])
        assert result.exit_code == 0

    def test_update_explicit_version(self):
        lz = _make_lz(version="3.2", latest="3.3")
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.update_landing_zone", return_value="op-u-3"),
            patch("standstill.commands.lz._poll_with_progress",
                  return_value={"status": "SUCCEEDED", "operationType": "UPDATE"}),
        ):
            result = runner.invoke(app, ["lz", "update", "--yes", "--version", "3.3"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# commands/lz.py — settings
# ---------------------------------------------------------------------------

class TestLzSettingsCommand:
    def test_settings_no_lz(self):
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=None):
            result = runner.invoke(app, ["lz", "settings"])
        assert result.exit_code == 1

    def test_settings_shows_detail(self):
        lz = _make_lz()
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "settings"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# commands/lz.py — settings-set
# ---------------------------------------------------------------------------

class TestLzSettingsSetCommand:
    def test_settings_set_no_flags(self):
        result = runner.invoke(app, ["lz", "settings-set"])
        assert result.exit_code == 1
        assert "No changes" in result.output

    def test_settings_set_no_lz(self):
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=None):
            result = runner.invoke(app, ["lz", "settings-set", "--logging-retention", "90"])
        assert result.exit_code == 1

    def test_settings_set_processing(self):
        lz = _make_lz(status="PROCESSING")
        with patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz):
            result = runner.invoke(app, ["lz", "settings-set", "--yes", "--logging-retention", "90"])
        assert result.exit_code == 1

    def test_settings_set_applies(self):
        lz = _make_lz()
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.build_updated_manifest", return_value={}),
            patch("standstill.commands.lz.lz_api.update_landing_zone", return_value="op-s-1"),
            patch("standstill.commands.lz._poll_with_progress",
                  return_value={"status": "SUCCEEDED", "operationType": "UPDATE"}),
        ):
            result = runner.invoke(app, ["lz", "settings-set", "--yes", "--logging-retention", "365"])
        assert result.exit_code == 0

    def test_settings_set_no_wait(self):
        lz = _make_lz()
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.build_updated_manifest", return_value={}),
            patch("standstill.commands.lz.lz_api.update_landing_zone", return_value="op-s-2"),
        ):
            result = runner.invoke(
                app, ["lz", "settings-set", "--yes", "--no-wait", "--logging-retention", "365"]
            )
        assert result.exit_code == 0

    def test_settings_set_fails(self):
        lz = _make_lz()
        with (
            patch("standstill.commands.lz.lz_api.get_landing_zone", return_value=lz),
            patch("standstill.commands.lz.lz_api.build_updated_manifest", return_value={}),
            patch("standstill.commands.lz.lz_api.update_landing_zone", return_value="op-s-3"),
            patch("standstill.commands.lz._poll_with_progress",
                  return_value={"status": "FAILED", "statusMessage": "error"}),
        ):
            result = runner.invoke(app, ["lz", "settings-set", "--yes", "--logging-retention", "365"])
        assert result.exit_code == 1
