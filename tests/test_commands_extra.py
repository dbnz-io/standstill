"""Additional CLI tests for apply, catalog, operations, and controltower module."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

import standstill.aws.controltower as ct_api
from standstill.aws.controltower import Control
from standstill.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def pending_ops_path(tmp_path, monkeypatch):
    path = tmp_path / "pending_operations.yaml"
    monkeypatch.setattr(ct_api, "_PENDING_OPS_PATH", path)
    return path


@pytest.fixture
def user_catalog_path(tmp_path, monkeypatch):
    path = tmp_path / "catalog.yaml"
    monkeypatch.setattr(ct_api, "_USER_CATALOG_PATH", path)
    return path


# ---------------------------------------------------------------------------
# standstill operations
# ---------------------------------------------------------------------------

class TestOperationsCommand:
    def test_list_empty(self, pending_ops_path):
        with patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path):
            result = runner.invoke(app, ["operations", "list"])
        assert result.exit_code == 0
        assert "No pending" in result.output

    def test_list_with_ops(self, pending_ops_path):
        import yaml
        pending_ops_path.write_text(yaml.dump([{
            "operation_id": "op-abc123",
            "control_arn": "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES",
            "ou_arn": "arn:aws:organizations:::ou/o-1/ou-abc",
            "started_at": "2024-01-01T00:00:00Z",
            "status": "IN_PROGRESS",
        }]))
        with patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path):
            result = runner.invoke(app, ["operations", "list"])
        assert result.exit_code == 0
        assert "op-abc123" in result.output

    def test_check_empty(self, pending_ops_path):
        with patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path):
            result = runner.invoke(app, ["operations", "check"])
        assert result.exit_code == 0
        assert "No pending" in result.output

    def test_check_with_ops(self, pending_ops_path):
        import yaml
        pending_ops_path.write_text(yaml.dump([{
            "operation_id": "op-abc123",
            "control_arn": "arn:aws:controltower:us-east-1::control/X",
            "ou_arn": "arn:aws:organizations:::ou/o-1/ou-abc",
            "started_at": "2024-01-01T00:00:00Z",
            "status": "IN_PROGRESS",
        }]))
        mock_ct = MagicMock()
        mock_ct.get_control_operation.return_value = {
            "controlOperation": {"status": "SUCCEEDED", "statusMessage": "Done"}
        }
        with (
            patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path),
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
        ):
            result = runner.invoke(app, ["operations", "check"])
        assert result.exit_code == 0

    def test_check_clears_completed(self, pending_ops_path):
        import yaml
        pending_ops_path.write_text(yaml.dump([{
            "operation_id": "op-done",
            "control_arn": "arn:aws:controltower:us-east-1::control/X",
            "ou_arn": "arn:...",
            "started_at": "2024-01-01T00:00:00Z",
            "status": "IN_PROGRESS",
        }]))
        mock_ct = MagicMock()
        mock_ct.get_control_operation.return_value = {
            "controlOperation": {"status": "SUCCEEDED", "statusMessage": ""}
        }
        with (
            patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path),
            patch.object(ct_api._state.state, "get_client", return_value=mock_ct),
        ):
            result = runner.invoke(app, ["operations", "check", "--clear"])
        assert result.exit_code == 0
        assert "Removed" in result.output

    def test_clear_empty(self, pending_ops_path):
        with patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path):
            result = runner.invoke(app, ["operations", "clear"])
        assert result.exit_code == 0
        assert "already empty" in result.output

    def test_clear_with_ops(self, pending_ops_path):
        import yaml
        pending_ops_path.write_text(yaml.dump([{
            "operation_id": "op-1", "control_arn": "arn:...",
            "ou_arn": "arn:...", "started_at": "2024-01-01T00:00:00Z", "status": "SUCCEEDED",
        }]))
        with patch.object(ct_api, "_PENDING_OPS_PATH", pending_ops_path):
            result = runner.invoke(app, ["operations", "clear"])
        assert result.exit_code == 0
        assert "Cleared" in result.output


# ---------------------------------------------------------------------------
# standstill catalog
# ---------------------------------------------------------------------------

class TestCatalogCommand:
    def test_info_bundled(self, user_catalog_path):
        # No user cache → falls back to bundled
        with patch.object(ct_api, "_USER_CATALOG_PATH", user_catalog_path):
            result = runner.invoke(app, ["catalog", "info"])
        assert result.exit_code == 0

    def test_info_user_cache(self, user_catalog_path):
        import yaml
        user_catalog_path.write_text(yaml.dump({
            "_meta": {"region": "us-east-1", "total": 1},
            "controls": [{
                "arn": "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES",
                "name": "Encryption at rest", "description": "",
                "behavior": "DETECTIVE", "severity": "HIGH",
            }],
        }))
        with patch.object(ct_api, "_USER_CATALOG_PATH", user_catalog_path):
            result = runner.invoke(app, ["catalog", "info"])
        assert result.exit_code == 0
        assert "user cache" in result.output

    def test_build_catalog(self, user_catalog_path):
        sample_controls = [{
            "arn": "arn:aws:controltower:us-east-1::control/AWS-GR_TEST",
            "fullName": "Test control", "description": "desc",
            "behavior": "DETECTIVE", "severity": "HIGH",
            "implementation_type": "AWS::Config::ManagedRule",
        }]
        with (
            patch.object(ct_api, "_USER_CATALOG_PATH", user_catalog_path),
            patch("standstill.commands.catalog.ct_api.fetch_controls_from_api",
                  return_value=sample_controls),
            patch("standstill.commands.catalog.ct_api.save_user_catalog",
                  return_value=user_catalog_path),
        ):
            result = runner.invoke(app, ["catalog", "build"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# standstill apply
# ---------------------------------------------------------------------------

class TestApplyCommand:
    def _make_yaml(self, tmp_path, content):
        f = tmp_path / "controls.yaml"
        f.write_text(content)
        return f

    def test_apply_no_args(self):
        result = runner.invoke(app, ["apply"])
        assert result.exit_code == 1

    def test_apply_file_not_found(self):
        result = runner.invoke(app, ["apply", "--file", "/no/such/file.yaml"])
        assert result.exit_code == 1

    def test_apply_dry_run_from_file(self, tmp_path):
        from standstill.aws.organizations import OUNode
        cfg_file = self._make_yaml(tmp_path, """\
targets:
  - ou_id: ou-ab12-34cd5678
    controls:
      - arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES
""")
        ou_node = OUNode(
            id="ou-ab12-34cd5678",
            arn="arn:aws:organizations:::ou/o-1/ou-ab12-34cd5678",
            name="TestOU",
            parent_id=None,
        )
        with (
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou_node]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou_node]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={"arn:aws:organizations:::ou/o-1/ou-ab12-34cd5678": (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
        ):
            result = runner.invoke(
                app, ["apply", "--file", str(cfg_file), "--dry-run"]
            )
        assert result.exit_code == 0
        assert "Dry" in result.output

    def test_apply_enable_all_requires_ou(self):
        result = runner.invoke(app, ["apply", "--enable-all"])
        assert result.exit_code == 1

    def test_apply_enable_detective_dry_run(self, tmp_path):
        from standstill.aws.organizations import OUNode
        mock_control = Control(
            arn="arn:aws:controltower:us-east-1::control/AWS-GR_TEST",
            full_name="Test", description="", behavior="DETECTIVE", severity="HIGH",
        )
        ou_node = OUNode(
            id="ou-ab12-34cd5678",
            arn="arn:aws:organizations:::ou/o-1/ou-ab12-34cd5678",
            name="TestOU",
            parent_id=None,
        )
        with (
            patch("standstill.commands.apply.ct_api.load_catalog",
                  return_value={"arn:aws:controltower:us-east-1::control/AWS-GR_TEST": mock_control}),
            patch("standstill.commands.apply.org_api.build_ou_tree", return_value=[ou_node]),
            patch("standstill.commands.apply.org_api.flatten_ous", return_value=[ou_node]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={"arn:aws:organizations:::ou/o-1/ou-ab12-34cd5678": (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous", return_value={}),
        ):
            result = runner.invoke(
                app, ["apply", "--enable-detective", "--ou", "ou-ab12-34cd5678", "--dry-run"]
            )
        assert result.exit_code == 0

    def test_apply_bad_yaml(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(": invalid: yaml: {[")
        result = runner.invoke(app, ["apply", "--file", str(f)])
        assert result.exit_code == 1

    def test_apply_invalid_schema(self, tmp_path):
        f = self._make_yaml(tmp_path, "targets:\n  - ou_id: not-valid\n    controls: []\n")
        result = runner.invoke(app, ["apply", "--file", str(f)])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# controltower module unit tests
# ---------------------------------------------------------------------------

class TestControlTower:
    def test_load_catalog_bundled(self):
        catalog = ct_api.load_catalog("us-east-1")
        assert len(catalog) > 0
        for arn, ctrl in catalog.items():
            assert "us-east-1" in arn or ctrl.arn

    def test_load_catalog_behavior_filter(self):
        detective = ct_api.load_catalog("us-east-1", behavior="DETECTIVE")
        all_controls = ct_api.load_catalog("us-east-1")
        assert all(c.behavior == "DETECTIVE" for c in detective.values())
        assert len(detective) <= len(all_controls)

    def test_save_and_load_user_catalog(self, user_catalog_path):
        controls = [{
            "arn": "arn:aws:controltower:us-east-1::control/TEST",
            "fullName": "Test", "description": "d", "behavior": "DETECTIVE", "severity": "HIGH",
        }]
        with patch.object(ct_api, "_USER_CATALOG_PATH", user_catalog_path):
            ct_api.save_user_catalog(controls, "us-east-1")
            assert user_catalog_path.exists()
            loaded = ct_api.load_catalog("us-east-1")
        assert len(loaded) == 1

    def test_pending_ops_lifecycle(self, pending_ops_path):
        ct_api.save_pending_operation("op-1", "arn:aws:controltower:::control/X", "ou-arn")
        ops = ct_api.load_pending_operations()
        assert len(ops) == 1
        assert ops[0]["operation_id"] == "op-1"

        ct_api.remove_pending_operation("op-1")
        ops2 = ct_api.load_pending_operations()
        assert ops2 == []

    def test_pending_ops_empty(self, pending_ops_path):
        ops = ct_api.load_pending_operations()
        assert ops == []

    def test_remove_nonexistent_op(self, pending_ops_path):
        ct_api.remove_pending_operation("nonexistent")  # should not raise

    def test_list_enabled_for_ou_empty(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.return_value = {"enabledControls": []}
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            result = ct_api.list_enabled_for_ou("arn:aws:organizations:::ou/o-1/ou-abc")
        assert result == []

    def test_list_enabled_for_ou_with_controls(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.return_value = {
            "enabledControls": [{
                "controlIdentifier": "arn:aws:controltower:us-east-1::control/TEST",
                "statusSummary": {"status": "SUCCEEDED"},
            }]
        }
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            result = ct_api.list_enabled_for_ou("arn:aws:organizations:::ou/o-1/ou-abc")
        assert len(result) == 1
        assert result[0].status == "SUCCEEDED"

    def test_list_enabled_for_ou_resource_not_found(self):
        from botocore.exceptions import ClientError
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "not found"}},
            "ListEnabledControls"
        )
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            result = ct_api.list_enabled_for_ou("arn:aws:organizations:::ou/o-1/ou-abc")
        assert result == []

    def test_list_enabled_for_ou_pagination(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_controls.side_effect = [
            {
                "enabledControls": [{"controlIdentifier": "arn:...:control/A",
                                      "statusSummary": {"status": "SUCCEEDED"}}],
                "nextToken": "token1",
            },
            {
                "enabledControls": [{"controlIdentifier": "arn:...:control/B",
                                      "statusSummary": {"status": "FAILED"}}],
            },
        ]
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            result = ct_api.list_enabled_for_ou("arn:...")
        assert len(result) == 2

    def test_check_ou_baseline_no_baselines(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_baselines.return_value = {"enabledBaselines": []}
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            ok, msg = ct_api.check_ou_baseline("arn:...")
        assert not ok
        assert "No baseline" in msg

    def test_check_ou_baseline_active(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_baselines.return_value = {
            "enabledBaselines": [{
                "statusSummary": {"status": "SUCCEEDED"},
                "baselineIdentifier": "arn:aws:controltower:::baseline/AWSControlTowerBaseline",
            }]
        }
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            ok, msg = ct_api.check_ou_baseline("arn:...")
        assert ok

    def test_check_ou_baseline_not_succeeded(self):
        mock_ct = MagicMock()
        mock_ct.list_enabled_baselines.return_value = {
            "enabledBaselines": [{"statusSummary": {"status": "IN_PROGRESS"}}]
        }
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            ok, msg = ct_api.check_ou_baseline("arn:...")
        assert not ok
        assert "IN_PROGRESS" in msg

    def test_check_ou_baseline_api_error(self):
        from botocore.exceptions import ClientError
        mock_ct = MagicMock()
        mock_ct.list_enabled_baselines.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
            "ListEnabledBaselines"
        )
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            ok, msg = ct_api.check_ou_baseline("arn:...")
        assert not ok
        assert "denied" in msg

    def test_enable_control(self):
        mock_ct = MagicMock()
        mock_ct.enable_control.return_value = {"operationIdentifier": "op-abc"}
        with patch.object(ct_api._state.state, "get_client", return_value=mock_ct):
            op_id = ct_api.enable_control("arn:aws:controltower:::control/X", "arn:ou")
        assert op_id == "op-abc"
