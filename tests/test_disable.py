"""Tests for commands/disable.py."""
from __future__ import annotations

import pathlib
import tempfile
from unittest.mock import patch

from typer.testing import CliRunner

from standstill.aws.controltower import Control, EnabledControl
from standstill.aws.organizations import OUNode
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
    return Control(
        arn="arn:aws:controltower:us-east-1::control/AWS-GR_TEST",
        full_name="Test", description="", behavior=behavior, severity="HIGH",
    )


def _make_enabled(arn="arn:aws:controltower:us-east-1::control/AWS-GR_TEST"):
    return EnabledControl(control_arn=arn, ou_arn="arn:aws:organizations:::ou/o-1/ou-ab12-34cd5678", status="SUCCEEDED")


class TestDisableCommand:
    def test_no_args_exits_1(self):
        result = runner.invoke(app, ["disable"])
        assert result.exit_code == 1
        assert "Provide" in result.output

    def test_mutually_exclusive_flags(self):
        result = runner.invoke(app, ["disable", "--disable-all", "--disable-detective", "--ou", "ou-ab12-34cd5678"])
        assert result.exit_code == 1
        assert "mutually" in result.output

    def test_all_requires_ou(self):
        result = runner.invoke(app, ["disable", "--disable-all"])
        assert result.exit_code == 1
        assert "require" in result.output

    def test_concurrency_out_of_range(self):
        result = runner.invoke(app, ["disable", "--disable-all", "--ou", "ou-ab12-34cd5678", "--concurrency", "100"])
        assert result.exit_code == 1
        assert "concurrency" in result.output

    def test_file_not_found(self):
        result = runner.invoke(app, ["disable", "--file", "/nonexistent.yaml"])
        assert result.exit_code == 1

    def test_disable_all_ou_not_found(self):
        with (
            patch("standstill.commands.disable.org_api.build_ou_tree", return_value=[]),
            patch("standstill.commands.disable.org_api.flatten_ous", return_value=[]),
        ):
            result = runner.invoke(app, ["disable", "--disable-all", "--ou", "ou-notexist"])
        assert result.exit_code == 1
        assert "OU not found" in result.output

    def test_disable_all_no_controls_enabled(self):
        ou = _make_ou()
        with (
            patch("standstill.commands.disable.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.disable.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.disable.ct_api.list_enabled_for_ou", return_value=[]),
        ):
            result = runner.invoke(app, ["disable", "--disable-all", "--ou", "ou-ab12-34cd5678"])
        assert result.exit_code == 0
        assert "No controls" in result.output

    def test_disable_all_dry_run(self):
        ou = _make_ou()
        enabled = [_make_enabled()]
        with (
            patch("standstill.commands.disable.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.disable.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.disable.ct_api.list_enabled_for_ou", return_value=enabled),
            patch("standstill.commands._engine.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands._engine.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous",
                  return_value={ou.arn: enabled}),
        ):
            result = runner.invoke(app, ["disable", "--disable-all", "--ou", "ou-ab12-34cd5678", "--dry-run"])
        assert result.exit_code == 0
        assert "Dry" in result.output

    def test_disable_detective_dry_run(self):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_TEST"
        enabled = [_make_enabled(ctrl_arn)]
        catalog = {ctrl_arn: _make_control("DETECTIVE")}
        with (
            patch("standstill.commands.disable.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands.disable.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.disable.ct_api.list_enabled_for_ou", return_value=enabled),
            patch("standstill.commands.disable.ct_api.load_catalog", return_value=catalog),
            patch("standstill.commands._engine.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands._engine.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous",
                  return_value={ou.arn: enabled}),
        ):
            result = runner.invoke(
                app, ["disable", "--disable-detective", "--ou", "ou-ab12-34cd5678", "--dry-run"]
            )
        assert result.exit_code == 0

    def test_disable_from_file_dry_run(self, tmp_path):
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        f = tmp_path / "controls.yaml"
        f.write_text(
            f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n"
        )
        enabled = [_make_enabled(ctrl_arn)]
        with (
            patch("standstill.commands._engine.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands._engine.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous",
                  return_value={ou.arn: enabled}),
        ):
            result = runner.invoke(app, ["disable", "--file", str(f), "--dry-run"])
        assert result.exit_code == 0

    def test_disable_nothing_to_do(self):
        """All specified controls are already disabled (not in enabled set)."""
        ou = _make_ou()
        ctrl_arn = "arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"
        f_content = f"targets:\n  - ou_id: {ou.id}\n    controls:\n      - {ctrl_arn}\n"
        with tempfile.NamedTemporaryFile(suffix=".yaml", mode="w", delete=False) as f:
            f.write(f_content)
            fpath = f.name

        with (
            patch("standstill.commands._engine.org_api.build_ou_tree", return_value=[ou]),
            patch("standstill.commands._engine.org_api.flatten_ous", return_value=[ou]),
            patch("standstill.commands.apply.ct_api.check_baselines_for_ous",
                  return_value={ou.arn: (True, "ok")}),
            # Control is NOT in enabled set → nothing to disable
            patch("standstill.commands.apply.ct_api.list_enabled_for_all_ous",
                  return_value={ou.arn: []}),
        ):
            result = runner.invoke(app, ["disable", "--file", fpath])
        pathlib.Path(fpath).unlink(missing_ok=True)
        assert result.exit_code == 0
        assert "Nothing to do" in result.output
