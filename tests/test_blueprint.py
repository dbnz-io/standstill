"""Tests for the blueprints feature."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from standstill.aws.blueprint import StackResult, deploy_stack, poll_stack
from standstill.main import app
from standstill.models.blueprint_config import BlueprintStack, load_blueprint

runner = CliRunner()

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_INLINE_TEMPLATE = (
    "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n"
    "  Wait:\n    Type: AWS::CloudFormation::WaitConditionHandle\n"
)


def _write_blueprint(tmp_path: Path, extra: str = "") -> Path:
    """Write a minimal valid blueprint to tmp_path and return its path."""
    f = tmp_path / "net.yaml"
    f.write_text(
        "name: standard-networking\n"
        "stacks:\n"
        "  - stack_name: baseline-networking\n"
        f"    template: |\n      {_INLINE_TEMPLATE.strip()}\n"
        + extra
    )
    return f


def _write_blueprint_with_file(tmp_path: Path) -> Path:
    """Write a blueprint that references a local template file."""
    tpl = tmp_path / "net.cfn.yaml"
    tpl.write_text(_INLINE_TEMPLATE)
    bp = tmp_path / "bp.yaml"
    bp.write_text(
        "name: file-blueprint\n"
        "stacks:\n"
        "  - stack_name: baseline-networking\n"
        "    template_file: net.cfn.yaml\n"
    )
    return bp


def _cfn_mock(status: str = "CREATE_COMPLETE") -> MagicMock:
    """Return a cfn_client mock whose describe_stacks returns the given status."""
    m = MagicMock()
    m.describe_stacks.return_value = {
        "Stacks": [{"StackName": "baseline-networking", "StackStatus": status}]
    }
    return m


# ===========================================================================
# Group 1: BlueprintStack — Pydantic unit tests
# ===========================================================================

class TestBlueprintStack:
    def test_valid_inline_template(self):
        s = BlueprintStack(stack_name="my-stack", template=_INLINE_TEMPLATE)
        assert s.stack_name == "my-stack"
        assert s.template == _INLINE_TEMPLATE

    def test_valid_template_file(self):
        s = BlueprintStack(stack_name="my-stack", template_file="tpl.yaml")
        assert s.template_file == "tpl.yaml"

    def test_neither_template_raises(self):
        with pytest.raises(Exception):
            BlueprintStack(stack_name="my-stack")

    def test_both_templates_raises(self):
        with pytest.raises(Exception):
            BlueprintStack(
                stack_name="my-stack",
                template=_INLINE_TEMPLATE,
                template_file="tpl.yaml",
            )

    def test_invalid_stack_name_starts_digit(self):
        with pytest.raises(Exception):
            BlueprintStack(stack_name="1bad", template=_INLINE_TEMPLATE)

    def test_invalid_stack_name_too_long(self):
        with pytest.raises(Exception):
            BlueprintStack(stack_name="a" * 129, template=_INLINE_TEMPLATE)

    def test_invalid_capability(self):
        with pytest.raises(Exception):
            BlueprintStack(
                stack_name="s", template=_INLINE_TEMPLATE, capabilities=["CAPABILITY_BADVALUE"]
            )

    def test_capability_normalised_to_upper(self):
        s = BlueprintStack(
            stack_name="s", template=_INLINE_TEMPLATE, capabilities=["capability_iam"]
        )
        assert s.capabilities == ["CAPABILITY_IAM"]

    def test_termination_protection_defaults_true(self):
        s = BlueprintStack(stack_name="s", template=_INLINE_TEMPLATE)
        assert s.termination_protection is True

    def test_termination_protection_off(self):
        s = BlueprintStack(
            stack_name="s", template=_INLINE_TEMPLATE, termination_protection=False
        )
        assert s.termination_protection is False

    def test_region_null_maps_to_none(self):
        s = BlueprintStack(stack_name="s", template=_INLINE_TEMPLATE, region=None)
        assert s.region is None


# ===========================================================================
# Group 2: load_blueprint
# ===========================================================================

class TestLoadBlueprint:
    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_blueprint(tmp_path / "nonexistent.yaml")

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        with pytest.raises(ValueError, match="empty"):
            load_blueprint(f)

    def test_missing_stacks(self, tmp_path):
        f = tmp_path / "bp.yaml"
        f.write_text("name: test\nstacks: []\n")
        with pytest.raises(ValueError):
            load_blueprint(f)

    def test_valid_inline_blueprint(self, tmp_path):
        f = _write_blueprint(tmp_path)
        bp = load_blueprint(f)
        assert bp.name == "standard-networking"
        assert len(bp.stacks) == 1

    def test_template_file_resolved(self, tmp_path):
        f = _write_blueprint_with_file(tmp_path)
        bp = load_blueprint(f)
        assert bp.stacks[0].template_file == "net.cfn.yaml"

    def test_template_file_not_found(self, tmp_path):
        f = tmp_path / "bp.yaml"
        f.write_text(
            "name: test\nstacks:\n  - stack_name: s\n    template_file: missing.yaml\n"
        )
        with pytest.raises(FileNotFoundError, match="missing.yaml"):
            load_blueprint(f)

    def test_template_too_large(self, tmp_path):
        tpl = tmp_path / "big.yaml"
        tpl.write_text("x: " + "y" * 52000)
        f = tmp_path / "bp.yaml"
        f.write_text(
            "name: test\nstacks:\n  - stack_name: s\n    template_file: big.yaml\n"
        )
        with pytest.raises(ValueError, match="51,200"):
            load_blueprint(f)

    def test_both_template_and_template_file_raises(self, tmp_path):
        tpl = tmp_path / "t.yaml"
        tpl.write_text(_INLINE_TEMPLATE)
        f = tmp_path / "bp.yaml"
        f.write_text(
            "name: test\nstacks:\n"
            "  - stack_name: s\n"
            "    template_file: t.yaml\n"
            "    template: |\n      Resources: {}\n"
        )
        with pytest.raises(ValueError):
            load_blueprint(f)

    def test_parameters_and_tags_parsed(self, tmp_path):
        f = tmp_path / "bp.yaml"
        f.write_text(
            "name: test\nstacks:\n"
            "  - stack_name: s\n"
            "    template: 'Resources: {}'\n"
            "    parameters:\n      VpcCidr: '10.0.0.0/16'\n"
            "    tags:\n      ManagedBy: standstill\n"
        )
        bp = load_blueprint(f)
        assert bp.stacks[0].parameters == {"VpcCidr": "10.0.0.0/16"}
        assert bp.stacks[0].tags == {"ManagedBy": "standstill"}


# ===========================================================================
# Group 3: deploy_stack
# ===========================================================================

class TestDeployStack:
    def test_creates_new_stack(self):
        cfn = MagicMock()
        cfn.describe_stacks.side_effect = __import__(
            "botocore.exceptions", fromlist=["ClientError"]
        ).ClientError(
            {"Error": {"Code": "ValidationError", "Message": "Stack does not exist"}},
            "DescribeStacks",
        )
        result = deploy_stack(cfn, "s", _INLINE_TEMPLATE, {}, [], {})
        assert result["action"] == "created"
        cfn.create_stack.assert_called_once()

    def test_updates_existing_stack(self):
        cfn = _cfn_mock("CREATE_COMPLETE")
        result = deploy_stack(cfn, "s", _INLINE_TEMPLATE, {}, [], {})
        assert result["action"] == "updated"
        cfn.update_stack.assert_called_once()

    def test_skips_when_no_update(self):
        from botocore.exceptions import ClientError
        cfn = _cfn_mock("CREATE_COMPLETE")
        cfn.update_stack.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": "No updates are to be performed"}},
            "UpdateStack",
        )
        result = deploy_stack(cfn, "s", _INLINE_TEMPLATE, {}, [], {})
        assert result["action"] == "skipped"

    def test_raises_on_failed_stack(self):
        cfn = _cfn_mock("ROLLBACK_COMPLETE")
        with pytest.raises(RuntimeError, match="ROLLBACK_COMPLETE"):
            deploy_stack(cfn, "s", _INLINE_TEMPLATE, {}, [], {})

    def test_raises_on_in_progress_stack(self):
        cfn = _cfn_mock("CREATE_IN_PROGRESS")
        with pytest.raises(RuntimeError, match="CREATE_IN_PROGRESS"):
            deploy_stack(cfn, "s", _INLINE_TEMPLATE, {}, [], {})

    def test_termination_protection_passed_on_create(self):
        cfn = MagicMock()
        from botocore.exceptions import ClientError
        cfn.describe_stacks.side_effect = ClientError(
            {"Error": {"Code": "ValidationError", "Message": "does not exist"}},
            "DescribeStacks",
        )
        deploy_stack(cfn, "s", _INLINE_TEMPLATE, {}, [], {}, termination_protection=True)
        _, kwargs = cfn.create_stack.call_args
        assert kwargs["EnableTerminationProtection"] is True


# ===========================================================================
# Group 4: poll_stack
# ===========================================================================

class TestPollStack:
    def test_succeeds_immediately(self):
        cfn = _cfn_mock("CREATE_COMPLETE")
        result = poll_stack(cfn, "s", timeout=30, poll_interval=0)
        assert result["StackStatus"] == "CREATE_COMPLETE"

    def test_waits_then_succeeds(self):
        cfn = MagicMock()
        cfn.describe_stacks.side_effect = [
            {"Stacks": [{"StackStatus": "CREATE_IN_PROGRESS"}]},
            {"Stacks": [{"StackStatus": "CREATE_IN_PROGRESS"}]},
            {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "StackName": "s"}]},
            # poll_stack calls describe_stacks again directly to return the full dict
            {"Stacks": [{"StackStatus": "CREATE_COMPLETE", "StackName": "s"}]},
        ]
        result = poll_stack(cfn, "s", timeout=30, poll_interval=0)
        assert result["StackStatus"] == "CREATE_COMPLETE"

    def test_raises_on_failure_status(self):
        cfn = _cfn_mock("CREATE_FAILED")
        with pytest.raises(RuntimeError, match="CREATE_FAILED"):
            poll_stack(cfn, "s", timeout=30, poll_interval=0)

    def test_timeout(self):
        cfn = _cfn_mock("CREATE_IN_PROGRESS")
        with pytest.raises(TimeoutError):
            poll_stack(cfn, "s", timeout=0, poll_interval=0)


# ===========================================================================
# Group 5: blueprint list command
# ===========================================================================

class TestBlueprintListCommand:
    def test_no_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "standstill.commands.blueprint._BLUEPRINTS_DIR", tmp_path / "nonexistent"
        )
        result = runner.invoke(app, ["blueprint", "list"])
        assert result.exit_code == 0
        assert "No blueprints directory" in result.output

    def test_empty_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr("standstill.commands.blueprint._BLUEPRINTS_DIR", tmp_path)
        result = runner.invoke(app, ["blueprint", "list"])
        assert result.exit_code == 0
        assert "No blueprint files" in result.output

    def test_mixed_valid_and_invalid(self, tmp_path, monkeypatch):
        monkeypatch.setattr("standstill.commands.blueprint._BLUEPRINTS_DIR", tmp_path)
        _write_blueprint(tmp_path)  # valid: net.yaml
        bad = tmp_path / "bad.yaml"
        bad.write_text("stacks: []\n")  # missing name
        result = runner.invoke(app, ["blueprint", "list"])
        assert result.exit_code == 0
        assert "standard-networking" in result.output
        assert "(invalid)" in result.output


# ===========================================================================
# Group 6: blueprint validate command
# ===========================================================================

class TestBlueprintValidateCommand:
    def test_valid_blueprint(self, tmp_path):
        f = _write_blueprint(tmp_path)
        result = runner.invoke(app, ["blueprint", "validate", "--file", str(f)])
        assert result.exit_code == 0
        assert "valid" in result.output
        # rich may truncate the name in the table; check prefix is present
        assert "baseline" in result.output

    def test_invalid_missing_stacks(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("name: test\nstacks: []\n")
        result = runner.invoke(app, ["blueprint", "validate", "--file", str(f)])
        assert result.exit_code == 1
        assert "failed" in result.output.lower()

    def test_missing_template_file(self, tmp_path):
        f = tmp_path / "bp.yaml"
        f.write_text(
            "name: test\nstacks:\n  - stack_name: s\n    template_file: missing.yaml\n"
        )
        result = runner.invoke(app, ["blueprint", "validate", "--file", str(f)])
        assert result.exit_code == 1

    def test_shows_stack_table(self, tmp_path):
        f = tmp_path / "bp.yaml"
        f.write_text(
            "name: multi\nstacks:\n"
            "  - stack_name: stack-one\n    template: 'Resources: {}'\n"
            "  - stack_name: stack-two\n    template: 'Resources: {}'\n"
        )
        result = runner.invoke(app, ["blueprint", "validate", "--file", str(f)])
        assert result.exit_code == 0
        assert "stack-one" in result.output
        assert "stack-two" in result.output


# ===========================================================================
# Group 7: blueprint apply command
# ===========================================================================

class TestBlueprintApplyCommand:
    def test_requires_account_or_ou(self, tmp_path):
        f = _write_blueprint(tmp_path)
        result = runner.invoke(app, ["blueprint", "apply", "--file", str(f)])
        assert result.exit_code == 1
        assert "Provide" in result.output

    def test_account_and_ou_mutually_exclusive(self, tmp_path):
        f = _write_blueprint(tmp_path)
        result = runner.invoke(
            app,
            ["blueprint", "apply", "--file", str(f),
             "--account", "123456789012", "--ou", "ou-ab12-34cd5678"],
        )
        assert result.exit_code == 1
        assert "mutually exclusive" in result.output

    def test_invalid_param_format(self, tmp_path):
        f = _write_blueprint(tmp_path)
        result = runner.invoke(
            app,
            ["blueprint", "apply", "--file", str(f),
             "--account", "123456789012", "--param", "no-equals"],
        )
        assert result.exit_code == 1
        assert "KEY=VALUE" in result.output

    def test_dry_run_account(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with patch(
            "standstill.commands.blueprint.bp_api.apply_blueprint_to_account",
            return_value=[StackResult("baseline-networking", "dry-run")],
        ) as mock_apply:
            result = runner.invoke(
                app,
                ["blueprint", "apply", "--file", str(f),
                 "--account", "123456789012", "--dry-run"],
            )
        assert result.exit_code == 0
        assert mock_apply.call_args.kwargs["dry_run"] is True

    def test_apply_with_yes_skips_confirm(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with patch(
            "standstill.commands.blueprint.bp_api.apply_blueprint_to_account",
            return_value=[StackResult("baseline-networking", "created", "CREATE_COMPLETE")],
        ):
            result = runner.invoke(
                app,
                ["blueprint", "apply", "--file", str(f),
                 "--account", "123456789012", "--yes"],
            )
        assert result.exit_code == 0
        assert "CREATED" in result.output

    def test_apply_confirms_without_yes(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with patch(
            "standstill.commands.blueprint.bp_api.apply_blueprint_to_account",
            return_value=[StackResult("baseline-networking", "created", "CREATE_COMPLETE")],
        ):
            result = runner.invoke(
                app,
                ["blueprint", "apply", "--file", str(f), "--account", "123456789012"],
                input="y\n",
            )
        assert result.exit_code == 0

    def test_param_override_passed_through(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with patch(
            "standstill.commands.blueprint.bp_api.apply_blueprint_to_account",
            return_value=[StackResult("baseline-networking", "created", "CREATE_COMPLETE")],
        ) as mock_apply:
            runner.invoke(
                app,
                ["blueprint", "apply", "--file", str(f),
                 "--account", "123456789012", "--yes",
                 "--param", "VpcCidr=10.2.0.0/16"],
            )
        assert mock_apply.call_args.kwargs["param_overrides"] == {"VpcCidr": "10.2.0.0/16"}

    def test_partial_failure_exits_1(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with patch(
            "standstill.commands.blueprint.bp_api.apply_blueprint_to_account",
            return_value=[StackResult("baseline-networking", "failed", error="Role error")],
        ):
            result = runner.invoke(
                app,
                ["blueprint", "apply", "--file", str(f),
                 "--account", "123456789012", "--yes"],
            )
        assert result.exit_code == 1

    def test_apply_ou_fetches_accounts(self, tmp_path):
        f = _write_blueprint(tmp_path)
        ou_detail = {"Accounts": [
            {"Id": "111111111111", "Status": "ACTIVE"},
            {"Id": "222222222222", "Status": "ACTIVE"},
            {"Id": "333333333333", "Status": "SUSPENDED"},  # excluded
        ]}
        with (
            patch("standstill.commands.blueprint.af_api.describe_ou", return_value=ou_detail),
            patch(
                "standstill.commands.blueprint.bp_api.apply_blueprint_to_account",
                return_value=[StackResult("baseline-networking", "created", "CREATE_COMPLETE")],
            ) as mock_apply,
        ):
            runner.invoke(
                app,
                ["blueprint", "apply", "--file", str(f),
                 "--ou", "ou-ab12-34cd5678", "--yes"],
            )
        # Only the two ACTIVE accounts
        assert mock_apply.call_count == 2
        called_ids = {c.kwargs["account_id"] for c in mock_apply.call_args_list}
        assert called_ids == {"111111111111", "222222222222"}


# ===========================================================================
# Group 8: accounts create --blueprint
# ===========================================================================

class TestAccountsCreateWithBlueprint:
    def test_blueprint_applied_after_success(self, tmp_path):
        f = _write_blueprint(tmp_path)
        op_result = {"status": "SUCCEEDED"}
        with (
            patch("standstill.commands.accounts.af_api.create_managed_account", return_value="op-1"),
            patch("standstill.commands.accounts._poll_with_progress", return_value=op_result),
            patch("standstill.commands.accounts.af_api.find_account_by_email", return_value="123456789012"),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account",
                  return_value=[StackResult("baseline-networking", "created", "CREATE_COMPLETE")]) as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "create",
                "--name", "TestAccount", "--email", "test@example.com",
                "--ou", "ou-ab12-34cd5678",
                "--blueprint", str(f),
            ])
        assert result.exit_code == 0
        mock_apply.assert_called_once()
        assert mock_apply.call_args.kwargs["account_id"] == "123456789012"

    def test_blueprint_skipped_on_ct_failure(self, tmp_path):
        f = _write_blueprint(tmp_path)
        op_result = {"status": "FAILED", "statusMessage": "quota exceeded"}
        with (
            patch("standstill.commands.accounts.af_api.create_managed_account", return_value="op-1"),
            patch("standstill.commands.accounts._poll_with_progress", return_value=op_result),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account") as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "create",
                "--name", "TestAccount", "--email", "test@example.com",
                "--ou", "ou-ab12-34cd5678",
                "--blueprint", str(f),
            ])
        assert result.exit_code == 1
        mock_apply.assert_not_called()

    def test_blueprint_ignored_with_no_wait(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with (
            patch("standstill.commands.accounts.af_api.create_managed_account", return_value="op-1"),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account") as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "create",
                "--name", "TestAccount", "--email", "test@example.com",
                "--ou", "ou-ab12-34cd5678",
                "--no-wait", "--blueprint", str(f),
            ])
        assert result.exit_code == 0
        assert "ignored" in result.output.lower() or "Warning" in result.output
        mock_apply.assert_not_called()

    def test_blueprint_warns_when_account_not_found(self, tmp_path):
        f = _write_blueprint(tmp_path)
        op_result = {"status": "SUCCEEDED"}
        with (
            patch("standstill.commands.accounts.af_api.create_managed_account", return_value="op-1"),
            patch("standstill.commands.accounts._poll_with_progress", return_value=op_result),
            patch("standstill.commands.accounts.af_api.find_account_by_email", return_value=None),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account") as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "create",
                "--name", "TestAccount", "--email", "test@example.com",
                "--ou", "ou-ab12-34cd5678",
                "--blueprint", str(f),
            ])
        assert result.exit_code == 0
        assert "manually" in result.output.lower()
        mock_apply.assert_not_called()

    def test_create_without_blueprint_unchanged(self):
        op_result = {"status": "SUCCEEDED"}
        with (
            patch("standstill.commands.accounts.af_api.create_managed_account", return_value="op-1"),
            patch("standstill.commands.accounts._poll_with_progress", return_value=op_result),
        ):
            result = runner.invoke(app, [
                "accounts", "create",
                "--name", "TestAccount", "--email", "test@example.com",
                "--ou", "ou-ab12-34cd5678",
            ])
        assert result.exit_code == 0
        assert "created successfully" in result.output


# ===========================================================================
# Group 9: accounts enroll --blueprint
# ===========================================================================

class TestAccountsEnrollWithBlueprint:
    def test_blueprint_applied_after_success(self, tmp_path):
        f = _write_blueprint(tmp_path)
        op_result = {"status": "SUCCEEDED"}
        with (
            patch("standstill.commands.accounts.af_api.register_managed_account", return_value="op-enroll"),
            patch("standstill.commands.accounts._poll_with_progress", return_value=op_result),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account",
                  return_value=[StackResult("baseline-networking", "created", "CREATE_COMPLETE")]) as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "enroll",
                "--account", "123456789012",
                "--ou", "ou-ab12-34cd5678",
                "--blueprint", str(f),
            ])
        assert result.exit_code == 0
        mock_apply.assert_called_once()
        assert mock_apply.call_args.kwargs["account_id"] == "123456789012"

    def test_blueprint_skipped_on_ct_failure(self, tmp_path):
        f = _write_blueprint(tmp_path)
        op_result = {"status": "FAILED", "statusMessage": "already enrolled"}
        with (
            patch("standstill.commands.accounts.af_api.register_managed_account", return_value="op-enroll"),
            patch("standstill.commands.accounts._poll_with_progress", return_value=op_result),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account") as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "enroll",
                "--account", "123456789012",
                "--ou", "ou-ab12-34cd5678",
                "--blueprint", str(f),
            ])
        assert result.exit_code == 1
        mock_apply.assert_not_called()

    def test_blueprint_ignored_with_no_wait(self, tmp_path):
        f = _write_blueprint(tmp_path)
        with (
            patch("standstill.commands.accounts.af_api.register_managed_account", return_value="op-enroll"),
            patch("standstill.commands.accounts.bp_api.apply_blueprint_to_account") as mock_apply,
        ):
            result = runner.invoke(app, [
                "accounts", "enroll",
                "--account", "123456789012",
                "--ou", "ou-ab12-34cd5678",
                "--no-wait", "--blueprint", str(f),
            ])
        assert result.exit_code == 0
        mock_apply.assert_not_called()


# ===========================================================================
# Group 10: find_account_by_email
# ===========================================================================

class TestFindAccountByEmail:
    def _mock_org(self, accounts: list[dict], next_token: str | None = None) -> MagicMock:
        m = MagicMock()
        resp: dict = {"Accounts": accounts}
        if next_token:
            resp["NextToken"] = next_token
        m.list_accounts_for_parent.return_value = resp
        return m

    def test_found(self):
        from standstill.aws.account_factory import find_account_by_email
        mock_org = self._mock_org([{"Id": "111122223333", "Email": "test@example.com", "Status": "ACTIVE"}])
        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            result = find_account_by_email("test@example.com", "ou-ab12-34cd5678")
        assert result == "111122223333"

    def test_case_insensitive(self):
        from standstill.aws.account_factory import find_account_by_email
        mock_org = self._mock_org([{"Id": "111122223333", "Email": "TEST@EXAMPLE.COM", "Status": "ACTIVE"}])
        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            result = find_account_by_email("test@example.com", "ou-ab12-34cd5678")
        assert result == "111122223333"

    def test_not_found(self):
        from standstill.aws.account_factory import find_account_by_email
        mock_org = self._mock_org([{"Id": "999999999999", "Email": "other@example.com"}])
        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            result = find_account_by_email("missing@example.com", "ou-ab12-34cd5678")
        assert result is None

    def test_paginated(self):
        from standstill.aws.account_factory import find_account_by_email
        mock_org = MagicMock()
        mock_org.list_accounts_for_parent.side_effect = [
            {"Accounts": [{"Id": "111111111111", "Email": "page1@example.com"}], "NextToken": "tok"},
            {"Accounts": [{"Id": "222222222222", "Email": "page2@example.com"}]},
        ]
        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            result = find_account_by_email("page2@example.com", "ou-ab12-34cd5678")
        assert result == "222222222222"
        assert mock_org.list_accounts_for_parent.call_count == 2
