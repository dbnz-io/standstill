"""Tests for the production-readiness pass: CLI error boundary, the notify
setup wizard (incl. the SNS topic-policy wiring), and the SNS policy helper."""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError, ProfileNotFound
from typer.testing import CliRunner

from standstill.main import app

runner = CliRunner()


# ---------------------------------------------------------------------------
# main() global error boundary
# ---------------------------------------------------------------------------

class TestErrorBoundary:
    def _run_main_raising(self, exc):
        import standstill.main as m
        with patch.object(m, "app", side_effect=exc):
            with pytest.raises(SystemExit) as ei:
                m.main()
        return ei.value.code

    def test_runtime_error_exits_1(self):
        assert self._run_main_raising(RuntimeError("boom")) == 1

    def test_profile_not_found_exits_1(self):
        assert self._run_main_raising(ProfileNotFound(profile="x")) == 1

    def test_client_error_exits_1(self):
        err = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "Op")
        assert self._run_main_raising(err) == 1

    def test_keyboard_interrupt_exits_130(self):
        assert self._run_main_raising(KeyboardInterrupt()) == 130

    def test_records_audit_on_exit(self):
        import standstill.main as m
        with patch.object(m, "app", side_effect=SystemExit(2)), patch.object(
            m, "_record_audit"
        ) as rec:
            with pytest.raises(SystemExit):
                m.main()
        rec.assert_called_once_with(2)

    def test_records_audit_on_error(self):
        import standstill.main as m
        with patch.object(m, "app", side_effect=RuntimeError("boom")), patch.object(
            m, "_record_audit"
        ) as rec:
            with pytest.raises(SystemExit):
                m.main()
        rec.assert_called_once_with(1)


# ---------------------------------------------------------------------------
# audit log
# ---------------------------------------------------------------------------

class TestAuditLog:
    def test_writes_jsonl_record(self, tmp_path, monkeypatch):
        from standstill import audit

        log = tmp_path / "audit.log"
        monkeypatch.setenv("STANDSTILL_AUDIT_LOG", str(log))
        audit.record_invocation(["scp", "detach", "-n", "X"], 0, profile="prod", region="us-east-1")
        audit.record_invocation(["sso", "assign"], 1, profile="prod", region="us-east-1")

        lines = log.read_text().strip().splitlines()
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["args"] == ["scp", "detach", "-n", "X"]
        assert first["exit_code"] == 0
        assert first["profile"] == "prod"
        assert "ts" in first

    def test_best_effort_never_raises(self, monkeypatch):
        from standstill import audit

        # Point at an unwritable path — must swallow the error, not raise.
        monkeypatch.setenv("STANDSTILL_AUDIT_LOG", "/nonexistent-root-dir/x/y/audit.log")
        audit.record_invocation(["view", "ous"], 0)  # should not raise

    def test_path_override(self, tmp_path, monkeypatch):
        from standstill import audit

        monkeypatch.setenv("STANDSTILL_AUDIT_LOG", str(tmp_path / "custom.log"))
        assert audit.audit_path() == tmp_path / "custom.log"

    def test_clean_message_formats_client_error(self):
        from standstill.main import _clean_message
        err = ClientError({"Error": {"Code": "AccessDenied", "Message": "nope"}}, "Op")
        msg = _clean_message(err)
        assert "nope" in msg and "AccessDenied" in msg

    def test_clean_message_plain_exception(self):
        from standstill.main import _clean_message
        assert _clean_message(RuntimeError("just this")) == "just this"


# ---------------------------------------------------------------------------
# notify setup wizard — validates the SNS topic-policy is actually applied
# ---------------------------------------------------------------------------

class TestNotifySetup:
    def test_setup_applies_topic_policy(self):
        from standstill.aws.notifications import EventRule

        topic_arn = "arn:aws:sns:us-east-1:111111111111:security-findings"
        rule = EventRule(
            name="security-findings-rule",
            arn="arn:aws:events:us-east-1:111111111111:rule/security-findings-rule",
            state="ENABLED",
            description="",
            event_pattern="{}",
            target_arns=[topic_arn],
        )

        with patch("standstill.commands.notifications.notify_api") as api:
            api.create_sns_topic.return_value = topic_arn
            api.create_finding_rule.return_value = rule
            api.set_eventbridge_publish_policy.return_value = {"Sid": "AllowEventBridgePublish"}

            # sources: only GuardDuty; create topic (default name); no email; default rule name
            result = runner.invoke(
                app,
                ["notify", "setup"],
                input="n\ny\nn\nn\nn\ny\n\nn\n\n",
            )

        assert result.exit_code == 0, result.output
        api.set_eventbridge_publish_policy.assert_called_once_with(
            topic_arn=topic_arn, rule_arn=rule.arn
        )
        assert "Setup complete" in result.output

    def test_setup_policy_failure_exits_nonzero(self):
        from standstill.aws.notifications import EventRule

        topic_arn = "arn:aws:sns:us-east-1:111111111111:security-findings"
        rule = EventRule(
            name="security-findings-rule",
            arn="arn:aws:events:us-east-1:111111111111:rule/r",
            state="ENABLED",
            description="",
            event_pattern="{}",
            target_arns=[topic_arn],
        )

        with patch("standstill.commands.notifications.notify_api") as api:
            api.create_sns_topic.return_value = topic_arn
            api.create_finding_rule.return_value = rule
            api.set_eventbridge_publish_policy.side_effect = RuntimeError("access denied")

            result = runner.invoke(
                app,
                ["notify", "setup"],
                input="n\ny\nn\nn\nn\ny\n\nn\n\n",
            )

        # The rule exists but delivery is not wired — must not report clean success.
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# set_eventbridge_publish_policy helper
# ---------------------------------------------------------------------------

class TestSetPublishPolicy:
    def test_merges_statement_into_existing_policy(self):
        from standstill.aws.notifications import set_eventbridge_publish_policy

        existing = {
            "Version": "2008-10-17",
            "Statement": [{"Sid": "Owner", "Effect": "Allow", "Action": "SNS:*"}],
        }
        sns = MagicMock()
        sns.get_topic_attributes.return_value = {"Attributes": {"Policy": json.dumps(existing)}}

        with patch(
            "standstill.aws.notifications._state.state.get_client", return_value=sns
        ):
            set_eventbridge_publish_policy("arn:topic", "arn:rule")

        _, kwargs = sns.set_topic_attributes.call_args
        written = json.loads(kwargs["AttributeValue"])
        sids = [s["Sid"] for s in written["Statement"]]
        assert "Owner" in sids
        assert sids.count("AllowEventBridgePublish") == 1

    def test_idempotent_replaces_prior_statement(self):
        from standstill.aws.notifications import set_eventbridge_publish_policy

        existing = {
            "Version": "2008-10-17",
            "Statement": [
                {"Sid": "AllowEventBridgePublish", "Effect": "Allow", "Action": "sns:Publish"}
            ],
        }
        sns = MagicMock()
        sns.get_topic_attributes.return_value = {"Attributes": {"Policy": json.dumps(existing)}}

        with patch(
            "standstill.aws.notifications._state.state.get_client", return_value=sns
        ):
            set_eventbridge_publish_policy("arn:topic", "arn:rule")

        _, kwargs = sns.set_topic_attributes.call_args
        written = json.loads(kwargs["AttributeValue"])
        sids = [s["Sid"] for s in written["Statement"]]
        assert sids.count("AllowEventBridgePublish") == 1

    def test_handles_empty_policy(self):
        from standstill.aws.notifications import set_eventbridge_publish_policy

        sns = MagicMock()
        sns.get_topic_attributes.return_value = {"Attributes": {}}

        with patch(
            "standstill.aws.notifications._state.state.get_client", return_value=sns
        ):
            stmt = set_eventbridge_publish_policy("arn:topic", "arn:rule")

        assert stmt["Sid"] == "AllowEventBridgePublish"
        sns.set_topic_attributes.assert_called_once()


# ---------------------------------------------------------------------------
# SSO commands — the assign/unassign write lifecycle (ROADMAP #8c) was untested
# ---------------------------------------------------------------------------

def _sso_instance():
    from standstill.aws.sso import SSOInstance
    return SSOInstance(instance_arn="arn:sso", identity_store_id="d-123", name="Test")


def _permission_set():
    from standstill.aws.sso import PermissionSet
    return PermissionSet(
        arn="arn:ps", name="Admin", description="", session_duration="PT1H",
        created_date=None,
    )


def _assignment():
    from standstill.aws.sso import AccountAssignment
    return AccountAssignment(
        account_id="111122223333", account_name="Prod", permission_set_arn="arn:ps",
        permission_set_name="Admin", principal_id="user-1", principal_name="alice",
        principal_type="USER",
    )


class TestSsoCommands:
    def _patch_api(self):
        return patch("standstill.commands.sso.sso_api")

    def test_assign_success(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.find_permission_set_by_name.return_value = _permission_set()
            api.resolve_principal_id.return_value = "user-1"
            api.create_assignment.return_value = {"RequestId": "req-1"}
            api.poll_assignment_status.return_value = "SUCCEEDED"
            result = runner.invoke(
                app, ["sso", "assign", "-a", "111122223333", "-p", "Admin", "-u", "alice"]
            )
        assert result.exit_code == 0, result.output
        api.create_assignment.assert_called_once()
        assert "created successfully" in result.output

    def test_assign_timeout_exits_2(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.find_permission_set_by_name.return_value = _permission_set()
            api.resolve_principal_id.return_value = "user-1"
            api.create_assignment.return_value = {"RequestId": "req-1"}
            api.poll_assignment_status.return_value = "IN_PROGRESS"
            result = runner.invoke(
                app, ["sso", "assign", "-a", "111122223333", "-p", "Admin", "-u", "alice"]
            )
        # Not confirmed within the window must not read as success.
        assert result.exit_code == 2

    def test_assign_failed_poll_exits_1(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.find_permission_set_by_name.return_value = _permission_set()
            api.resolve_principal_id.return_value = "user-1"
            api.create_assignment.return_value = {"RequestId": "req-1"}
            api.poll_assignment_status.return_value = "FAILED"
            result = runner.invoke(
                app, ["sso", "assign", "-a", "111122223333", "-p", "Admin", "-u", "alice"]
            )
        assert result.exit_code == 1

    def test_assign_principal_not_found_exits_1(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.find_permission_set_by_name.return_value = _permission_set()
            api.resolve_principal_id.return_value = None
            result = runner.invoke(
                app, ["sso", "assign", "-a", "111122223333", "-p", "Admin", "-u", "ghost"]
            )
        assert result.exit_code == 1
        assert "not found" in result.output

    def test_assign_permission_set_not_found_exits_1(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.find_permission_set_by_name.return_value = None
            result = runner.invoke(
                app, ["sso", "assign", "-a", "111122223333", "-p", "Nope", "-u", "alice"]
            )
        assert result.exit_code == 1

    def test_unassign_success_with_yes(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.find_permission_set_by_name.return_value = _permission_set()
            api.resolve_principal_id.return_value = "user-1"
            api.delete_assignment.return_value = {"RequestId": "req-2"}
            api.poll_assignment_status.return_value = "SUCCEEDED"
            result = runner.invoke(
                app,
                ["sso", "unassign", "-a", "111122223333", "-p", "Admin", "-u", "alice", "-y"],
            )
        assert result.exit_code == 0, result.output
        api.delete_assignment.assert_called_once()
        assert "removed successfully" in result.output

    def test_status_no_instance(self):
        with self._patch_api() as api:
            api.get_instance.return_value = None
            result = runner.invoke(app, ["sso", "status"])
        assert result.exit_code == 0
        assert "No SSO instance" in result.output

    def test_status_success(self):
        with self._patch_api() as api, patch(
            "standstill.aws.organizations.build_ou_tree", return_value=[]
        ), patch("standstill.aws.organizations.all_accounts", return_value=[]):
            api.get_instance.return_value = _sso_instance()
            api.list_permission_sets.return_value = [_permission_set()]
            api.list_all_assignments.return_value = [_assignment()]
            result = runner.invoke(app, ["sso", "status"])
        assert result.exit_code == 0, result.output

    def test_status_error_exits_1(self):
        with self._patch_api() as api:
            api.get_instance.side_effect = RuntimeError("access denied")
            result = runner.invoke(app, ["sso", "status"])
        assert result.exit_code == 1

    def test_list_permission_sets(self):
        with self._patch_api() as api:
            api.get_instance.return_value = _sso_instance()
            api.list_permission_sets.return_value = [_permission_set()]
            result = runner.invoke(app, ["sso", "list-permission-sets"])
        assert result.exit_code == 0, result.output
        assert "Admin" in result.output

    def test_audit_renders_assignments(self):
        with self._patch_api() as api, patch(
            "standstill.aws.organizations.build_ou_tree", return_value=[]
        ), patch("standstill.aws.organizations.all_accounts", return_value=[]):
            api.get_instance.return_value = _sso_instance()
            api.list_permission_sets.return_value = [_permission_set()]
            api.list_all_assignments.return_value = [_assignment()]
            result = runner.invoke(app, ["sso", "audit"])
        assert result.exit_code == 0, result.output

    def test_list_all_assignments_raises_on_access_denied(self):
        from botocore.exceptions import ClientError

        from standstill.aws import sso as sso_api
        from standstill.aws.sso import PermissionSet

        client = MagicMock()
        client.list_accounts_for_provisioned_permission_set.side_effect = ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "List"
        )
        ps = PermissionSet(
            arn="arn:ps", name="Admin", description="", session_duration="PT1H",
            created_date=None,
        )
        with patch(
            "standstill.aws.sso._state.state.get_client", return_value=client
        ):
            with pytest.raises(ClientError):
                sso_api.list_all_assignments("arn:sso", "d-1", [ps], {})

    def test_list_assignments_filters_by_account(self):
        with self._patch_api() as api, patch(
            "standstill.aws.organizations.build_ou_tree", return_value=[]
        ), patch("standstill.aws.organizations.all_accounts", return_value=[]):
            api.get_instance.return_value = _sso_instance()
            api.list_permission_sets.return_value = [_permission_set()]
            api.list_all_assignments.return_value = [_assignment()]
            result = runner.invoke(
                app, ["sso", "list-assignments", "-a", "111122223333"]
            )
        assert result.exit_code == 0, result.output
