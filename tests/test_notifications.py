"""Tests for standstill/aws/notifications.py and standstill/commands/notifications.py"""
from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

import standstill.aws.notifications as notify_mod
from standstill import state as _state
from standstill.aws.notifications import EventRule, SNSTopic


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

runner = CliRunner()


def _client_error(code, message="Some error"):
    response = {"Error": {"Code": code, "Message": message}}
    return ClientError(response, "TestOp")


def _make_rule(name="test-rule", state="ENABLED", sources=None):
    sources = sources or ["aws.securityhub"]
    pattern = json.dumps({"source": sources})
    return {
        "Name": name,
        "Arn": f"arn:aws:events:us-east-1:123456789012:rule/{name}",
        "State": state,
        "Description": "Test rule",
        "EventPattern": pattern,
    }


# ---------------------------------------------------------------------------
# list_security_event_rules
# ---------------------------------------------------------------------------

class TestListSecurityEventRules:
    def test_returns_security_rules(self):
        mock_client = MagicMock()
        mock_client.list_rules.return_value = {
            "Rules": [_make_rule("sec-rule", sources=["aws.securityhub"])]
        }
        mock_client.list_targets_by_rule.return_value = {
            "Targets": [{"Id": "1", "Arn": "arn:aws:sns:us-east-1:123:test-topic"}]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_event_rules("us-east-1")
        assert len(result) == 1
        assert result[0].name == "sec-rule"
        assert len(result[0].target_arns) == 1

    def test_filters_non_security_rules(self):
        mock_client = MagicMock()
        mock_client.list_rules.return_value = {
            "Rules": [
                _make_rule("sec-rule", sources=["aws.securityhub"]),
                {"Name": "other-rule", "Arn": "arn:...", "State": "ENABLED",
                 "Description": "", "EventPattern": json.dumps({"source": ["aws.s3"]})},
            ]
        }
        mock_client.list_targets_by_rule.return_value = {"Targets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_event_rules("us-east-1")
        assert len(result) == 1
        assert result[0].name == "sec-rule"

    def test_empty_when_no_security_rules(self):
        mock_client = MagicMock()
        mock_client.list_rules.return_value = {"Rules": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_event_rules("us-east-1")
        assert result == []

    def test_pagination(self):
        mock_client = MagicMock()
        mock_client.list_rules.side_effect = [
            {"Rules": [_make_rule("rule1", sources=["aws.guardduty"])], "NextToken": "tok"},
            {"Rules": [_make_rule("rule2", sources=["aws.securityhub"])]},
        ]
        mock_client.list_targets_by_rule.return_value = {"Targets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_event_rules("us-east-1")
        assert len(result) == 2

    def test_includes_all_security_sources(self):
        mock_client = MagicMock()
        all_sources = ["aws.guardduty", "aws.macie2", "aws.inspector2", "aws.access-analyzer"]
        mock_client.list_rules.return_value = {
            "Rules": [_make_rule("multi-rule", sources=all_sources)]
        }
        mock_client.list_targets_by_rule.return_value = {"Targets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_event_rules("us-east-1")
        assert len(result) == 1

    def test_handles_missing_pattern(self):
        mock_client = MagicMock()
        mock_client.list_rules.return_value = {
            "Rules": [{"Name": "no-pattern", "Arn": "", "State": "ENABLED", "Description": ""}]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_event_rules("us-east-1")
        assert result == []


# ---------------------------------------------------------------------------
# list_security_sns_topics
# ---------------------------------------------------------------------------

class TestListSecuritySnsTopics:
    def test_returns_security_topics(self):
        mock_client = MagicMock()
        mock_client.list_topics.return_value = {
            "Topics": [{"TopicArn": "arn:aws:sns:us-east-1:123:security-alerts"}]
        }
        mock_client.get_topic_attributes.return_value = {
            "Attributes": {"DisplayName": "security-alerts"}
        }
        mock_client.list_subscriptions_by_topic.return_value = {"Subscriptions": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_sns_topics("us-east-1")
        assert len(result) == 1
        assert result[0].name == "security-alerts"

    def test_filters_non_security_topics(self):
        mock_client = MagicMock()
        mock_client.list_topics.return_value = {
            "Topics": [
                {"TopicArn": "arn:aws:sns:us-east-1:123:security-findings"},
                {"TopicArn": "arn:aws:sns:us-east-1:123:billing-reports"},
            ]
        }

        def get_attrs(TopicArn):
            name = TopicArn.split(":")[-1]
            return {"Attributes": {"DisplayName": name}}

        mock_client.get_topic_attributes.side_effect = get_attrs
        mock_client.list_subscriptions_by_topic.return_value = {"Subscriptions": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_sns_topics("us-east-1")
        # Only security-findings should match
        assert len(result) == 1
        assert "security" in result[0].name

    def test_includes_subscriptions(self):
        mock_client = MagicMock()
        mock_client.list_topics.return_value = {
            "Topics": [{"TopicArn": "arn:aws:sns:us-east-1:123:guardduty-alerts"}]
        }
        mock_client.get_topic_attributes.return_value = {
            "Attributes": {"DisplayName": "guardduty-alerts"}
        }
        mock_client.list_subscriptions_by_topic.return_value = {
            "Subscriptions": [
                {
                    "Protocol": "email",
                    "Endpoint": "test@example.com",
                    "SubscriptionArn": "arn:...:sub-123",
                }
            ]
        }
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_sns_topics("us-east-1")
        assert len(result[0].subscriptions) == 1
        assert result[0].subscriptions[0]["Protocol"] == "email"

    def test_empty_when_no_topics(self):
        mock_client = MagicMock()
        mock_client.list_topics.return_value = {"Topics": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = notify_mod.list_security_sns_topics("us-east-1")
        assert result == []


# ---------------------------------------------------------------------------
# create_finding_rule
# ---------------------------------------------------------------------------

class TestCreateFindingRule:
    def test_creates_securityhub_rule_with_severity(self):
        mock_client = MagicMock()
        mock_client.put_rule.return_value = {
            "RuleArn": "arn:aws:events:us-east-1:123:rule/sec-rule"
        }
        mock_client.put_targets.return_value = {"FailedEntryCount": 0}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            rule = notify_mod.create_finding_rule(
                name="sec-rule",
                sources=["aws.securityhub"],
                topic_arn="arn:aws:sns:us-east-1:123:sec-topic",
                severity_labels=["CRITICAL", "HIGH"],
                region="us-east-1",
            )
        assert rule.name == "sec-rule"
        assert rule.state == "ENABLED"
        # Check pattern includes severity
        pattern = json.loads(rule.event_pattern)
        assert pattern["source"] == ["aws.securityhub"]
        assert "detail" in pattern

    def test_creates_guardduty_rule(self):
        mock_client = MagicMock()
        mock_client.put_rule.return_value = {"RuleArn": "arn:aws:events:us-east-1:123:rule/gd-rule"}
        mock_client.put_targets.return_value = {"FailedEntryCount": 0}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            rule = notify_mod.create_finding_rule(
                name="gd-rule",
                sources=["aws.guardduty"],
                topic_arn="arn:aws:sns:us-east-1:123:topic",
                severity_labels=None,
                region="us-east-1",
            )
        pattern = json.loads(rule.event_pattern)
        assert "GuardDuty Finding" in pattern.get("detail-type", [])

    def test_creates_multi_source_rule(self):
        mock_client = MagicMock()
        mock_client.put_rule.return_value = {"RuleArn": "arn:..."}
        mock_client.put_targets.return_value = {"FailedEntryCount": 0}
        sources = ["aws.securityhub", "aws.guardduty"]
        with patch.object(_state.state, "get_client", return_value=mock_client):
            rule = notify_mod.create_finding_rule(
                name="multi-rule",
                sources=sources,
                topic_arn="arn:aws:sns:us-east-1:123:topic",
                severity_labels=None,
                region="us-east-1",
            )
        pattern = json.loads(rule.event_pattern)
        assert set(pattern["source"]) == set(sources)

    def test_target_arn_in_rule(self):
        mock_client = MagicMock()
        topic_arn = "arn:aws:sns:us-east-1:123:my-topic"
        mock_client.put_rule.return_value = {"RuleArn": "arn:..."}
        mock_client.put_targets.return_value = {"FailedEntryCount": 0}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            rule = notify_mod.create_finding_rule("r", ["aws.securityhub"], topic_arn, None, "us-east-1")
        assert topic_arn in rule.target_arns


# ---------------------------------------------------------------------------
# Command tests
# ---------------------------------------------------------------------------

class TestNotifyCommands:
    def test_status_command(self):
        from standstill.commands.notifications import app as notify_app

        mock_client = MagicMock()
        mock_client.list_rules.return_value = {"Rules": []}
        mock_client.list_topics.return_value = {"Topics": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(notify_app, ["status"])
        assert result.exit_code == 0

    def test_list_command_no_rules(self):
        from standstill.commands.notifications import app as notify_app

        mock_client = MagicMock()
        mock_client.list_rules.return_value = {"Rules": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(notify_app, ["list"])
        assert result.exit_code == 0
        assert "No security-related" in result.output

    def test_list_command_with_rules(self):
        from standstill.commands.notifications import app as notify_app

        mock_client = MagicMock()
        mock_client.list_rules.return_value = {
            "Rules": [_make_rule("sec-rule", sources=["aws.securityhub"])]
        }
        mock_client.list_targets_by_rule.return_value = {"Targets": []}
        with patch.object(_state.state, "get_client", return_value=mock_client):
            result = runner.invoke(notify_app, ["list"])
        assert result.exit_code == 0
