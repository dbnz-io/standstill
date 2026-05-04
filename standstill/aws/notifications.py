from __future__ import annotations

import json
from dataclasses import dataclass, field

from botocore.exceptions import ClientError

from standstill import state as _state


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class EventRule:
    name: str
    arn: str
    state: str  # "ENABLED" | "DISABLED"
    description: str
    event_pattern: str  # JSON string
    target_arns: list[str] = field(default_factory=list)


@dataclass
class SNSTopic:
    arn: str
    name: str
    subscriptions: list[dict] = field(default_factory=list)  # {Protocol, Endpoint, SubscriptionArn, SubscriptionStatus}


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_SECURITY_SOURCES = [
    "aws.securityhub",
    "aws.guardduty",
    "aws.macie2",
    "aws.inspector2",
    "aws.access-analyzer",
    "aws.securitylake",
]

_SECURITY_TOPIC_KEYWORDS = [
    "security",
    "finding",
    "guardduty",
    "securityhub",
    "alert",
    "alarm",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pattern_has_security_source(pattern_str: str) -> bool:
    """Check if an event pattern JSON string references any security source."""
    if not pattern_str:
        return False
    try:
        pattern = json.loads(pattern_str)
    except (json.JSONDecodeError, ValueError):
        return False
    sources = pattern.get("source", [])
    for src in sources:
        if any(sec_src in src for sec_src in _SECURITY_SOURCES):
            return True
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def list_security_event_rules(region: str) -> list[EventRule]:
    """List EventBridge rules that reference security service sources."""
    client = _state.state.get_client("events")
    rules: list[EventRule] = []
    kwargs: dict = {}
    while True:
        resp = client.list_rules(**kwargs)
        for r in resp.get("Rules", []):
            pattern = r.get("EventPattern", "")
            if _pattern_has_security_source(pattern):
                # Get targets for this rule
                target_arns: list[str] = []
                try:
                    t_kwargs: dict = {"Rule": r["Name"]}
                    while True:
                        t_resp = client.list_targets_by_rule(**t_kwargs)
                        for tgt in t_resp.get("Targets", []):
                            target_arns.append(tgt.get("Arn", ""))
                        t_token = t_resp.get("NextToken")
                        if not t_token:
                            break
                        t_kwargs["NextToken"] = t_token
                except ClientError:
                    pass

                rules.append(EventRule(
                    name=r.get("Name", ""),
                    arn=r.get("Arn", ""),
                    state=r.get("State", ""),
                    description=r.get("Description", ""),
                    event_pattern=pattern,
                    target_arns=target_arns,
                ))
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return rules


def list_security_sns_topics(region: str) -> list[SNSTopic]:
    """List SNS topics whose names suggest they are security-related."""
    client = _state.state.get_client("sns")
    topics: list[SNSTopic] = []
    kwargs: dict = {}
    while True:
        resp = client.list_topics(**kwargs)
        for topic in resp.get("Topics", []):
            arn = topic.get("TopicArn", "")
            # Get topic name from attributes
            try:
                attrs = client.get_topic_attributes(TopicArn=arn)
                topic_name = attrs.get("Attributes", {}).get("DisplayName", "") or arn.split(":")[-1]
            except ClientError:
                topic_name = arn.split(":")[-1]

            # Filter to security-related topics
            name_lower = topic_name.lower()
            arn_lower = arn.lower()
            if not any(kw in name_lower or kw in arn_lower for kw in _SECURITY_TOPIC_KEYWORDS):
                continue

            # Get subscriptions
            subscriptions: list[dict] = []
            try:
                sub_kwargs: dict = {"TopicArn": arn}
                while True:
                    sub_resp = client.list_subscriptions_by_topic(**sub_kwargs)
                    for sub in sub_resp.get("Subscriptions", []):
                        subscriptions.append({
                            "Protocol": sub.get("Protocol", ""),
                            "Endpoint": sub.get("Endpoint", ""),
                            "SubscriptionArn": sub.get("SubscriptionArn", ""),
                            "SubscriptionStatus": (
                                "confirmed" if not sub.get("SubscriptionArn", "").startswith("PendingConfirmation")
                                else "pending"
                            ),
                        })
                    sub_token = sub_resp.get("NextToken")
                    if not sub_token:
                        break
                    sub_kwargs["NextToken"] = sub_token
            except ClientError:
                pass

            topics.append(SNSTopic(arn=arn, name=topic_name, subscriptions=subscriptions))

        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return topics


def create_sns_topic(name: str, region: str) -> str:
    """Create an SNS topic and return its ARN."""
    client = _state.state.get_client("sns")
    resp = client.create_topic(Name=name)
    return resp["TopicArn"]


def subscribe_email(topic_arn: str, email: str) -> str:
    """Subscribe an email address to an SNS topic. Returns the subscription ARN."""
    client = _state.state.get_client("sns")
    resp = client.subscribe(
        TopicArn=topic_arn,
        Protocol="email",
        Endpoint=email,
    )
    return resp.get("SubscriptionArn", "")


def create_finding_rule(
    name: str,
    sources: list[str],
    topic_arn: str,
    severity_labels: list[str] | None,
    region: str,
) -> EventRule:
    """
    Create an EventBridge rule that routes security findings to an SNS topic.

    For Security Hub with severity labels, the pattern uses:
      {"source": ["aws.securityhub"], "detail-type": [...], "detail": {"findings": [{"Severity": {"Label": [...]}}]}}

    For GuardDuty findings:
      {"source": ["aws.guardduty"], "detail-type": ["GuardDuty Finding"]}
    """
    client = _state.state.get_client("events")

    # Build event pattern
    if len(sources) == 1 and sources[0] == "aws.securityhub" and severity_labels:
        pattern = {
            "source": ["aws.securityhub"],
            "detail-type": ["Security Hub Findings - Imported"],
            "detail": {
                "findings": [{"Severity": {"Label": severity_labels}}]
            },
        }
    elif len(sources) == 1 and sources[0] == "aws.guardduty":
        pattern = {
            "source": ["aws.guardduty"],
            "detail-type": ["GuardDuty Finding"],
        }
    else:
        # Generic multi-source pattern
        pattern_dict: dict = {"source": sources}
        if severity_labels:
            pattern_dict["detail"] = {
                "findings": [{"Severity": {"Label": severity_labels}}]
            }
        pattern = pattern_dict

    pattern_str = json.dumps(pattern)

    # Create the rule
    rule_resp = client.put_rule(
        Name=name,
        EventPattern=pattern_str,
        State="ENABLED",
        Description=f"Security findings routing rule for: {', '.join(sources)}",
    )
    rule_arn = rule_resp.get("RuleArn", "")

    # Add SNS topic as target
    client.put_targets(
        Rule=name,
        Targets=[
            {
                "Id": "SecurityFindingsTopic",
                "Arn": topic_arn,
            }
        ],
    )

    return EventRule(
        name=name,
        arn=rule_arn,
        state="ENABLED",
        description=f"Security findings routing rule",
        event_pattern=pattern_str,
        target_arns=[topic_arn],
    )


def enable_rule(rule_name: str) -> None:
    """Enable an EventBridge rule."""
    client = _state.state.get_client("events")
    client.enable_rule(Name=rule_name)


def disable_rule(rule_name: str) -> None:
    """Disable an EventBridge rule."""
    client = _state.state.get_client("events")
    client.disable_rule(Name=rule_name)
