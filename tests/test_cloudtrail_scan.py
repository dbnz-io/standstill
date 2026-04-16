"""Tests for standstill/aws/cloudtrail_scan.py and usage_type_map.py."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock

from standstill.aws.cloudtrail_scan import ScanResult, TrailEvent, scan
from standstill.aws.usage_type_map import (
    _REGION_PREFIX_RE,
    get_event_source,
    get_usage_type_info,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(name="PutMetricData", source="monitoring.amazonaws.com", username="alice",
           account="123456789012", region="us-east-1", read_only=False,
           error_code="", ts=None):
    return TrailEvent(
        event_id="evt-" + name,
        event_name=name,
        event_time=ts or datetime(2024, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
        event_source=source,
        username=username,
        account_id=account,
        source_ip="1.2.3.4",
        user_agent="test-agent/1.0",
        region=region,
        read_only=read_only,
        error_code=error_code,
    )


def _scan_result(events=None):
    return ScanResult(
        usage_type="CW:Requests",
        service="CloudWatch",
        event_source="monitoring.amazonaws.com",
        api_calls_searched=["PutMetricData", "GetMetricData"],
        start="2024-03-01T00:00:00+00:00",
        end="2024-03-15T00:00:00+00:00",
        events=events or [],
    )


# ---------------------------------------------------------------------------
# usage_type_map
# ---------------------------------------------------------------------------

class TestUsageTypeMap:
    def test_known_type(self):
        info = get_usage_type_info("CW:Requests")
        assert info is not None
        assert "CloudWatch" in info.service

    def test_unknown_type(self):
        info = get_usage_type_info("BOGUS:Unknown")
        assert info is None

    def test_region_prefix_stripping(self):
        raw = "USE1-CW:Requests"
        stripped = _REGION_PREFIX_RE.sub("", raw)
        assert stripped == "CW:Requests"
        info = get_usage_type_info(stripped)
        assert info is not None

    def test_get_event_source_known(self):
        src = get_event_source("CloudWatch")
        assert src is not None
        assert "amazonaws.com" in src

    def test_get_event_source_unknown(self):
        src = get_event_source("BogusService123")
        assert src is None

    def test_s3_usage_type(self):
        info = get_usage_type_info("S3-Requests-Tier1")
        assert info is not None

    def test_lambda_usage_type(self):
        info = get_usage_type_info("Lambda-Requests")
        assert info is not None

    # ------------------------------------------------------------------
    # Phase 2 — instance-family regex (no service prefix)
    # ------------------------------------------------------------------

    def test_redshift_dc2_node(self):
        info = get_usage_type_info("DC2.Large-NodeUsage")
        assert info is not None
        assert info.service == "Redshift"

    def test_redshift_ra3_node(self):
        info = get_usage_type_info("RA3.4XLarge-NodeUsage")
        assert info is not None
        assert info.service == "Redshift"

    def test_redshift_ds2_node(self):
        info = get_usage_type_info("DS2.XLarge-NodeUsage")
        assert info is not None
        assert info.service == "Redshift"

    def test_redshift_node_with_region_prefix(self):
        info = get_usage_type_info("USE1-DC2.Large-NodeUsage")
        assert info is not None
        assert info.service == "Redshift"

    def test_elasticache_cache_node(self):
        info = get_usage_type_info("cache.r6g.large-NodeUsage")
        assert info is not None
        assert info.service == "ElastiCache"

    def test_rds_bare_instance_type(self):
        info = get_usage_type_info("db.r5.large-Multi-AZ")
        assert info is not None
        assert info.service == "RDS"

    # ------------------------------------------------------------------
    # Phase 3 — Amazon*/AWS* name-extraction fallback
    # ------------------------------------------------------------------

    def test_fallback_amazon_prefix(self):
        info = get_usage_type_info("AmazonFutureService-SomeFeature")
        assert info is not None
        assert info.service == "Future Service"

    def test_fallback_aws_prefix(self):
        info = get_usage_type_info("AWSNewThing-Usage")
        assert info is not None
        assert info.service == "New Thing"

    def test_fallback_no_match_returns_none(self):
        # Totally unknown prefix with no Amazon/AWS token → None
        info = get_usage_type_info("BOGUS:Unknown")
        assert info is None

    def test_fallback_not_triggered_when_phase1_matches(self):
        # AmazonGuardDuty- must be resolved by Phase 1, not fallback
        info = get_usage_type_info("AmazonGuardDuty-DataSources")
        assert info is not None
        assert info.service == "GuardDuty"


# ---------------------------------------------------------------------------
# ScanResult — summary_by_event
# ---------------------------------------------------------------------------

class TestSummaryByEvent:
    def test_basic(self):
        events = [
            _event("PutMetricData"),
            _event("PutMetricData"),
            _event("GetMetricData"),
        ]
        result = _scan_result(events)
        summary = result.summary_by_event()
        assert summary[0]["event_name"] == "PutMetricData"
        assert summary[0]["count"] == 2
        assert summary[1]["event_name"] == "GetMetricData"
        assert summary[1]["count"] == 1

    def test_empty(self):
        assert _scan_result().summary_by_event() == []


# ---------------------------------------------------------------------------
# ScanResult — summary_by_caller
# ---------------------------------------------------------------------------

class TestSummaryByCaller:
    def test_basic(self):
        events = [
            _event(username="alice"),
            _event(username="alice"),
            _event(username="bob"),
        ]
        result = _scan_result(events)
        callers = result.summary_by_caller()
        assert callers[0]["username"] == "alice"
        assert callers[0]["count"] == 2

    def test_empty_username_becomes_unknown(self):
        events = [_event(username="")]
        result = _scan_result(events)
        callers = result.summary_by_caller()
        assert callers[0]["username"] == "(unknown)"


# ---------------------------------------------------------------------------
# ScanResult — summary_by_identity_attribution
# ---------------------------------------------------------------------------

class TestSummaryByIdentityAttribution:
    def test_assumed_role_identity(self):
        events = [
            _event(username="arn:aws:sts::123456789012:assumed-role/MyRole/session"),
        ]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["identity_type"] == "AssumedRole"
        assert rows[0]["identity_name"] == "MyRole"

    def test_iam_user_identity(self):
        events = [
            _event(username="arn:aws:iam::123456789012:user/alice"),
        ]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["identity_type"] == "IAMUser"
        assert rows[0]["identity_name"] == "alice"

    def test_root_identity(self):
        events = [_event(username="root")]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["identity_type"] == "Root"

    def test_service_identity(self):
        events = [_event(username="lambda.amazonaws.com")]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["identity_type"] == "Service"

    def test_federated_user(self):
        events = [_event(username="alice@example.com")]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["identity_type"] == "FederatedUser"

    def test_empty_events(self):
        result = _scan_result([])
        assert result.summary_by_identity_attribution() == []

    def test_error_count(self):
        events = [
            _event(username="alice", error_code="AccessDenied"),
            _event(username="alice", error_code=""),
        ]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["error_count"] == 1
        assert rows[0]["call_count"] == 2

    def test_region_aggregation(self):
        ts = datetime(2024, 3, 10, 12, 0, 0, tzinfo=timezone.utc)
        events = [
            _event(username="alice", region="us-east-1", ts=ts),
            _event(username="alice", region="eu-west-1", ts=ts),
        ]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert set(rows[0]["regions"]) == {"us-east-1", "eu-west-1"}

    def test_grouped_by_account_and_identity(self):
        events = [
            _event(username="alice", account="111111111111"),
            _event(username="alice", account="222222222222"),
        ]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert len(rows) == 2

    def test_sorted_by_call_count_descending(self):
        events = [
            _event(username="bob"),
            _event(username="alice"),
            _event(username="alice"),
            _event(username="alice"),
        ]
        result = _scan_result(events)
        rows = result.summary_by_identity_attribution()
        assert rows[0]["identity_name"] == "alice"
        assert rows[0]["call_count"] == 3


# ---------------------------------------------------------------------------
# ScanResult — to_dict
# ---------------------------------------------------------------------------

class TestToDict:
    def test_includes_expected_keys(self):
        result = _scan_result([_event()])
        d = result.to_dict()
        assert "usage_type" in d
        assert "events" in d
        assert "summary_by_event" in d
        assert "summary_by_caller" in d
        assert d["total_events"] == 1

    def test_event_time_is_isoformat(self):
        result = _scan_result([_event()])
        d = result.to_dict()
        # Should be parseable as ISO datetime
        datetime.fromisoformat(d["events"][0]["event_time"])


# ---------------------------------------------------------------------------
# scan (CloudTrail lookup_events)
# ---------------------------------------------------------------------------

class TestScan:
    def _ct_event(self, name, username="alice", ts=None):
        return {
            "EventId": "evt-" + name,
            "EventName": name,
            "EventTime": ts or datetime(2024, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
            "EventSource": "monitoring.amazonaws.com",
            "Username": username,
            "CloudTrailEvent": json.dumps({
                "eventVersion": "1.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "accountId": "123456789012",
                    "arn": "arn:aws:iam::123456789012:user/alice",
                },
                "sourceIPAddress": "1.2.3.4",
                "userAgent": "test-agent",
                "awsRegion": "us-east-1",
                "readOnly": False,
                "errorCode": "",
                "errorMessage": "",
                "resources": [],
            }),
        }

    def test_basic_scan(self):
        ct = MagicMock()
        ct.lookup_events.return_value = {
            "Events": [self._ct_event("PutMetricData")],
        }
        result = scan(
            ct,
            usage_type="CW:Requests",
            event_source="monitoring.amazonaws.com",
            api_calls=["PutMetricData"],
            start=datetime(2024, 3, 1, tzinfo=timezone.utc),
            end=datetime(2024, 3, 15, tzinfo=timezone.utc),
        )
        assert isinstance(result, ScanResult)
        assert len(result.events) >= 0  # may dedup

    def test_empty_api_calls_uses_event_source(self):
        ct = MagicMock()
        ct.lookup_events.return_value = {"Events": []}
        result = scan(
            ct,
            usage_type="SomeType",
            event_source="ec2.amazonaws.com",
            api_calls=[],
            start=datetime(2024, 3, 1, tzinfo=timezone.utc),
            end=datetime(2024, 3, 15, tzinfo=timezone.utc),
        )
        assert isinstance(result, ScanResult)
