"""Tests for standstill/display/renderer.py — verify all render functions run without error."""
from __future__ import annotations

from datetime import datetime, timezone
from io import StringIO

import pytest
from rich.console import Console

from standstill.aws.budgets import Budget
from standstill.aws.cloudtrail_scan import ScanResult, TrailEvent
from standstill.aws.config_recorder import RecorderResult, RecorderState
from standstill.aws.controltower import Control, EnabledControl
from standstill.aws.cost import Anomaly, CostGroup, CostPeriod
from standstill.aws.optimize import RightsizingRecommendation, RISummary, SavingsPlansSummary
from standstill.aws.organizations import Account, OUNode
from standstill.aws.security_services import (
    AccountAssessment,
    DelegationStatus,
    MemberServiceStatus,
    ServiceApplyResult,
    ServiceStatus,
)
from standstill.display import renderer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def test_console(monkeypatch):
    """Replace the module-level console with a silent test console."""
    silent = Console(file=StringIO(), width=120)
    monkeypatch.setattr(renderer, "console", silent)
    return silent


def _account(aid="123456789012", name="MyAccount", ou="Security"):
    return Account(id=aid, arn=f"arn:aws:organizations:::{aid}", name=name,
                   email="t@t.com", status="ACTIVE", ou_id="ou-1", ou_name=ou)


def _ou_node(name="SecurityOU", num_accounts=2):
    node = OUNode(id="ou-abc123", arn="arn:aws:organizations:::ou/o-1/ou-abc123",
                  name=name, parent_id=None)
    node.accounts = [_account(f"1{'0'*11}{i}", f"Acct{i}") for i in range(num_accounts)]
    return node


def _control():
    return Control(
        arn="arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES",
        full_name="Encryption at rest", description="Ensures EBS volumes are encrypted",
        behavior="DETECTIVE", severity="HIGH",
    )


def _recorder_state(error="", exists=True, running=True, all_supported=False):
    return RecorderState(
        account_id="123456789012", account_name="TestAcct", ou_name="Prod",
        exists=exists, running=running, all_supported=all_supported,
        recorder_name="default", role_arn="arn:aws:iam::123456789012:role/ConfigRole",
        resource_type_count=5, recording_frequency="DAILY", error=error,
    )


def _recorder_result(success=True, noop=False, error_msg=""):
    return RecorderResult(
        account_id="123456789012", account_name="TestAcct", ou_name="Prod",
        success=success, noop=noop,
        message=error_msg if error_msg else ("ok" if success else "failed"),
        planned_types=5, planned_frequency="DAILY",
    )


def _delegation_status(service="guardduty", action="register"):
    return DelegationStatus(
        service=service, principal="guardduty.amazonaws.com",
        current_admin=None, target_admin="123456789012",
        action=action,
    )


def _service_apply_result(service="guardduty", success=True):
    return ServiceApplyResult(
        service=service, phase="configuration", success=success,
        message="ok" if success else "error",
        details=["detail1"] if success else [],
    )


def _service_status(service="guardduty", enabled=True, error=""):
    return ServiceStatus(
        service=service, delegated_admin="123456789012",
        enabled=enabled, auto_enable="ALL",
        details={"key": "val"}, error=error,
    )


def _account_assessment(account_id="123456789012", all_enabled=True):
    services = {
        svc: MemberServiceStatus(enabled=all_enabled, member_status="Enabled" if all_enabled else "not_member")
        for svc in ["guardduty", "security_hub", "macie", "inspector"]
    }
    services["access_analyzer"] = MemberServiceStatus(enabled=True, member_status="org_wide")
    return AccountAssessment(
        account_id=account_id, account_name="TestAcct", ou_name="TestOU",
        services=services,
    )


# ---------------------------------------------------------------------------
# Identity / Permissions
# ---------------------------------------------------------------------------

def test_render_identity():
    renderer.render_identity(
        {"Account": "123456789012", "Arn": "arn:aws:iam::123456789012:user/test", "UserId": "AIDA"},
        profile="dev", region="us-east-1",
    )


def test_render_identity_no_profile():
    renderer.render_identity(
        {"Account": "123456789012", "Arn": "arn:...", "UserId": "AIDA"},
        profile=None, region=None,
    )


def test_render_permissions_all_granted():
    renderer.render_permissions({
        "organizations:DescribeOrganization": True,
        "controltower:ListLandingZones": True,
    })


def test_render_permissions_with_denied():
    renderer.render_permissions({
        "organizations:DescribeOrganization": "AccessDeniedException",
        "controltower:ListLandingZones": "(verified at runtime)",
    })


# ---------------------------------------------------------------------------
# OU tree
# ---------------------------------------------------------------------------

def test_render_ou_tree_empty():
    renderer.render_ou_tree([])


def test_render_ou_tree_with_nodes():
    parent = _ou_node("Parent")
    child = _ou_node("Child")
    parent.children = [child]
    renderer.render_ou_tree([parent])


# ---------------------------------------------------------------------------
# Accounts table
# ---------------------------------------------------------------------------

def test_render_accounts_table_empty():
    renderer.render_accounts_table([])


def test_render_accounts_table():
    accounts = [
        _account("111111111111", "AcctA", "Dev"),
        Account("222222222222", "arn:...", "Inactive", "i@t.com", "SUSPENDED", "ou-2", "Infra"),
    ]
    renderer.render_accounts_table(accounts)


# ---------------------------------------------------------------------------
# Controls summary
# ---------------------------------------------------------------------------

def test_render_controls_summary_empty():
    renderer.render_controls_summary([], {})


def test_render_controls_summary():
    node = _ou_node()
    child = _ou_node("Child")
    child.parent_id = node.id
    node.children = [child]
    ec = EnabledControl(
        control_arn="arn:aws:controltower:us-east-1::control/X",
        ou_arn=node.arn, status="SUCCEEDED"
    )
    ec_fail = EnabledControl(
        control_arn="arn:aws:controltower:us-east-1::control/Y",
        ou_arn=node.arn, status="FAILED"
    )
    ec_progress = EnabledControl(
        control_arn="arn:aws:controltower:us-east-1::control/Z",
        ou_arn=node.arn, status="IN_PROGRESS"
    )
    enabled_by_ou = {
        node.arn: [ec, ec_fail, ec_progress],
        child.arn: [],
    }
    renderer.render_controls_summary([node], enabled_by_ou)


# ---------------------------------------------------------------------------
# Resource types list
# ---------------------------------------------------------------------------

def test_render_resource_types_list_bundled():
    bundled = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::IAM::Role"]
    renderer.render_resource_types_list(bundled, bundled, is_user_override=False)


def test_render_resource_types_list_user_override_with_additions():
    bundled = ["AWS::EC2::Instance", "AWS::S3::Bucket"]
    active = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::EC2::VPC"]  # added VPC
    renderer.render_resource_types_list(active, bundled, is_user_override=True)


def test_render_resource_types_list_show_removed():
    bundled = ["AWS::EC2::Instance", "AWS::S3::Bucket", "AWS::IAM::Role"]
    active = ["AWS::EC2::Instance"]  # S3 and IAM removed
    renderer.render_resource_types_list(active, bundled, is_user_override=True, show_removed=True)


def test_render_resource_types_list_empty():
    renderer.render_resource_types_list([], [], is_user_override=False)


# ---------------------------------------------------------------------------
# Recorder status
# ---------------------------------------------------------------------------

def test_render_recorder_status_running():
    renderer.render_recorder_status([_recorder_state()])


def test_render_recorder_status_stopped():
    renderer.render_recorder_status([_recorder_state(running=False)])


def test_render_recorder_status_no_recorder():
    renderer.render_recorder_status([_recorder_state(exists=False)])


def test_render_recorder_status_error():
    renderer.render_recorder_status([_recorder_state(error="Cannot assume role")])


def test_render_recorder_status_all_supported():
    renderer.render_recorder_status([_recorder_state(all_supported=True)])


def test_render_recorder_status_multiple():
    renderer.render_recorder_status([
        _recorder_state(),
        _recorder_state(error="Access denied"),
        _recorder_state(exists=False),
    ])


# ---------------------------------------------------------------------------
# Recorder plan
# ---------------------------------------------------------------------------

def test_render_recorder_plan_update():
    renderer.render_recorder_plan(
        [_recorder_state(running=True)],
        desired_types=["AWS::S3::Bucket"] * 10,
        desired_frequency="DAILY",
    )


def test_render_recorder_plan_no_change():
    state = _recorder_state(running=True)
    state.resource_type_count = 5
    state.recording_frequency = "DAILY"
    renderer.render_recorder_plan([state], desired_types=["t"] * 5, desired_frequency="DAILY")


def test_render_recorder_plan_error():
    renderer.render_recorder_plan(
        [_recorder_state(error="fail")],
        desired_types=[], desired_frequency="CONTINUOUS",
    )


def test_render_recorder_plan_no_recorder():
    renderer.render_recorder_plan(
        [_recorder_state(exists=False)],
        desired_types=[], desired_frequency="DAILY",
    )


# ---------------------------------------------------------------------------
# Recorder results
# ---------------------------------------------------------------------------

def test_render_recorder_results_success():
    renderer.render_recorder_results([_recorder_result(success=True)])


def test_render_recorder_results_noop():
    renderer.render_recorder_results([_recorder_result(noop=True)])


def test_render_recorder_results_failure():
    renderer.render_recorder_results([_recorder_result(success=False, error_msg="fail")])


def test_render_recorder_results_mixed():
    renderer.render_recorder_results([
        _recorder_result(success=True),
        _recorder_result(noop=True),
        _recorder_result(success=False, error_msg="err"),
    ])


# ---------------------------------------------------------------------------
# Account roles
# ---------------------------------------------------------------------------

def test_render_account_roles_all_ok():
    accounts = [_account("111111111111"), _account("222222222222")]
    results = {a.id: (True, "") for a in accounts}
    renderer.render_account_roles_table(accounts, results, "AWSControlTowerExecution")


def test_render_account_roles_with_failures():
    accounts = [_account("111111111111"), _account("222222222222")]
    results = {
        "111111111111": (True, ""),
        "222222222222": (False, "not authorized"),
    }
    renderer.render_account_roles_table(accounts, results, "AWSControlTowerExecution")


# ---------------------------------------------------------------------------
# Security plan / results / status
# ---------------------------------------------------------------------------

def test_render_security_plan():
    from standstill.models.security_config import SecurityServicesConfig
    config = SecurityServicesConfig(delegated_admin_account="123456789012")
    delegation = [_delegation_status(svc, action) for svc, action in [
        ("guardduty", "register"),
        ("security_hub", "skip"),
        ("macie", "conflict"),
        ("inspector", "error"),
        ("access_analyzer", "register"),
    ]]
    renderer.render_security_plan(config, delegation)


def test_render_security_results_empty():
    renderer.render_security_results([], "Phase 1")


def test_render_security_results_mixed():
    renderer.render_security_results([
        _service_apply_result("guardduty", success=True),
        _service_apply_result("security_hub", success=False),
    ], "Phase 2")


def test_render_security_status_enabled():
    renderer.render_security_status([_service_status("guardduty", enabled=True)])


def test_render_security_status_disabled():
    renderer.render_security_status([_service_status("guardduty", enabled=False)])


def test_render_security_status_error():
    renderer.render_security_status([_service_status("guardduty", error="not delegated")])


def test_render_security_status_all_services():
    renderer.render_security_status([
        _service_status(svc)
        for svc in ["guardduty", "security_hub", "macie", "inspector", "access_analyzer"]
    ])


# ---------------------------------------------------------------------------
# Security assessment
# ---------------------------------------------------------------------------

def test_render_security_assessment_all_healthy():
    results = [_account_assessment("111111111111", all_enabled=True)]
    renderer.render_security_assessment(
        results,
        active_services=["guardduty", "security_hub", "macie", "inspector", "access_analyzer"],
        show_all=False,
    )


def test_render_security_assessment_with_gaps():
    results = [
        _account_assessment("111111111111", all_enabled=True),
        _account_assessment("222222222222", all_enabled=False),
    ]
    renderer.render_security_assessment(
        results,
        active_services=["guardduty", "security_hub", "macie", "inspector", "access_analyzer"],
        show_all=False,
    )


def test_render_security_assessment_show_all():
    results = [
        _account_assessment("111111111111", all_enabled=True),
        _account_assessment("222222222222", all_enabled=False),
    ]
    renderer.render_security_assessment(
        results,
        active_services=["guardduty", "security_hub", "macie", "inspector", "access_analyzer"],
        show_all=True,
    )


def test_render_security_assessment_special_statuses():
    admin = AccountAssessment(
        account_id="123456789012", account_name="Admin", ou_name="Infra",
        services={
            "guardduty": MemberServiceStatus(True, "delegated_admin"),
            "security_hub": MemberServiceStatus(True, "management_account"),
            "macie": MemberServiceStatus(True, "org_wide"),
            "inspector": MemberServiceStatus(False, "error", error="API error"),
        }
    )
    renderer.render_security_assessment(
        [admin],
        active_services=["guardduty", "security_hub", "macie", "inspector"],
        show_all=True,
    )


def test_render_security_assessment_many_errors():
    results = [
        AccountAssessment(
            account_id=f"1{i:011d}", account_name=f"Acct{i}", ou_name="OU",
            services={"guardduty": MemberServiceStatus(False, "error", error=f"err{i}")}
        )
        for i in range(10)
    ]
    renderer.render_security_assessment(
        results,
        active_services=["guardduty"],
        show_all=True,
    )


# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------

def test_render_json():
    renderer.render_json({"key": "value", "number": 42})



# ---------------------------------------------------------------------------
# Cost Explorer
# ---------------------------------------------------------------------------

def _period(start="2024-01-01", end="2024-02-01", groups=None, total=120.0):
    g = groups or [
        CostGroup(key="Amazon EC2", amount=100.0),
        CostGroup(key="Amazon S3", amount=20.0),
    ]
    return CostPeriod(start=start, end=end, groups=g, total=total)


def _trail_event(name="PutMetricData", username="alice"):
    return TrailEvent(
        event_id="e1", event_name=name,
        event_time=datetime(2024, 3, 10, 12, 0, 0, tzinfo=timezone.utc),
        event_source="monitoring.amazonaws.com",
        username=username, account_id="123456789012",
        source_ip="1.2.3.4", user_agent="agent/1.0",
        region="us-east-1", read_only=False,
    )


class TestRenderCostReport:
    def test_single_period_aggregated(self):
        renderer.render_cost_report([_period()], group_by="service", metric="unblended", granularity="monthly")

    def test_matrix_two_periods(self):
        renderer.render_cost_report(
            [_period("2024-01-01", "2024-02-01"), _period("2024-02-01", "2024-03-01")],
            group_by="service", metric="unblended", granularity="monthly",
        )

    def test_daily_granularity(self):
        renderer.render_cost_report(
            [_period() for _ in range(7)],
            group_by="service", metric="unblended", granularity="daily",
        )

    def test_empty_periods(self):
        renderer.render_cost_report([], group_by="service", metric="unblended", granularity="monthly")

    def test_usage_type_enrichment(self):
        p = _period(groups=[CostGroup(key="CW:Requests", amount=50.0)])
        renderer.render_cost_report([p], group_by="usage-type", metric="unblended", granularity="monthly")

    def test_with_account_names(self):
        p = _period(groups=[CostGroup(key="123456789012", amount=100.0)])
        renderer.render_cost_report(
            [p], group_by="account", metric="unblended", granularity="monthly",
            account_names={"123456789012": "ProdAccount"},
        )

    def test_tag_group_by_label(self):
        p = _period(groups=[CostGroup(key="production", amount=100.0)])
        renderer.render_cost_report([p], group_by="tag:Environment", metric="unblended", granularity="monthly")

    def test_compare_mode(self):
        current = [_period("2024-02-01", "2024-03-01")]
        prior   = [_period("2024-01-01", "2024-02-01", groups=[CostGroup(key="Amazon EC2", amount=80.0)], total=80.0)]
        renderer.render_cost_report(
            current, group_by="service", metric="unblended", granularity="monthly",
            prior_periods=prior,
        )

    def test_compare_decrease(self):
        current = [_period(groups=[CostGroup(key="Amazon EC2", amount=50.0)], total=50.0)]
        prior   = [_period(groups=[CostGroup(key="Amazon EC2", amount=100.0)], total=100.0)]
        renderer.render_cost_report(
            current, group_by="service", metric="unblended", granularity="monthly",
            prior_periods=prior,
        )


class TestRenderCostReportCsv:
    def test_basic(self, capsys):
        renderer.render_cost_report_csv([_period()], group_by="service")
        out = capsys.readouterr().out
        assert "Amazon EC2" in out

    def test_usage_type_enriched(self, capsys):
        p = _period(groups=[CostGroup(key="CW:Requests", amount=50.0)])
        renderer.render_cost_report_csv([p], group_by="usage-type")
        out = capsys.readouterr().out
        assert "CW:Requests" in out


class TestRenderCostServices:
    def test_no_services(self):
        renderer.render_cost_services([], start="2024-01-01", end="2024-02-01")

    def test_with_services(self):
        renderer.render_cost_services(
            ["Amazon EC2", "Amazon S3"],
            start="2024-01-01", end="2024-02-01",
        )

    def test_with_costs(self):
        renderer.render_cost_services(
            ["Amazon EC2", "Amazon S3"],
            start="2024-01-01", end="2024-02-01",
            svc_costs={"Amazon EC2": 100.0, "Amazon S3": 20.0},
        )

    def test_csv_with_costs(self, capsys):
        renderer.render_cost_services_csv(
            ["Amazon EC2", "Amazon S3"],
            svc_costs={"Amazon EC2": 100.0, "Amazon S3": 20.0},
        )
        out = capsys.readouterr().out
        assert "100" in out

    def test_csv_no_costs(self, capsys):
        renderer.render_cost_services_csv(["Amazon EC2"])
        out = capsys.readouterr().out
        assert "Amazon EC2" in out


class TestRenderCostForecast:
    def _result(self):
        return {
            "total": 300.0,
            "unit": "USD",
            "monthly": [
                {"start": "2024-02-01", "end": "2024-03-01", "amount": 100.0, "lower": 80.0, "upper": 120.0},
                {"start": "2024-03-01", "end": "2024-04-01", "amount": 110.0, "lower": 90.0, "upper": 130.0},
            ],
        }

    def test_table(self):
        renderer.render_cost_forecast(self._result(), metric="unblended")

    def test_csv(self, capsys):
        renderer.render_cost_forecast_csv(self._result())
        out = capsys.readouterr().out
        assert "2024-02-01" in out

    def test_by_service_table(self):
        svc_results = [
            {
                "service": "Amazon EC2",
                "total": 200.0,
                "unit": "USD",
                "monthly": [
                    {"start": "2024-02-01", "end": "2024-03-01", "amount": 100.0, "lower": 80.0, "upper": 120.0},
                ],
            },
            {"service": "Amazon S3", "total": 0.0, "unit": "USD", "monthly": [], "error": True},
        ]
        renderer.render_cost_forecast_by_service(svc_results, metric="unblended")

    def test_by_service_empty(self):
        renderer.render_cost_forecast_by_service([], metric="unblended")

    def test_by_service_csv(self, capsys):
        svc_results = [
            {
                "service": "Amazon EC2", "total": 200.0, "unit": "USD",
                "monthly": [{"start": "2024-02-01", "end": "2024-03-01", "amount": 100.0, "lower": 80.0, "upper": 120.0}],
            }
        ]
        renderer.render_cost_forecast_by_service_csv(svc_results)
        out = capsys.readouterr().out
        assert "Amazon EC2" in out


class TestRenderBudgets:
    def _budget(self, name="B1", pct=75.0, status="OK"):
        return Budget(
            name=name, budget_type="COST", time_unit="MONTHLY",
            budgeted=1000.0, actual_spend=pct * 10.0, forecasted_spend=900.0,
        )

    def test_empty(self):
        renderer.render_budgets([])

    def test_with_budgets(self):
        renderer.render_budgets([
            self._budget("B1"),
            Budget(name="Over", budget_type="COST", time_unit="MONTHLY",
                   budgeted=100.0, actual_spend=120.0, forecasted_spend=130.0),
            Budget(name="Warn", budget_type="COST", time_unit="MONTHLY",
                   budgeted=100.0, actual_spend=85.0, forecasted_spend=95.0),
        ])

    def test_csv(self, capsys):
        renderer.render_budgets_csv([self._budget()])
        out = capsys.readouterr().out
        assert "B1" in out


class TestRenderAnomalies:
    def _anomaly(self):
        return Anomaly(
            anomaly_id="anom-1", service="Amazon EC2", region="us-east-1",
            account_id="123456789012", start_date="2024-03-10", end_date="2024-03-15",
            impact_max=200.0, impact_total=800.0, expected=100.0,
            root_cause="Amazon EC2 / us-east-1 / BoxUsage",
        )

    def test_empty(self):
        renderer.render_anomalies([])

    def test_with_anomalies(self):
        renderer.render_anomalies([self._anomaly()])

    def test_csv(self, capsys):
        renderer.render_anomalies_csv([self._anomaly()])
        out = capsys.readouterr().out
        assert "anom-1" in out


class TestRenderOptimize:
    def test_savings_plans_high_util(self):
        summary = SavingsPlansSummary(
            period_start="2024-01-01", period_end="2024-02-01",
            utilization_pct=85.0, coverage_pct=72.0,
            net_savings=1200.0, on_demand_equiv=3000.0, sp_spend=1800.0,
        )
        renderer.render_savings_plans(summary)

    def test_savings_plans_low_util(self):
        summary = SavingsPlansSummary(
            period_start="2024-01-01", period_end="2024-02-01",
            utilization_pct=50.0, coverage_pct=40.0,
            net_savings=100.0, on_demand_equiv=500.0, sp_spend=400.0,
        )
        renderer.render_savings_plans(summary)

    def test_ri_empty(self):
        renderer.render_ri([])

    def test_ri_with_data(self):
        renderer.render_ri([
            RISummary(
                period_start="2024-01-01", period_end="2024-02-01",
                service="Amazon EC2", utilization_pct=90.0, coverage_pct=75.0,
                ri_cost=500.0, on_demand_cost=1000.0, net_savings=500.0,
            )
        ])

    def test_rightsizing_empty(self):
        renderer.render_rightsizing([])

    def test_rightsizing_with_data(self):
        renderer.render_rightsizing([
            RightsizingRecommendation(
                account_id="123456789012", region="us-east-1",
                resource_id="i-1234567890abcdef0",
                resource_type="m5.xlarge", current_instance="m5.xlarge",
                recommended_action="Modify", target_instance="m5.large",
                estimated_savings=120.0, estimated_savings_pct=30.0,
            ),
            RightsizingRecommendation(
                account_id="123456789012", region="us-east-1",
                resource_id="i-abcdef1234567890",
                resource_type="t3.large", current_instance="t3.large",
                recommended_action="Terminate", target_instance="",
                estimated_savings=200.0, estimated_savings_pct=100.0,
            ),
        ])


class TestRenderScanResult:
    def _result(self, events=None):
        return ScanResult(
            usage_type="CW:Requests",
            service="CloudWatch",
            event_source="monitoring.amazonaws.com",
            api_calls_searched=["PutMetricData"],
            start="2024-03-01T00:00:00+00:00",
            end="2024-03-15T00:00:00+00:00",
            events=events or [],
        )

    def test_no_events(self):
        renderer.render_scan_result(self._result())

    def test_with_events(self):
        events = [_trail_event()]
        renderer.render_scan_result(self._result(events))

    def test_with_errors(self):
        ev = _trail_event()
        ev.error_code = "AccessDenied"
        renderer.render_scan_result(self._result([ev]))

    def test_more_than_20_events(self):
        events = [_trail_event(name=f"Event{i}") for i in range(25)]
        renderer.render_scan_result(self._result(events))

    def test_csv(self, capsys):
        events = [_trail_event()]
        renderer.render_scan_csv(self._result(events))
        out = capsys.readouterr().out
        assert "PutMetricData" in out

    def test_identity_attribution_shown(self):
        events = [
            _trail_event(username="arn:aws:sts::123:assumed-role/MyRole/sess"),
            _trail_event(username="arn:aws:iam::123:user/alice"),
        ]
        renderer.render_scan_result(self._result(events))


class TestRenderTrailConfig:
    def test_s3_only(self):
        renderer.render_trail_config(
            s3_cfg={"bucket": "my-bucket", "prefix": "AWSLogs/123"},
            cloudwatch_log_group=None,
        )

    def test_cloudwatch_only(self):
        renderer.render_trail_config(
            s3_cfg=None,
            cloudwatch_log_group="/aws/cloudtrail/mgmt",
        )

    def test_both(self):
        renderer.render_trail_config(
            s3_cfg={"bucket": "b", "prefix": "p"},
            cloudwatch_log_group="/aws/cloudtrail/mgmt",
        )
