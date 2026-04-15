"""Tests for standstill/aws/budgets.py and standstill/aws/optimize.py."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from standstill.aws.budgets import Budget, list_budgets
from standstill.aws.optimize import (
    RISummary,
    RightsizingRecommendation,
    SavingsPlansSummary,
    get_ri_summary,
    get_rightsizing_recommendations,
    get_savings_plans_summary,
)


# ---------------------------------------------------------------------------
# Budget dataclass
# ---------------------------------------------------------------------------

class TestBudgetDataclass:
    def test_pct_used(self):
        b = Budget(
            name="test", budget_type="COST", time_unit="MONTHLY",
            budgeted=1000.0, actual_spend=750.0, forecasted_spend=900.0,
        )
        assert b.pct_used == pytest.approx(75.0)

    def test_pct_used_zero_budget(self):
        b = Budget(
            name="test", budget_type="COST", time_unit="MONTHLY",
            budgeted=0.0, actual_spend=0.0, forecasted_spend=0.0,
        )
        assert b.pct_used == 0.0

    def test_status_ok(self):
        b = Budget(name="t", budget_type="COST", time_unit="MONTHLY",
                   budgeted=1000.0, actual_spend=500.0, forecasted_spend=600.0)
        assert b.status == "OK"

    def test_status_warning(self):
        b = Budget(name="t", budget_type="COST", time_unit="MONTHLY",
                   budgeted=1000.0, actual_spend=850.0, forecasted_spend=900.0)
        assert b.status == "WARNING"

    def test_status_exceeded(self):
        b = Budget(name="t", budget_type="COST", time_unit="MONTHLY",
                   budgeted=1000.0, actual_spend=1200.0, forecasted_spend=1300.0)
        assert b.status == "EXCEEDED"

    def test_alert_thresholds_default_empty(self):
        b = Budget(name="t", budget_type="COST", time_unit="MONTHLY",
                   budgeted=100.0, actual_spend=0.0, forecasted_spend=0.0)
        assert b.alert_thresholds == []


# ---------------------------------------------------------------------------
# list_budgets
# ---------------------------------------------------------------------------

class TestListBudgets:
    def _raw_budget(self, name="MyBudget", budget=1000.0, actual=750.0, forecast=900.0):
        return {
            "BudgetName": name,
            "BudgetType": "COST",
            "TimeUnit": "MONTHLY",
            "BudgetLimit": {"Amount": str(budget), "Unit": "USD"},
            "CalculatedSpend": {
                "ActualSpend": {"Amount": str(actual), "Unit": "USD"},
                "ForecastedSpend": {"Amount": str(forecast), "Unit": "USD"},
            },
            "TimePeriod": {"Start": "2024-01-01", "End": "2024-12-31"},
        }

    def test_basic_list(self):
        client = MagicMock()
        client.describe_budgets.return_value = {
            "Budgets": [self._raw_budget("Budget1"), self._raw_budget("Budget2")]
        }
        result = list_budgets(client, "123456789012")
        assert len(result) == 2
        assert result[0].name == "Budget1"
        assert result[0].budgeted == pytest.approx(1000.0)
        assert result[0].actual_spend == pytest.approx(750.0)

    def test_pagination(self):
        client = MagicMock()
        client.describe_budgets.side_effect = [
            {"Budgets": [self._raw_budget("B1")], "NextToken": "tok"},
            {"Budgets": [self._raw_budget("B2")]},
        ]
        result = list_budgets(client, "123456789012")
        assert len(result) == 2
        assert client.describe_budgets.call_count == 2

    def test_empty(self):
        client = MagicMock()
        client.describe_budgets.return_value = {"Budgets": []}
        result = list_budgets(client, "123456789012")
        assert result == []

    def test_budget_with_notifications(self):
        client = MagicMock()
        raw = self._raw_budget()
        raw["Notifications"] = [
            {"Threshold": 80.0, "ThresholdType": "PERCENTAGE",
             "ComparisonOperator": "GREATER_THAN", "NotificationType": "ACTUAL"}
        ]
        client.describe_budgets.return_value = {"Budgets": [raw]}
        result = list_budgets(client, "123456789012")
        assert len(result[0].alert_thresholds) == 1
        assert result[0].alert_thresholds[0]["threshold"] == 80.0


# ---------------------------------------------------------------------------
# get_savings_plans_summary
# ---------------------------------------------------------------------------

class TestGetSavingsPlansSummary:
    def _ce(self):
        ce = MagicMock()
        ce.get_savings_plans_utilization.return_value = {
            "Total": {
                "Utilization": {"UtilizationPercentage": "85.5"},
                "Savings": {"NetSavings": "1200.00", "OnDemandCostEquivalent": "3000.00"},
                "AmortizedCommitment": {"AmortizedRecurringCommitment": "1800.00"},
            }
        }
        ce.get_savings_plans_coverage.return_value = {
            "SavingsPlansCoverages": [
                {"Coverage": {"CoveragePercentage": "72.0"}}
            ]
        }
        return ce

    def test_basic(self):
        ce = self._ce()
        summary = get_savings_plans_summary(ce, "2024-01-01", "2024-02-01")
        assert summary.utilization_pct == pytest.approx(85.5)
        assert summary.coverage_pct == pytest.approx(72.0)
        assert summary.net_savings == pytest.approx(1200.0)
        assert summary.sp_spend == pytest.approx(1800.0)
        assert summary.period_start == "2024-01-01"

    def test_no_coverage_data(self):
        ce = self._ce()
        ce.get_savings_plans_coverage.return_value = {"SavingsPlansCoverages": []}
        summary = get_savings_plans_summary(ce, "2024-01-01", "2024-02-01")
        assert summary.coverage_pct == 0.0


# ---------------------------------------------------------------------------
# get_ri_summary
# ---------------------------------------------------------------------------

class TestGetRiSummary:
    def test_basic(self):
        ce = MagicMock()
        ce.get_reservation_utilization.return_value = {
            "UtilizationsByTime": [
                {
                    "Groups": [
                        {
                            "Key": "Amazon EC2",
                            "Utilization": {
                                "UtilizationPercentage": "90.0",
                                "AmortizedRecurringFee": "500.00",
                                "OnDemandCostOfRIHoursUsed": "1000.00",
                                "NetRISavings": "500.00",
                            }
                        }
                    ]
                }
            ]
        }
        ce.get_reservation_coverage.return_value = {
            "CoveragesByTime": [
                {
                    "Groups": [
                        {
                            "Attributes": {"SERVICE": "Amazon EC2"},
                            "Coverage": {"CoverageHoursPercentage": "75.0"},
                        }
                    ]
                }
            ]
        }
        results = get_ri_summary(ce, "2024-01-01", "2024-02-01")
        assert len(results) == 1
        assert results[0].service == "Amazon EC2"
        assert results[0].utilization_pct == pytest.approx(90.0)
        assert results[0].coverage_pct == pytest.approx(75.0)
        assert results[0].net_savings == pytest.approx(500.0)

    def test_empty(self):
        ce = MagicMock()
        ce.get_reservation_utilization.return_value = {"UtilizationsByTime": [{"Groups": []}]}
        ce.get_reservation_coverage.return_value = {"CoveragesByTime": [{"Groups": []}]}
        results = get_ri_summary(ce, "2024-01-01", "2024-02-01")
        assert results == []


# ---------------------------------------------------------------------------
# get_rightsizing_recommendations
# ---------------------------------------------------------------------------

class TestGetRightsizingRecommendations:
    def _raw_rec(self, action="Modify"):
        rec = {
            "RightsizingType": action,
            "CurrentInstance": {
                "ResourceId": "i-1234567890abcdef0",
                "ResourceDetails": {
                    "EC2ResourceDetails": {
                        "Region": "us-east-1",
                        "InstanceType": "m5.xlarge",
                    }
                },
            },
        }
        if action == "Modify":
            rec["ModifyRecommendationDetail"] = {
                "EstimatedMonthlySavings": "120.00",
                "EstimatedMonthlySavingsPercentage": "30.0",
                "TargetInstances": [
                    {
                        "ResourceDetails": {
                            "EC2ResourceDetails": {"InstanceType": "m5.large"}
                        }
                    }
                ],
            }
        else:
            rec["TerminateRecommendationDetail"] = {
                "EstimatedMonthlySavings": "200.00",
                "EstimatedMonthlySavingsPercentage": "100.0",
            }
        return rec

    def test_modify_recommendation(self):
        ce = MagicMock()
        ce.get_rightsizing_recommendation.return_value = {
            "RightsizingRecommendations": [self._raw_rec("Modify")]
        }
        recs = get_rightsizing_recommendations(ce)
        assert len(recs) == 1
        assert recs[0].recommended_action == "Modify"
        assert recs[0].current_instance == "m5.xlarge"
        assert recs[0].target_instance == "m5.large"
        assert recs[0].estimated_savings == pytest.approx(120.0)

    def test_terminate_recommendation(self):
        ce = MagicMock()
        ce.get_rightsizing_recommendation.return_value = {
            "RightsizingRecommendations": [self._raw_rec("Terminate")]
        }
        recs = get_rightsizing_recommendations(ce)
        assert recs[0].recommended_action == "Terminate"
        assert recs[0].estimated_savings == pytest.approx(200.0)

    def test_empty(self):
        ce = MagicMock()
        ce.get_rightsizing_recommendation.return_value = {"RightsizingRecommendations": []}
        recs = get_rightsizing_recommendations(ce)
        assert recs == []

    def test_pagination(self):
        ce = MagicMock()
        ce.get_rightsizing_recommendation.side_effect = [
            {"RightsizingRecommendations": [self._raw_rec()], "NextPageToken": "tok"},
            {"RightsizingRecommendations": [self._raw_rec()]},
        ]
        recs = get_rightsizing_recommendations(ce)
        assert len(recs) == 2
        assert ce.get_rightsizing_recommendation.call_count == 2
