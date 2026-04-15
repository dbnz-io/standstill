"""Tests for standstill/aws/cost.py — unit tests with mocked CE client."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from standstill.aws.cost import (
    Anomaly,
    _build_ce_filter,
    compute_prior_period,
    get_anomalies,
    get_cost_and_usage,
    get_forecast,
    get_forecast_by_service,
    get_service_costs,
    list_services,
    resolve_service_filter,
    service_filter_alias,
)

# ---------------------------------------------------------------------------
# _build_ce_filter
# ---------------------------------------------------------------------------

class TestBuildCeFilter:
    def test_empty_returns_none(self):
        assert _build_ce_filter([]) is None

    def test_single_dimension(self):
        result = _build_ce_filter([("service", ["Amazon EC2"])])
        assert result == {
            "Dimensions": {"Key": "SERVICE", "Values": ["Amazon EC2"], "MatchOptions": ["EQUALS"]}
        }

    def test_multiple_dimensions_wrapped_in_and(self):
        result = _build_ce_filter([("service", ["Amazon EC2"]), ("region", ["us-east-1"])])
        assert "And" in result
        assert len(result["And"]) == 2

    def test_tag_prefix_generates_tags_clause(self):
        result = _build_ce_filter([("tag:Environment", ["production"])])
        assert "Tags" in result
        assert result["Tags"]["Key"] == "Environment"
        assert result["Tags"]["Values"] == ["production"]

    def test_tag_and_dimension_combined(self):
        result = _build_ce_filter([("service", ["Amazon S3"]), ("tag:Team", ["platform"])])
        assert "And" in result
        types = {list(c.keys())[0] for c in result["And"]}
        assert types == {"Dimensions", "Tags"}

    def test_unknown_dimension_raises(self):
        with pytest.raises(ValueError, match="Unknown filter dimension"):
            _build_ce_filter([("bogus", ["x"])])

    def test_tag_case_insensitive(self):
        result = _build_ce_filter([("TAG:Env", ["prod"])])
        assert "Tags" in result
        assert result["Tags"]["Key"] == "Env"


# ---------------------------------------------------------------------------
# service_filter_alias
# ---------------------------------------------------------------------------

class TestServiceFilterAlias:
    def test_known_service(self):
        assert service_filter_alias("Amazon Elastic Compute Cloud - Compute") == "ec2"
        assert service_filter_alias("Amazon Simple Storage Service") == "s3"
        assert service_filter_alias("Amazon Relational Database Service") == "rds"

    def test_unknown_service_returns_empty(self):
        assert service_filter_alias("Some Unknown Service") == ""

    def test_case_insensitive(self):
        alias = service_filter_alias("amazon elastic compute cloud - compute")
        assert alias == "ec2"


# ---------------------------------------------------------------------------
# resolve_service_filter
# ---------------------------------------------------------------------------

class TestResolveServiceFilter:
    def _ce(self, services):
        ce = MagicMock()
        ce.get_dimension_values.return_value = {
            "DimensionValues": [{"Value": s} for s in services]
        }
        return ce

    def test_full_name_returned_as_is(self):
        ce = self._ce([])
        result = resolve_service_filter(ce, "Amazon EC2", "2024-01-01", "2024-02-01")
        assert result == ["Amazon EC2"]
        ce.get_dimension_values.assert_not_called()

    def test_aws_prefix_returned_as_is(self):
        ce = self._ce([])
        result = resolve_service_filter(ce, "AWS Lambda", "2024-01-01", "2024-02-01")
        assert result == ["AWS Lambda"]

    def test_short_alias_expands(self):
        services = ["Amazon Elastic Compute Cloud - Compute", "Amazon EC2 Auto Scaling"]
        ce = self._ce(services)
        result = resolve_service_filter(ce, "ec2", "2024-01-01", "2024-02-01")
        assert "Amazon Elastic Compute Cloud - Compute" in result

    def test_no_match_returns_raw(self):
        ce = self._ce(["Amazon S3"])
        result = resolve_service_filter(ce, "xyz-unknown", "2024-01-01", "2024-02-01")
        assert result == ["xyz-unknown"]


# ---------------------------------------------------------------------------
# get_cost_and_usage
# ---------------------------------------------------------------------------

def _make_ce_response(groups, start="2024-01-01", end="2024-02-01", estimated=False):
    """Build a minimal CE get_cost_and_usage response."""
    return {
        "ResultsByTime": [
            {
                "TimePeriod": {"Start": start, "End": end},
                "Estimated": estimated,
                "Groups": [
                    {
                        "Keys": [g["key"]],
                        "Metrics": {"UnblendedCost": {"Amount": str(g["amount"]), "Unit": "USD"}},
                    }
                    for g in groups
                ],
                "Total": {},
            }
        ]
    }


class TestGetCostAndUsage:
    def test_basic_service_grouping(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = _make_ce_response([
            {"key": "Amazon EC2", "amount": "100.00"},
            {"key": "Amazon S3", "amount": "20.00"},
        ])
        periods = get_cost_and_usage(ce, "2024-01-01", "2024-02-01", "MONTHLY", "service")
        assert len(periods) == 1
        assert periods[0].groups[0].key == "Amazon EC2"
        assert periods[0].groups[0].amount == pytest.approx(100.0)

    def test_min_cost_filter(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = _make_ce_response([
            {"key": "Amazon EC2", "amount": "100.00"},
            {"key": "Cheap Service", "amount": "0.001"},
        ])
        periods = get_cost_and_usage(ce, "2024-01-01", "2024-02-01", "MONTHLY", "service", min_cost=0.01)
        assert len(periods[0].groups) == 1
        assert periods[0].groups[0].key == "Amazon EC2"

    def test_top_n_filter(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = _make_ce_response([
            {"key": "SvcA", "amount": "300"},
            {"key": "SvcB", "amount": "200"},
            {"key": "SvcC", "amount": "100"},
        ])
        periods = get_cost_and_usage(ce, "2024-01-01", "2024-02-01", "MONTHLY", "service", top=2)
        assert len(periods[0].groups) == 2
        assert periods[0].groups[0].key == "SvcA"

    def test_tag_group_by(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = _make_ce_response([{"key": "backend", "amount": "50"}])
        get_cost_and_usage(ce, "2024-01-01", "2024-02-01", "MONTHLY", "tag:Team")
        call_kwargs = ce.get_cost_and_usage.call_args[1]
        assert call_kwargs["GroupBy"] == [{"Type": "TAG", "Key": "Team"}]

    def test_with_filter(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = _make_ce_response([])
        get_cost_and_usage(
            ce, "2024-01-01", "2024-02-01", "MONTHLY", "service",
            filters=[("region", ["us-east-1"])],
        )
        call_kwargs = ce.get_cost_and_usage.call_args[1]
        assert "Filter" in call_kwargs

    def test_pagination(self):
        ce = MagicMock()
        page1 = {
            "ResultsByTime": [{"TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                               "Groups": [], "Total": {}, "Estimated": False}],
            "NextPageToken": "token123",
        }
        page2 = {
            "ResultsByTime": [{"TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                               "Groups": [], "Total": {}, "Estimated": False}],
        }
        ce.get_cost_and_usage.side_effect = [page1, page2]
        periods = get_cost_and_usage(ce, "2024-01-01", "2024-03-01", "MONTHLY", "service")
        assert len(periods) == 2
        assert ce.get_cost_and_usage.call_count == 2


# ---------------------------------------------------------------------------
# list_services
# ---------------------------------------------------------------------------

class TestListServices:
    def test_returns_service_names(self):
        ce = MagicMock()
        ce.get_dimension_values.return_value = {
            "DimensionValues": [
                {"Value": "Amazon EC2"},
                {"Value": "Amazon S3"},
            ]
        }
        result = list_services(ce, "2024-01-01", "2024-02-01")
        assert result == ["Amazon EC2", "Amazon S3"]

    def test_empty_values_excluded(self):
        ce = MagicMock()
        ce.get_dimension_values.return_value = {
            "DimensionValues": [{"Value": ""}, {"Value": "Amazon S3"}]
        }
        result = list_services(ce, "2024-01-01", "2024-02-01")
        assert "" not in result


# ---------------------------------------------------------------------------
# get_forecast
# ---------------------------------------------------------------------------

class TestGetForecast:
    def test_basic_forecast(self):
        ce = MagicMock()
        ce.get_cost_forecast.return_value = {
            "Total": {"Amount": "300.00", "Unit": "USD"},
            "ForecastResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                    "MeanValue": "100.00",
                    "PredictionIntervalLowerBound": "80.00",
                    "PredictionIntervalUpperBound": "120.00",
                }
            ],
        }
        result = get_forecast(ce, "2024-02-01", "2024-03-01")
        assert result["total"] == pytest.approx(300.0)
        assert len(result["monthly"]) == 1
        assert result["monthly"][0]["amount"] == pytest.approx(100.0)


# ---------------------------------------------------------------------------
# get_service_costs
# ---------------------------------------------------------------------------

class TestGetServiceCosts:
    def test_aggregates_across_periods(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "50", "Unit": "USD"}}},
                        {"Keys": ["Amazon S3"], "Metrics": {"UnblendedCost": {"Amount": "10", "Unit": "USD"}}},
                    ]
                },
                {
                    "Groups": [
                        {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "60", "Unit": "USD"}}},
                    ]
                },
            ]
        }
        result = get_service_costs(ce, "2024-01-01", "2024-03-01")
        assert result["Amazon EC2"] == pytest.approx(110.0)
        assert result["Amazon S3"] == pytest.approx(10.0)


# ---------------------------------------------------------------------------
# compute_prior_period
# ---------------------------------------------------------------------------

class TestComputePriorPeriod:
    def test_prior_end_is_current_start(self):
        """Prior period always ends exactly where the current period starts."""
        prior_start, prior_end = compute_prior_period("2024-03-01", "2024-04-01")
        assert prior_end == "2024-03-01"

    def test_same_duration(self):
        """Prior period has the same number of days as the current period."""
        from datetime import date as d
        for start, end in [
            ("2024-03-01", "2024-04-01"),
            ("2024-01-01", "2024-04-01"),
            ("2024-03-10", "2024-03-20"),
        ]:
            prior_start, prior_end = compute_prior_period(start, end)
            current_days = (d.fromisoformat(end) - d.fromisoformat(start)).days
            prior_days   = (d.fromisoformat(prior_end) - d.fromisoformat(prior_start)).days
            assert current_days == prior_days

    def test_7_day_window(self):
        prior_start, prior_end = compute_prior_period("2024-03-08", "2024-03-15")
        assert prior_start == "2024-03-01"
        assert prior_end == "2024-03-08"


# ---------------------------------------------------------------------------
# get_forecast_by_service
# ---------------------------------------------------------------------------

class TestGetForecastByService:
    def test_returns_per_service_results(self):
        ce = MagicMock()
        # Mock get_cost_and_usage for recent costs (used to rank services)
        ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {
                    "Groups": [
                        {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}},
                        {"Keys": ["Amazon S3"], "Metrics": {"UnblendedCost": {"Amount": "20", "Unit": "USD"}}},
                    ]
                }
            ]
        }
        # Mock get_cost_forecast for each service
        ce.get_cost_forecast.return_value = {
            "Total": {"Amount": "50", "Unit": "USD"},
            "ForecastResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-02-01", "End": "2024-03-01"},
                    "MeanValue": "50",
                    "PredictionIntervalLowerBound": "40",
                    "PredictionIntervalUpperBound": "60",
                }
            ],
        }
        results = get_forecast_by_service(ce, "2024-02-01", "2024-04-01", top_n=2)
        assert len(results) == 2
        assert all("service" in r for r in results)
        assert all("total" in r for r in results)

    def test_error_in_service_marked(self):
        ce = MagicMock()
        ce.get_cost_and_usage.return_value = {
            "ResultsByTime": [
                {"Groups": [{"Keys": ["Bad Service"], "Metrics": {"UnblendedCost": {"Amount": "10", "Unit": "USD"}}}]}
            ]
        }
        ce.get_cost_forecast.side_effect = Exception("CE error")
        results = get_forecast_by_service(ce, "2024-02-01", "2024-03-01", top_n=1)
        assert results[0].get("error") is True
        assert results[0]["total"] == 0.0


# ---------------------------------------------------------------------------
# get_anomalies / Anomaly
# ---------------------------------------------------------------------------

class TestGetAnomalies:
    def test_basic_anomaly(self):
        ce = MagicMock()
        ce.get_anomalies.return_value = {
            "Anomalies": [
                {
                    "AnomalyId": "anom-123",
                    "DimensionValue": "Amazon EC2",
                    "AnomalyStartDate": "2024-03-10",
                    "AnomalyEndDate": "2024-03-15",
                    "Impact": {
                        "MaxImpact": 200.0,
                        "TotalImpact": 800.0,
                        "TotalExpectedSpend": 100.0,
                    },
                    "RootCauses": [
                        {"Service": "Amazon EC2", "Region": "us-east-1",
                         "UsageType": "BoxUsage", "LinkedAccount": "123456789012"}
                    ],
                    "MonitorArn": "arn:aws:ce::monitor/xyz",
                    "Feedback": "PLANNED_ACTIVITY",
                }
            ]
        }
        result = get_anomalies(ce, days_back=30)
        assert len(result) == 1
        a = result[0]
        assert a.anomaly_id == "anom-123"
        assert a.service == "Amazon EC2"
        assert a.impact_total == pytest.approx(800.0)
        assert a.region == "us-east-1"
        assert "Amazon EC2" in a.root_cause

    def test_empty_anomalies(self):
        ce = MagicMock()
        ce.get_anomalies.return_value = {"Anomalies": []}
        result = get_anomalies(ce)
        assert result == []

    def test_anomaly_dataclass_properties(self):
        a = Anomaly(
            anomaly_id="x", service="EC2", region="us-east-1", account_id="123",
            start_date="2024-01-01", end_date="2024-01-05",
            impact_max=100.0, impact_total=400.0, expected=50.0,
        )
        assert a.unit == "USD"
        assert a.feedback == ""
