"""Tests for standstill/commands/cost.py — CLI integration with mocked AWS."""
from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

import standstill.config as cfg_module
from standstill import state as _state
from standstill.aws.budgets import Budget
from standstill.aws.cloudtrail_scan import ScanResult, TrailEvent
from standstill.aws.cost import Anomaly, CostGroup, CostPeriod
from standstill.aws.optimize import RightsizingRecommendation, SavingsPlansSummary
from standstill.commands.cost import app
from standstill.display import renderer

runner = CliRunner()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def silent_console(monkeypatch):
    """Suppress Rich output in all cost command tests."""
    silent = __import__("rich.console", fromlist=["Console"]).Console(
        file=StringIO(), width=120
    )
    monkeypatch.setattr(renderer, "console", silent)


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.yaml"
    monkeypatch.setattr(cfg_module, "_CONFIG_PATH", config_path)
    return config_path


def _periods(groups=None, start="2024-01-01", end="2024-02-01"):
    g = groups or [CostGroup(key="Amazon EC2", amount=100.0), CostGroup(key="Amazon S3", amount=20.0)]
    return [CostPeriod(start=start, end=end, groups=g, total=120.0)]


# ---------------------------------------------------------------------------
# cost report
# ---------------------------------------------------------------------------

class TestReportCommand:
    def test_table_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                        "Estimated": False,
                        "Groups": [
                            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}}
                        ],
                        "Total": {},
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["report", "--start", "2024-01-01", "--end", "2024-02-01"])
            assert result.exit_code == 0

    def test_json_output(self):
        import json as _json
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                        "Estimated": False,
                        "Groups": [
                            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}}
                        ],
                        "Total": {},
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            _state.state.output = "json"
            result = runner.invoke(app, ["report", "--start", "2024-01-01", "--end", "2024-02-01"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_csv_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                        "Estimated": False,
                        "Groups": [
                            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}}
                        ],
                        "Total": {},
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            _state.state.output = "csv"
            result = runner.invoke(app, ["report", "--start", "2024-01-01", "--end", "2024-02-01"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_invalid_dates_exit_1(self):
        result = runner.invoke(app, ["report", "--start", "2024-03-01", "--end", "2024-01-01"])
        assert result.exit_code == 1

    def test_bad_date_format_exit_1(self):
        result = runner.invoke(app, ["report", "--start", "not-a-date", "--end", "2024-02-01"])
        assert result.exit_code == 1

    def test_invalid_group_by(self):
        result = runner.invoke(app, ["report", "--group-by", "badvalue"])
        assert result.exit_code != 0

    def test_group_by_tag(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                        "Estimated": False,
                        "Groups": [
                            {"Keys": ["production"], "Metrics": {"UnblendedCost": {"Amount": "200", "Unit": "USD"}}}
                        ],
                        "Total": {},
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "report", "--group-by", "tag:Environment",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 0

    def test_compare_flag(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                        "Estimated": False,
                        "Groups": [
                            {"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}}
                        ],
                        "Total": {},
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "report", "--compare",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 0

    def test_api_error_exit_1(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.side_effect = Exception("CE error")
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["report", "--start", "2024-01-01", "--end", "2024-02-01"])
            assert result.exit_code == 1

    def test_filter_region_all_is_noop(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {
                        "TimePeriod": {"Start": "2024-01-01", "End": "2024-02-01"},
                        "Estimated": False, "Groups": [], "Total": {},
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "report", "--filter", "region=all",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 0

    def test_filter_bad_format_exit_1(self):
        result = runner.invoke(app, ["report", "--filter", "noequals"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# cost services
# ---------------------------------------------------------------------------

class TestServicesCommand:
    def _setup_ce(self):
        ce = MagicMock()
        ce.get_dimension_values.return_value = {
            "DimensionValues": [{"Value": "Amazon EC2"}, {"Value": "Amazon S3"}]
        }
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
        return ce

    def test_table_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            mock_ce_fn.return_value = self._setup_ce()
            result = runner.invoke(app, ["services", "--start", "2024-01-01", "--end", "2024-02-01"])
            assert result.exit_code == 0

    def test_json_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            mock_ce_fn.return_value = self._setup_ce()
            _state.state.output = "json"
            result = runner.invoke(app, ["services", "--start", "2024-01-01", "--end", "2024-02-01"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_csv_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            mock_ce_fn.return_value = self._setup_ce()
            _state.state.output = "csv"
            result = runner.invoke(app, ["services", "--start", "2024-01-01", "--end", "2024-02-01"])
            _state.state.output = "table"
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# cost forecast
# ---------------------------------------------------------------------------

class TestForecastCommand:
    def _forecast_resp(self):
        return {
            "Total": {"Amount": "300", "Unit": "USD"},
            "ForecastResultsByTime": [
                {
                    "TimePeriod": {"Start": "2024-05-01", "End": "2024-06-01"},
                    "MeanValue": "100",
                    "PredictionIntervalLowerBound": "80",
                    "PredictionIntervalUpperBound": "120",
                }
            ],
        }

    def test_table_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_forecast.return_value = self._forecast_resp()
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["forecast"])
            assert result.exit_code == 0

    def test_json_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_forecast.return_value = self._forecast_resp()
            mock_ce_fn.return_value = ce
            _state.state.output = "json"
            result = runner.invoke(app, ["forecast"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_csv_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_forecast.return_value = self._forecast_resp()
            mock_ce_fn.return_value = ce
            _state.state.output = "csv"
            result = runner.invoke(app, ["forecast"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_by_service(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {"Groups": [{"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}}]}
                ]
            }
            ce.get_cost_forecast.return_value = self._forecast_resp()
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["forecast", "--by-service", "--top", "2"])
            assert result.exit_code == 0

    def test_by_service_csv(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_and_usage.return_value = {
                "ResultsByTime": [
                    {"Groups": [{"Keys": ["Amazon EC2"], "Metrics": {"UnblendedCost": {"Amount": "100", "Unit": "USD"}}}]}
                ]
            }
            ce.get_cost_forecast.return_value = self._forecast_resp()
            mock_ce_fn.return_value = ce
            _state.state.output = "csv"
            result = runner.invoke(app, ["forecast", "--by-service"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_api_error(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_cost_forecast.side_effect = Exception("forecast failed")
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["forecast"])
            assert result.exit_code == 1


# ---------------------------------------------------------------------------
# cost budgets
# ---------------------------------------------------------------------------

class TestBudgetsCommand:
    def _budget(self, name="MyBudget", pct=75.0):
        b = Budget(
            name=name, budget_type="COST", time_unit="MONTHLY",
            budgeted=1000.0, actual_spend=pct * 10, forecasted_spend=900.0,
        )
        return b

    def test_table_output(self):
        with (
            patch("standstill.commands.cost._state") as mock_state,
            patch("standstill.aws.budgets.list_budgets") as mock_lb,
        ):
            mock_state.state.output = "table"
            mock_state.state.get_client.return_value = MagicMock(
                get_caller_identity=MagicMock(return_value={"Account": "123456789012"})
            )
            mock_lb.return_value = [self._budget()]
            result = runner.invoke(app, ["budgets"])
            assert result.exit_code == 0

    def test_json_output(self):
        with patch("standstill.commands.cost._state") as mock_state:
            sts_mock = MagicMock()
            sts_mock.get_caller_identity.return_value = {"Account": "123456789012"}
            budgets_mock = MagicMock()
            budgets_mock_resp = {"Budgets": []}

            def get_client(svc, **kw):
                if svc == "sts":
                    return sts_mock
                return MagicMock(describe_budgets=MagicMock(return_value={"Budgets": []}))

            mock_state.state.output = "json"
            mock_state.state.get_client.side_effect = get_client
            result = runner.invoke(app, ["budgets"])
            mock_state.state.output = "table"
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# cost anomalies
# ---------------------------------------------------------------------------

class TestAnomaliesCommand:
    def test_table_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_anomalies.return_value = {
                "Anomalies": [
                    {
                        "AnomalyId": "anom-1",
                        "DimensionValue": "Amazon EC2",
                        "AnomalyStartDate": "2024-03-10",
                        "AnomalyEndDate": "2024-03-12",
                        "Impact": {"MaxImpact": 100.0, "TotalImpact": 300.0, "TotalExpectedSpend": 50.0},
                        "RootCauses": [],
                    }
                ]
            }
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["anomalies"])
            assert result.exit_code == 0

    def test_json_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_anomalies.return_value = {"Anomalies": []}
            mock_ce_fn.return_value = ce
            _state.state.output = "json"
            result = runner.invoke(app, ["anomalies"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_csv_output(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_anomalies.return_value = {"Anomalies": []}
            mock_ce_fn.return_value = ce
            _state.state.output = "csv"
            result = runner.invoke(app, ["anomalies"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_api_error(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_anomalies.side_effect = Exception("api error")
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["anomalies"])
            assert result.exit_code == 1


# ---------------------------------------------------------------------------
# cost trail
# ---------------------------------------------------------------------------

class TestTrailCommands:
    def test_trail_set_s3(self, isolated_config):
        result = runner.invoke(app, [
            "trail", "set", "--s3-bucket", "my-bucket", "--s3-prefix", "AWSLogs/123"
        ])
        assert result.exit_code == 0

    def test_trail_set_cloudwatch(self, isolated_config):
        result = runner.invoke(app, [
            "trail", "set", "--log-group", "/aws/cloudtrail/mgmt"
        ])
        assert result.exit_code == 0

    def test_trail_set_no_args_error(self, isolated_config):
        result = runner.invoke(app, ["trail", "set"])
        assert result.exit_code == 1

    def test_trail_show_empty(self, isolated_config):
        result = runner.invoke(app, ["trail", "show"])
        assert result.exit_code == 0

    def test_trail_show_with_config(self, isolated_config):
        runner.invoke(app, ["trail", "set", "--s3-bucket", "b", "--s3-prefix", "p"])
        result = runner.invoke(app, ["trail", "show"])
        assert result.exit_code == 0

    def test_trail_clear_s3(self, isolated_config):
        runner.invoke(app, ["trail", "set", "--s3-bucket", "b"])
        result = runner.invoke(app, ["trail", "clear", "--s3"])
        assert result.exit_code == 0

    def test_trail_clear_cloudwatch(self, isolated_config):
        runner.invoke(app, ["trail", "set", "--log-group", "/lg"])
        result = runner.invoke(app, ["trail", "clear", "--cloudwatch"])
        assert result.exit_code == 0

    def test_trail_clear_no_args_error(self, isolated_config):
        result = runner.invoke(app, ["trail", "clear"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# cost scan usage-type
# ---------------------------------------------------------------------------

class TestScanUsageType:
    def test_unknown_usage_type_exit_1(self):
        result = runner.invoke(app, ["scan", "usage-type", "BOGUS:Unknown"])
        assert result.exit_code == 1

    def test_valid_usage_type_event_history(self):
        with patch("standstill.commands.cost._state") as mock_state:
            mock_state.state.output = "table"
            ct_mock = MagicMock()
            ct_mock.lookup_events.return_value = {"Events": []}
            mock_state.state.get_client.return_value = ct_mock
            result = runner.invoke(app, [
                "scan", "usage-type", "CW:Requests",
                "--start", "2024-03-01", "--end", "2024-03-08",
            ])
            assert result.exit_code == 0

    def test_s3_target_no_config_exit_1(self, isolated_config):
        result = runner.invoke(app, [
            "scan", "usage-type", "CW:Requests", "--target", "s3",
        ])
        assert result.exit_code == 1

    def test_cloudwatch_target_no_config_exit_1(self, isolated_config):
        result = runner.invoke(app, [
            "scan", "usage-type", "CW:Requests", "--target", "cloudwatch",
        ])
        assert result.exit_code == 1

    def test_start_after_end_exit_1(self):
        result = runner.invoke(app, [
            "scan", "usage-type", "CW:Requests",
            "--start", "2024-03-15", "--end", "2024-03-01",
        ])
        assert result.exit_code == 1

    def test_json_output(self):
        with patch("standstill.commands.cost._state") as mock_state:
            mock_state.state.output = "json"
            ct_mock = MagicMock()
            ct_mock.lookup_events.return_value = {"Events": []}
            mock_state.state.get_client.return_value = ct_mock
            result = runner.invoke(app, [
                "scan", "usage-type", "CW:Requests",
                "--start", "2024-03-01", "--end", "2024-03-08",
            ])
            assert result.exit_code == 0


# ---------------------------------------------------------------------------
# cost optimize
# ---------------------------------------------------------------------------

class TestOptimizeCommands:
    def test_savings_plans(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_savings_plans_utilization.return_value = {
                "Total": {
                    "Utilization": {"UtilizationPercentage": "85"},
                    "Savings": {"NetSavings": "500", "OnDemandCostEquivalent": "2000"},
                    "AmortizedCommitment": {"AmortizedRecurringCommitment": "1500"},
                }
            }
            ce.get_savings_plans_coverage.return_value = {"SavingsPlansCoverages": []}
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "optimize", "savings-plans",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 0

    def test_savings_plans_json(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_savings_plans_utilization.return_value = {
                "Total": {
                    "Utilization": {"UtilizationPercentage": "85"},
                    "Savings": {"NetSavings": "500", "OnDemandCostEquivalent": "2000"},
                    "AmortizedCommitment": {"AmortizedRecurringCommitment": "1500"},
                }
            }
            ce.get_savings_plans_coverage.return_value = {"SavingsPlansCoverages": []}
            mock_ce_fn.return_value = ce
            _state.state.output = "json"
            result = runner.invoke(app, [
                "optimize", "savings-plans",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_reserved(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_reservation_utilization.return_value = {"UtilizationsByTime": [{"Groups": []}]}
            ce.get_reservation_coverage.return_value = {"CoveragesByTime": [{"Groups": []}]}
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "optimize", "reserved",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 0

    def test_rightsizing(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_rightsizing_recommendation.return_value = {"RightsizingRecommendations": []}
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["optimize", "rightsizing"])
            assert result.exit_code == 0

    def test_rightsizing_json(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_rightsizing_recommendation.return_value = {"RightsizingRecommendations": []}
            mock_ce_fn.return_value = ce
            _state.state.output = "json"
            result = runner.invoke(app, ["optimize", "rightsizing"])
            _state.state.output = "table"
            assert result.exit_code == 0

    def test_savings_plans_error(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_savings_plans_utilization.side_effect = Exception("not supported")
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "optimize", "savings-plans",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 1

    def test_reserved_error(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_reservation_utilization.side_effect = Exception("not supported")
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, [
                "optimize", "reserved",
                "--start", "2024-01-01", "--end", "2024-02-01",
            ])
            assert result.exit_code == 1

    def test_rightsizing_error(self):
        with patch("standstill.commands.cost._ce") as mock_ce_fn:
            ce = MagicMock()
            ce.get_rightsizing_recommendation.side_effect = Exception("not supported")
            mock_ce_fn.return_value = ce
            result = runner.invoke(app, ["optimize", "rightsizing"])
            assert result.exit_code == 1
