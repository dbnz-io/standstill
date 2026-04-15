from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Budget:
    name:             str
    budget_type:      str          # COST | USAGE | RI_UTILIZATION | SAVINGS_PLANS_UTILIZATION
    time_unit:        str          # MONTHLY | QUARTERLY | ANNUALLY
    budgeted:         float
    actual_spend:     float
    forecasted_spend: float
    unit:             str = "USD"
    start_date:       str = ""
    end_date:         str = ""
    alert_thresholds: list[dict] = None  # list of {"threshold": float, "type": str}

    def __post_init__(self) -> None:
        if self.alert_thresholds is None:
            self.alert_thresholds = []

    @property
    def pct_used(self) -> float:
        if not self.budgeted:
            return 0.0
        return self.actual_spend / self.budgeted * 100

    @property
    def status(self) -> str:
        pct = self.pct_used
        if pct >= 100:
            return "EXCEEDED"
        if pct >= 80:
            return "WARNING"
        return "OK"


def list_budgets(budgets_client, account_id: str) -> list[Budget]:
    """
    Return all budgets for *account_id*.

    ``budgets_client`` must be a boto3 ``budgets`` client.  The Budgets API
    endpoint is global but requires an explicit AccountId.
    """
    items: list[Budget] = []
    kwargs: dict = {"AccountId": account_id, "MaxResults": 100}

    while True:
        resp = budgets_client.describe_budgets(**kwargs)
        for raw in resp.get("Budgets", []):
            spend      = raw.get("CalculatedSpend", {})
            actual     = float(spend.get("ActualSpend", {}).get("Amount", 0))
            forecasted = float(spend.get("ForecastedSpend", {}).get("Amount", 0))
            budgeted   = float(raw.get("BudgetLimit", {}).get("Amount", 0))
            unit       = raw.get("BudgetLimit", {}).get("Unit", "USD")
            time_period = raw.get("TimePeriod", {})

            # Collect alert notification thresholds.
            thresholds: list[dict] = []
            for notif in raw.get("Notifications", []):
                thresholds.append({
                    "threshold":         notif.get("Threshold", 0),
                    "type":              notif.get("ThresholdType", "PERCENTAGE"),
                    "comparison":        notif.get("ComparisonOperator", ""),
                    "notification_type": notif.get("NotificationType", ""),
                })

            items.append(Budget(
                name             = raw.get("BudgetName", ""),
                budget_type      = raw.get("BudgetType", "COST"),
                time_unit        = raw.get("TimeUnit", "MONTHLY"),
                budgeted         = budgeted,
                actual_spend     = actual,
                forecasted_spend = forecasted,
                unit             = unit,
                start_date       = time_period.get("Start", ""),
                end_date         = time_period.get("End", ""),
                alert_thresholds = thresholds,
            ))

        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token

    return items
