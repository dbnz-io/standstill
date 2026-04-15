from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import date


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class CostGroup:
    key: str
    amount: float
    unit: str = "USD"


@dataclass
class CostPeriod:
    start: str
    end: str
    groups: list[CostGroup] = field(default_factory=list)
    total: float = 0.0
    unit: str = "USD"
    estimated: bool = False


# ---------------------------------------------------------------------------
# Internal mappings
# ---------------------------------------------------------------------------

_METRIC_KEYS: dict[str, str] = {
    "unblended":    "UnblendedCost",
    "blended":      "BlendedCost",
    "amortized":    "AmortizedCost",
    "net-amortized": "NetAmortizedCost",
}

_DIMENSION_KEYS: dict[str, str] = {
    "service":    "SERVICE",
    "usage-type": "USAGE_TYPE",
    "account":    "LINKED_ACCOUNT",
    "region":     "REGION",
}

# Dimensions accepted in the --filter option.  Superset of _DIMENSION_KEYS
# because you may want to filter by a dimension you are not grouping by.
_FILTER_DIMENSION_KEYS: dict[str, str] = {
    "service":       "SERVICE",
    "usage-type":    "USAGE_TYPE",
    "account":       "LINKED_ACCOUNT",
    "region":        "REGION",
    "az":            "AZ",
    "instance-type": "INSTANCE_TYPE",
    "operation":     "OPERATION",
    "platform":      "PLATFORM",
    "purchase-type": "PURCHASE_TYPE",
}


def _build_ce_filter(filters: list[tuple[str, list[str]]]) -> dict | None:
    """
    Build a CE ``Filter`` dict from a list of ``(dimension_name, [values])`` pairs.

    Dimension names prefixed with ``tag:`` (e.g. ``"tag:Environment"``) generate
    a CE Tags clause instead of a Dimensions clause.

    Multiple values within a pair are OR'd (single Dimensions/Tags clause with a list).
    Multiple pairs are AND'd (wrapped in ``And``).
    Returns ``None`` when *filters* is empty.
    """
    if not filters:
        return None

    clauses = []
    for dim_name, values in filters:
        if dim_name.lower().startswith("tag:"):
            tag_key = dim_name[4:]
            clauses.append({
                "Tags": {
                    "Key": tag_key,
                    "Values": values,
                    "MatchOptions": ["EQUALS"],
                }
            })
        else:
            dim_key = _FILTER_DIMENSION_KEYS.get(dim_name.lower())
            if dim_key is None:
                known = ", ".join(sorted(_FILTER_DIMENSION_KEYS))
                raise ValueError(
                    f"Unknown filter dimension '{dim_name}'. "
                    f"Valid options: {known}, or tag:KEY (e.g. tag:Environment)"
                )
            clauses.append({
                "Dimensions": {
                    "Key": dim_key,
                    "Values": values,
                    "MatchOptions": ["EQUALS"],
                }
            })

    return clauses[0] if len(clauses) == 1 else {"And": clauses}


# Abbreviations whose short name does not literally appear in the CE service
# string.  Maps the short name → search term used for substring matching.
_SERVICE_SEARCH_EXPANSIONS: dict[str, str] = {
    "ec2":          "elastic compute cloud|ec2",
    "ebs":          "elastic block store",
    "elb":          "elastic load balancing",
    "alb":          "elastic load balancing",
    "nlb":          "elastic load balancing",
    "ecs":          "elastic container service",
    "ecr":          "container registry",
    "eks":          "elastic kubernetes",
    "efs":          "elastic file system",
    "fsx":          "amazon fsx",
    "s3":           "simple storage service",
    "glacier":      "s3 glacier",
    "rds":          "relational database",
    "vpc":          "virtual private cloud",
    "sqs":          "simple queue service",
    "sns":          "simple notification service",
    "ses":          "simple email service",
    "msk":          "managed streaming",
    "emr":          "amazon emr",
}


def service_filter_alias(service_name: str) -> str:
    """
    Return the shortest ``--filter service=`` alias for *service_name*, or an
    empty string if no alias is defined.

    When multiple aliases map to the same service (e.g. ``elb``/``alb``/``nlb``
    all match ``"Elastic Load Balancing"``) the first one in insertion order is
    returned.  Duplicates with the same search expansion (like alb/nlb) are
    deduplicated so only one representative alias is shown.
    """
    lower = service_name.lower()
    seen_expansions: set[str] = set()
    for alias, raw_expansion in _SERVICE_SEARCH_EXPANSIONS.items():
        if raw_expansion in seen_expansions:
            continue
        seen_expansions.add(raw_expansion)
        needles = [t.strip() for t in raw_expansion.split("|")]
        if any(n in lower for n in needles):
            return alias
    return ""


def resolve_service_filter(ce, value: str, start: str, end: str) -> list[str]:
    """
    Resolve a user-supplied service name into the exact CE service name(s).

    * Full names (contain a space, or start with ``Amazon``/``AWS``) are
      returned as-is without an API lookup.
    * Short names (e.g. ``"ec2"``, ``"s3"``) are expanded via
      :data:`_SERVICE_SEARCH_EXPANSIONS` when the abbreviation does not
      appear literally in CE service strings, then matched case-insensitively
      against the live CE dimension-value list for the period.
    * If no services match the expanded search term the raw value is returned
      so the CE API can surface a meaningful error.
    """
    looks_like_full_name = (
        " " in value
        or value.lower().startswith("amazon")
        or value.lower().startswith("aws")
    )
    if looks_like_full_name:
        return [value]

    raw_needle = _SERVICE_SEARCH_EXPANSIONS.get(value.lower(), value.lower())
    # Expansion values may contain "|" to express multiple search terms (OR).
    needles = [t.strip() for t in raw_needle.split("|")]
    all_services = list_services(ce, start, end)
    matches = [
        s for s in all_services
        if any(n in s.lower() for n in needles)
    ]
    return matches if matches else [value]


# ---------------------------------------------------------------------------
# API functions
# ---------------------------------------------------------------------------

def get_cost_and_usage(
    ce,
    start: str,
    end: str,
    granularity: str,
    dimension: str,
    filters: list[tuple[str, list[str]]] | None = None,
    metric: str = "unblended",
    top: int | None = None,
    min_cost: float = 0.01,
) -> list[CostPeriod]:
    """
    Fetch cost and usage from Cost Explorer, grouped by *dimension*.

    Args:
        ce:          boto3 ``ce`` client (must be in ``us-east-1``).
        start:       ISO date string, inclusive (e.g. ``"2024-01-01"``).
        end:         ISO date string, exclusive (e.g. ``"2024-02-01"``).
        granularity: ``"MONTHLY"`` or ``"DAILY"``.
        dimension:   One of ``"service"``, ``"usage-type"``, ``"account"``, ``"region"``.
        filters:     List of ``(dimension_name, [values])`` pairs.  Values within a
                     pair are OR'd; pairs are AND'd.  Supported dimension names:
                     service, usage-type, account, region, az, instance-type,
                     operation, platform, purchase-type.
        metric:      One of ``"unblended"``, ``"blended"``, ``"amortized"``.
        top:         Keep only the top *N* groups per period (by cost).
        min_cost:    Drop groups whose cost is below this threshold.

    Returns:
        One :class:`CostPeriod` per time-period bucket returned by the API.
    """
    metric_key = _METRIC_KEYS.get(metric, "UnblendedCost")

    if dimension.startswith("tag:"):
        tag_key = dimension[4:]
        group_by_clause = [{"Type": "TAG", "Key": tag_key}]
    else:
        dim_key = _DIMENSION_KEYS.get(dimension, "SERVICE")
        group_by_clause = [{"Type": "DIMENSION", "Key": dim_key}]

    kwargs: dict = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": granularity,
        "GroupBy": group_by_clause,
        "Metrics": [metric_key],
    }

    ce_filter = _build_ce_filter(filters or [])
    if ce_filter:
        kwargs["Filter"] = ce_filter

    # Cost Explorer uses NextPageToken pagination (not standard paginators).
    results_by_time: list[dict] = []
    next_token: str | None = None
    while True:
        if next_token:
            kwargs["NextPageToken"] = next_token
        resp = ce.get_cost_and_usage(**kwargs)
        results_by_time.extend(resp.get("ResultsByTime", []))
        next_token = resp.get("NextPageToken")
        if not next_token:
            break

    periods: list[CostPeriod] = []
    for result in results_by_time:
        period_start = result["TimePeriod"]["Start"]
        period_end = result["TimePeriod"]["End"]
        estimated = result.get("Estimated", False)

        groups: list[CostGroup] = []
        for g in result.get("Groups", []):
            keys = g.get("Keys", [])
            key = keys[0] if keys else "Unknown"
            metrics = g.get("Metrics", {})
            cost_data = metrics.get(metric_key, {})
            amount = float(cost_data.get("Amount", 0))
            unit = cost_data.get("Unit", "USD")
            if amount >= min_cost:
                groups.append(CostGroup(key=key, amount=amount, unit=unit))

        groups.sort(key=lambda x: x.amount, reverse=True)
        if top is not None:
            groups = groups[:top]

        total_data = result.get("Total", {}).get(metric_key, {})
        if total_data and total_data.get("Amount"):
            total = float(total_data["Amount"])
            unit = total_data.get("Unit", "USD")
        else:
            total = sum(g.amount for g in groups)
            unit = groups[0].unit if groups else "USD"

        periods.append(CostPeriod(
            start=period_start,
            end=period_end,
            groups=groups,
            total=total,
            unit=unit,
            estimated=estimated,
        ))

    return periods


def list_services(ce, start: str, end: str) -> list[str]:
    """
    Return all AWS service names that incurred costs in the given period,
    ordered by cost descending.
    """
    resp = ce.get_dimension_values(
        TimePeriod={"Start": start, "End": end},
        Dimension="SERVICE",
        Context="COST_AND_USAGE",
        SortBy=[{"Key": "BlendedCost", "SortOrder": "DESCENDING"}],
    )
    return [item["Value"] for item in resp.get("DimensionValues", []) if item.get("Value")]


def get_forecast(ce, start: str, end: str, metric: str = "unblended") -> dict:
    """
    Fetch a monthly cost forecast from Cost Explorer.

    Args:
        ce:     boto3 ``ce`` client.
        start:  First future date to forecast from (today or later).
        end:    Last date (exclusive) to forecast to.
        metric: One of ``"unblended"``, ``"blended"``, ``"amortized"``.

    Returns:
        Dict with keys ``total``, ``unit``, and ``monthly`` (list of period dicts).
    """
    metric_key = _METRIC_KEYS.get(metric, "UnblendedCost")
    resp = ce.get_cost_forecast(
        TimePeriod={"Start": start, "End": end},
        Metric=metric_key,
        Granularity="MONTHLY",
    )
    total = float(resp.get("Total", {}).get("Amount", 0))
    unit = resp.get("Total", {}).get("Unit", "USD")
    monthly = [
        {
            "start": r["TimePeriod"]["Start"],
            "end":   r["TimePeriod"]["End"],
            "amount": float(r.get("MeanValue", 0)),
            "lower":  float(r.get("PredictionIntervalLowerBound", 0)),
            "upper":  float(r.get("PredictionIntervalUpperBound", 0)),
        }
        for r in resp.get("ForecastResultsByTime", [])
    ]
    return {"total": total, "unit": unit, "monthly": monthly}


def get_service_costs(
    ce,
    start: str,
    end: str,
    metric: str = "unblended",
) -> dict[str, float]:
    """
    Return ``{service_name: total_cost}`` aggregated over the full period.

    Uses a single ``get_cost_and_usage`` call with monthly granularity and
    SERVICE group-by, then sums across all months.
    """
    metric_key = _METRIC_KEYS.get(metric, "UnblendedCost")
    kwargs: dict = {
        "TimePeriod": {"Start": start, "End": end},
        "Granularity": "MONTHLY",
        "GroupBy": [{"Type": "DIMENSION", "Key": "SERVICE"}],
        "Metrics": [metric_key],
    }
    costs: dict[str, float] = {}
    next_token: str | None = None
    while True:
        if next_token:
            kwargs["NextPageToken"] = next_token
        resp = ce.get_cost_and_usage(**kwargs)
        for result in resp.get("ResultsByTime", []):
            for g in result.get("Groups", []):
                key = g["Keys"][0]
                amount = float(g["Metrics"].get(metric_key, {}).get("Amount", 0))
                costs[key] = costs.get(key, 0.0) + amount
        next_token = resp.get("NextPageToken")
        if not next_token:
            break
    return costs


def compute_prior_period(start: str, end: str) -> tuple[str, str]:
    """
    Return the immediately preceding period of the same length.

    E.g. March 2024 (2024-03-01 → 2024-04-01) → February 2024 (2024-02-01 → 2024-03-01).
    """
    from datetime import timedelta
    s = date.fromisoformat(start)
    e = date.fromisoformat(end)
    delta = e - s
    prior_end = s
    prior_start = s - delta
    return prior_start.isoformat(), prior_end.isoformat()


def get_forecast_by_service(
    ce,
    start: str,
    end: str,
    metric: str = "unblended",
    top_n: int = 10,
) -> list[dict]:
    """
    Fan-out monthly forecasts per top service in parallel.

    CE does not support GroupBy on ``get_cost_forecast``, so we:
    1. Fetch the top *top_n* services by cost in the preceding 30 days.
    2. Build a per-service CE filter and call ``get_cost_forecast`` in parallel.

    Returns a list of ``{"service", "total", "unit", "monthly": [...]}`` dicts,
    sorted by total forecast cost descending.
    """
    from datetime import timedelta

    # Determine a recent lookback window to rank services.
    end_date   = date.fromisoformat(start)   # forecast starts here
    start_date = end_date - timedelta(days=30)
    service_costs = get_service_costs(
        ce,
        start=start_date.isoformat(),
        end=end_date.isoformat(),
        metric=metric,
    )
    top_services = sorted(service_costs, key=lambda s: service_costs[s], reverse=True)[:top_n]

    metric_key = _METRIC_KEYS.get(metric, "UnblendedCost")

    def _forecast_one(svc: str) -> dict:
        try:
            resp = ce.get_cost_forecast(
                TimePeriod={"Start": start, "End": end},
                Metric=metric_key,
                Granularity="MONTHLY",
                Filter={"Dimensions": {"Key": "SERVICE", "Values": [svc], "MatchOptions": ["EQUALS"]}},
            )
            total = float(resp.get("Total", {}).get("Amount", 0))
            unit  = resp.get("Total", {}).get("Unit", "USD")
            monthly = [
                {
                    "start":  r["TimePeriod"]["Start"],
                    "end":    r["TimePeriod"]["End"],
                    "amount": float(r.get("MeanValue", 0)),
                    "lower":  float(r.get("PredictionIntervalLowerBound", 0)),
                    "upper":  float(r.get("PredictionIntervalUpperBound", 0)),
                }
                for r in resp.get("ForecastResultsByTime", [])
            ]
            return {"service": svc, "total": total, "unit": unit, "monthly": monthly}
        except Exception:  # noqa: BLE001
            return {"service": svc, "total": 0.0, "unit": "USD", "monthly": [], "error": True}

    results: list[dict] = []
    with ThreadPoolExecutor(max_workers=min(len(top_services), 8)) as pool:
        futures = {pool.submit(_forecast_one, svc): svc for svc in top_services}
        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda r: r["total"], reverse=True)


# ---------------------------------------------------------------------------
# Anomalies
# ---------------------------------------------------------------------------

@dataclass
class Anomaly:
    anomaly_id:     str
    service:        str
    region:         str
    account_id:     str
    start_date:     str
    end_date:       str
    impact_max:     float
    impact_total:   float
    expected:       float
    unit:           str = "USD"
    root_cause:     str = ""
    monitor_arn:    str = ""
    feedback:       str = ""


def get_anomalies(
    ce,
    days_back: int = 90,
    min_impact: float = 0.0,
    monitor_arn: str | None = None,
) -> list[Anomaly]:
    """
    Fetch cost anomalies detected by Cost Explorer Anomaly Detection.

    Args:
        ce:          boto3 ``ce`` client.
        days_back:   How many days into the past to look (max 90).
        min_impact:  Minimum total impact in USD to include.
        monitor_arn: Optionally scope to a specific anomaly monitor.
    """
    from datetime import timedelta
    end   = date.today()
    start = end - timedelta(days=min(days_back, 90))

    kwargs: dict = {
        "DateInterval": {
            "StartDate": start.isoformat(),
            "EndDate":   end.isoformat(),
        },
        "SortBy": {"Key": "IMPACT_TOTAL_NET_UNBLENDED_COST", "SortOrder": "DESCENDING"},
        "MaxResults": 100,
    }
    if min_impact > 0:
        kwargs["TotalImpact"] = {"NumericOperator": "GREATER_THAN", "StartValue": min_impact}
    if monitor_arn:
        kwargs["MonitorArn"] = monitor_arn

    anomalies: list[Anomaly] = []
    while True:
        resp = ce.get_anomalies(**kwargs)
        for raw in resp.get("Anomalies", []):
            impact     = raw.get("Impact", {})
            root_causes = raw.get("RootCauses", [])
            root_cause  = ""
            if root_causes:
                rc = root_causes[0]
                parts = [
                    rc.get("Service", ""),
                    rc.get("Region", ""),
                    rc.get("UsageType", ""),
                ]
                root_cause = " / ".join(p for p in parts if p)

            anomalies.append(Anomaly(
                anomaly_id   = raw.get("AnomalyId", ""),
                service      = raw.get("DimensionValue", ""),
                region       = (root_causes[0].get("Region", "") if root_causes else ""),
                account_id   = (root_causes[0].get("LinkedAccount", "") if root_causes else ""),
                start_date   = raw.get("AnomalyStartDate", ""),
                end_date     = raw.get("AnomalyEndDate", ""),
                impact_max   = float(impact.get("MaxImpact", 0)),
                impact_total = float(impact.get("TotalImpact", 0)),
                expected     = float(impact.get("TotalExpectedSpend", 0)),
                root_cause   = root_cause,
                monitor_arn  = raw.get("MonitorArn", ""),
                feedback     = raw.get("Feedback", ""),
            ))

        next_token = resp.get("NextPageToken")
        if not next_token:
            break
        kwargs["NextPageToken"] = next_token

    return anomalies
