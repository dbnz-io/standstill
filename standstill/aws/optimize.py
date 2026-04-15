from __future__ import annotations

from dataclasses import dataclass

# ---------------------------------------------------------------------------
# Savings Plans
# ---------------------------------------------------------------------------

@dataclass
class SavingsPlansSummary:
    period_start:    str
    period_end:      str
    utilization_pct: float   # % of purchased SP actually used
    coverage_pct:    float   # % of eligible spend covered by SPs
    net_savings:     float   # estimated net savings vs on-demand
    on_demand_equiv: float   # on-demand cost without SPs
    sp_spend:        float   # amount spent on SP commitments
    unit:            str = "USD"


def get_savings_plans_summary(ce, start: str, end: str) -> SavingsPlansSummary:
    """Fetch SP utilization and coverage for the given monthly period."""
    util_resp = ce.get_savings_plans_utilization(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
    )
    cov_resp = ce.get_savings_plans_coverage(
        TimePeriod={"Start": start, "End": end},
        Granularity="MONTHLY",
    )

    total_util = util_resp.get("Total", {})
    util_pct   = float(total_util.get("Utilization", {}).get("UtilizationPercentage", 0))
    net_sav    = float(total_util.get("Savings", {}).get("NetSavings", 0))
    od_equiv   = float(total_util.get("Savings", {}).get("OnDemandCostEquivalent", 0))
    sp_spend   = float(total_util.get("AmortizedCommitment", {}).get("AmortizedRecurringCommitment", 0))

    coverages = cov_resp.get("SavingsPlansCoverages", [])
    cov_pct = 0.0
    if coverages:
        raw_pct = coverages[0].get("Coverage", {}).get("CoveragePercentage", "0")
        cov_pct = float(raw_pct)

    return SavingsPlansSummary(
        period_start    = start,
        period_end      = end,
        utilization_pct = util_pct,
        coverage_pct    = cov_pct,
        net_savings     = net_sav,
        on_demand_equiv = od_equiv,
        sp_spend        = sp_spend,
    )


# ---------------------------------------------------------------------------
# Reserved Instances
# ---------------------------------------------------------------------------

@dataclass
class RISummary:
    period_start:    str
    period_end:      str
    service:         str
    utilization_pct: float
    coverage_pct:    float
    ri_cost:         float
    on_demand_cost:  float
    net_savings:     float
    unit:            str = "USD"


def get_ri_summary(ce, start: str, end: str) -> list[RISummary]:
    """Fetch RI utilization and coverage, broken down by service."""
    util_resp = ce.get_reservation_utilization(
        TimePeriod={"Start": start, "End": end},
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )
    cov_resp = ce.get_reservation_coverage(
        TimePeriod={"Start": start, "End": end},
        GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
    )

    # Build coverage map: service → pct
    cov_map: dict[str, float] = {}
    for g in cov_resp.get("CoveragesByTime", [{}])[0].get("Groups", []) if cov_resp.get("CoveragesByTime") else []:
        svc = g.get("Attributes", {}).get("SERVICE", "Unknown")
        pct = float(g.get("Coverage", {}).get("CoverageHoursPercentage", 0))
        cov_map[svc] = pct

    results: list[RISummary] = []
    for g in util_resp.get("UtilizationsByTime", [{}])[0].get("Groups", []) if util_resp.get("UtilizationsByTime") else []:
        svc       = g.get("Key", "Unknown")
        util_data = g.get("Utilization", {})
        util_pct  = float(util_data.get("UtilizationPercentage", 0))
        ri_cost   = float(util_data.get("AmortizedRecurringFee", 0))
        on_dem    = float(util_data.get("OnDemandCostOfRIHoursUsed", 0))
        savings   = float(util_data.get("NetRISavings", 0))

        results.append(RISummary(
            period_start    = start,
            period_end      = end,
            service         = svc,
            utilization_pct = util_pct,
            coverage_pct    = cov_map.get(svc, 0.0),
            ri_cost         = ri_cost,
            on_demand_cost  = on_dem,
            net_savings     = savings,
        ))

    return sorted(results, key=lambda r: r.ri_cost, reverse=True)


# ---------------------------------------------------------------------------
# Rightsizing
# ---------------------------------------------------------------------------

@dataclass
class RightsizingRecommendation:
    account_id:          str
    region:              str
    resource_id:         str
    resource_type:       str
    current_instance:    str
    recommended_action:  str          # "Terminate" | "Modify"
    target_instance:     str
    estimated_savings:   float
    estimated_savings_pct: float
    currency:            str = "USD"
    details:             str = ""


def get_rightsizing_recommendations(
    ce,
    service: str = "AmazonEC2",
    lookback_days: int = 14,
) -> list[RightsizingRecommendation]:
    """
    Fetch rightsizing recommendations for a service.

    Note: CE rightsizing only supports ``AmazonEC2`` at this time.
    ``lookback_days`` must be 7 or 14.
    """
    kwargs: dict = {
        "Service": service,
        "Configuration": {
            "RecommendationTarget": "SAME_INSTANCE_FAMILY",
            "BenefitsConsidered": True,
        },
    }

    recs: list[RightsizingRecommendation] = []
    while True:
        resp = ce.get_rightsizing_recommendation(**kwargs)
        for raw in resp.get("RightsizingRecommendations", []):
            curr   = raw.get("CurrentInstance", {})
            action = raw.get("RightsizingType", "")
            savings_data = raw.get("ModifyRecommendationDetail", raw.get("TerminateRecommendationDetail", {}))

            est_savings = float(
                savings_data.get("EstimatedMonthlySavings", "0")
                if isinstance(savings_data.get("EstimatedMonthlySavings"), str)
                else savings_data.get("EstimatedMonthlySavings", 0)
            )
            est_pct = float(
                savings_data.get("EstimatedMonthlySavingsPercentage", "0")
                if isinstance(savings_data.get("EstimatedMonthlySavingsPercentage"), str)
                else savings_data.get("EstimatedMonthlySavingsPercentage", 0)
            )

            target_instance = ""
            if action == "Modify":
                mods = raw.get("ModifyRecommendationDetail", {}).get("TargetInstances", [])
                if mods:
                    target_instance = mods[0].get("ResourceDetails", {}).get(
                        "EC2ResourceDetails", {}
                    ).get("InstanceType", "")

            recs.append(RightsizingRecommendation(
                account_id            = curr.get("ResourceDetails", {}).get("EC2ResourceDetails", {}).get("Region", ""),
                region                = curr.get("ResourceDetails", {}).get("EC2ResourceDetails", {}).get("Region", ""),
                resource_id           = curr.get("ResourceId", ""),
                resource_type         = curr.get("ResourceDetails", {}).get("EC2ResourceDetails", {}).get("InstanceType", ""),
                current_instance      = curr.get("ResourceDetails", {}).get("EC2ResourceDetails", {}).get("InstanceType", ""),
                recommended_action    = action,
                target_instance       = target_instance,
                estimated_savings     = est_savings,
                estimated_savings_pct = est_pct,
            ))

        next_token = resp.get("NextPageToken")
        if not next_token:
            break
        kwargs["NextPageToken"] = next_token

    return sorted(recs, key=lambda r: r.estimated_savings, reverse=True)
