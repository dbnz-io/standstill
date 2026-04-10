from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError

from standstill import state as _state

if TYPE_CHECKING:
    from standstill.models.security_config import SecurityServicesConfig

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SERVICE_PRINCIPALS: dict[str, str] = {
    "guardduty":       "guardduty.amazonaws.com",
    "security_hub":    "securityhub.amazonaws.com",
    "macie":           "macie.amazonaws.com",
    "inspector":       "inspector2.amazonaws.com",
    "access_analyzer": "access-analyzer.amazonaws.com",
}

SECURITY_HUB_STANDARD_ARNS: dict[str, str] = {
    "fsbp":    "arn:aws:securityhub:{r}::standards/aws-foundational-security-best-practices/v/1.0.0",
    "cis_1_4": "arn:aws:securityhub:{r}::standards/cis-aws-foundations-benchmark/v/1.4.0",
    "cis_3_0": "arn:aws:securityhub:{r}::standards/cis-aws-foundations-benchmark/v/3.0.0",
    "pci_dss": "arn:aws:securityhub:{r}::standards/pci-dss/v/3.2.1",
    "nist":    "arn:aws:securityhub:{r}::standards/nist-800-53/v/5.0.0",
}

GUARDDUTY_FEATURE_MAP: dict[str, str] = {
    "s3_logs":             "S3_DATA_EVENTS",
    "eks_audit_logs":      "EKS_AUDIT_LOGS",
    "eks_runtime":         "EKS_RUNTIME_MONITORING",
    "ecs_runtime":         "ECS_RUNTIME_MONITORING",
    "ec2_malware_scan":    "EBS_MALWARE_PROTECTION",
    "lambda_network_logs": "LAMBDA_NETWORK_LOGS",
    "rds_login_events":    "RDS_LOGIN_EVENTS",
}


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class MemberServiceStatus:
    enabled: bool        # True when the account is actively enrolled and sending findings
    member_status: str   # raw status string from the API, or sentinel like "not_member"
    error: str = ""


@dataclass
class AccountAssessment:
    account_id: str
    account_name: str
    ou_name: str
    services: dict[str, MemberServiceStatus] = field(default_factory=dict)

    @property
    def healthy(self) -> bool:
        """True when every assessed service is enabled (or not applicable)."""
        return all(
            s.enabled or s.member_status in ("delegated_admin", "management_account", "org_wide")
            for s in self.services.values()
        )


@dataclass
class DelegationStatus:
    service: str
    principal: str
    current_admin: str | None  # account ID or None
    target_admin: str
    action: str  # "register" | "skip" | "conflict" | "error"
    error: str = ""


@dataclass
class ServiceApplyResult:
    service: str
    phase: str   # "delegation" | "configuration"
    success: bool
    message: str
    details: list[str] = field(default_factory=list)


@dataclass
class ServiceStatus:
    service: str
    delegated_admin: str | None
    enabled: bool
    auto_enable: str
    details: dict[str, str | bool]
    error: str = ""


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def _admin_client(service: str, admin_account_id: str, role_name: str, region: str):
    """
    Return a boto3 client for `service` scoped to the delegated admin account.
    Assumes the CT execution role there via the current management session.
    """
    role_arn = f"arn:aws:iam::{admin_account_id}:role/{role_name}"
    sts = _state.state.get_client("sts")
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"standstill-sec-{os.getpid()}")
    except ClientError as exc:
        raise RuntimeError(
            f"Cannot assume {role_arn}: {exc.response['Error']['Message']}"
        ) from exc
    creds = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    return session.client(service, region_name=region)


# ---------------------------------------------------------------------------
# Delegation — Phase 1 (called from management account)
# ---------------------------------------------------------------------------

def check_delegated_admins(target_account: str, region: str) -> list[DelegationStatus]:
    """
    Check which services already have a delegated administrator registered,
    and compute the action needed for each.
    """
    org = _state.state.get_client("organizations", region_name=region)
    statuses: list[DelegationStatus] = []

    for svc, principal in SERVICE_PRINCIPALS.items():
        try:
            resp = org.list_delegated_administrators(ServicePrincipal=principal)
            admins = resp.get("DelegatedAdministrators", [])
            current = admins[0]["Id"] if admins else None
        except ClientError as exc:
            statuses.append(DelegationStatus(
                service=svc, principal=principal,
                current_admin=None, target_admin=target_account,
                action="error", error=exc.response["Error"]["Message"],
            ))
            continue

        if current is None:
            action = "register"
        elif current == target_account:
            action = "skip"
        else:
            action = "conflict"  # different account already registered

        statuses.append(DelegationStatus(
            service=svc, principal=principal,
            current_admin=current, target_admin=target_account,
            action=action,
        ))

    return statuses


def register_delegated_admin(
    service: str,
    target_account: str,
    region: str,
) -> ServiceApplyResult:
    """Register the delegated administrator for a single service."""
    try:
        if service == "guardduty":
            gd = _state.state.get_client("guardduty", region_name=region)
            gd.enable_organization_admin_account(AdminAccountId=target_account)

        elif service == "security_hub":
            sh = _state.state.get_client("securityhub", region_name=region)
            sh.enable_organization_admin_account(AdminAccountId=target_account)

        elif service == "macie":
            mc = _state.state.get_client("macie2", region_name=region)
            mc.enable_organization_admin_account(AdminAccountId=target_account)

        elif service == "inspector":
            ins = _state.state.get_client("inspector2", region_name=region)
            ins.enable_delegated_admin_account(DelegatedAdminAccountId=target_account)

        elif service == "access_analyzer":
            org = _state.state.get_client("organizations", region_name=region)
            org.register_delegated_administrator(
                AccountId=target_account,
                ServicePrincipal=SERVICE_PRINCIPALS["access_analyzer"],
            )

        return ServiceApplyResult(
            service=service, phase="delegation", success=True,
            message=f"Delegated admin registered: {target_account}",
        )

    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        # Already registered by another path
        if code in ("AccountAlreadyRegisteredException", "AlreadyExistsException"):
            return ServiceApplyResult(
                service=service, phase="delegation", success=True,
                message="Already registered (skipped).",
            )
        return ServiceApplyResult(
            service=service, phase="delegation", success=False,
            message=exc.response["Error"]["Message"],
        )


# ---------------------------------------------------------------------------
# Configuration — Phase 2 (called from delegated admin account)
# ---------------------------------------------------------------------------

def configure_guardduty(
    cfg,  # GuardDutyConfig
    admin_account: str,
    role_name: str,
    region: str,
) -> ServiceApplyResult:
    result = ServiceApplyResult(service="guardduty", phase="configuration", success=False, message="")
    try:
        gd = _admin_client("guardduty", admin_account, role_name, region)
        freq = cfg.detector.finding_publishing_frequency
        auto = cfg.organization.auto_enable

        # Ensure a detector exists in the delegated admin account
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            resp = gd.create_detector(Enable=True, FindingPublishingFrequency=freq)
            detector_id = resp["DetectorId"]
            result.details.append(f"Detector created: {detector_id}")
        else:
            detector_id = detectors[0]
            gd.update_detector(DetectorId=detector_id, FindingPublishingFrequency=freq)

        # Build features list from protection_plans config
        plans = cfg.protection_plans
        features = [
            {
                "Name": api_name,
                "AutoEnable": auto if getattr(plans, cfg_key) else "NONE",
            }
            for cfg_key, api_name in GUARDDUTY_FEATURE_MAP.items()
        ]

        gd.update_organization_configuration(
            DetectorId=detector_id,
            AutoEnable=auto,
            Features=features,
        )

        enabled_plans = [k for k in GUARDDUTY_FEATURE_MAP if getattr(plans, k)]
        result.success = True
        result.message = (
            f"auto-enable={auto}, freq={freq.lower()}, "
            f"plans=[{', '.join(enabled_plans) or 'none'}]"
        )
    except (ClientError, RuntimeError) as exc:
        result.message = str(exc)
    return result


def configure_security_hub(
    cfg,  # SecurityHubConfig
    admin_account: str,
    role_name: str,
    region: str,
) -> ServiceApplyResult:
    result = ServiceApplyResult(service="security_hub", phase="configuration", success=False, message="")
    try:
        sh = _admin_client("securityhub", admin_account, role_name, region)

        # Enable Security Hub if not already enabled
        try:
            sh.enable_security_hub(EnableDefaultStandards=False)
            result.details.append("Security Hub enabled.")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceConflictException":
                raise

        # Org auto-enable
        auto = cfg.organization.auto_enable
        auto_enable_standards = "DEFAULT" if auto == "ALL" else "NONE"
        sh.update_organization_configuration(
            AutoEnable=auto != "NONE",
            AutoEnableStandards=auto_enable_standards,
        )

        # Enable requested standards
        standards = cfg.standards
        to_enable = [
            key for key, flag in {
                "fsbp": standards.fsbp,
                "cis_1_4": standards.cis_1_4,
                "cis_3_0": standards.cis_3_0,
                "pci_dss": standards.pci_dss,
                "nist": standards.nist,
            }.items()
            if flag
        ]

        if to_enable:
            arns = [SECURITY_HUB_STANDARD_ARNS[k].replace("{r}", region) for k in to_enable]
            current = {
                s["StandardsArn"]
                for s in sh.get_enabled_standards().get("StandardsSubscriptions", [])
            }
            new_arns = [a for a in arns if a not in current]
            if new_arns:
                sh.batch_enable_standards(
                    StandardsSubscriptionRequests=[{"StandardsArn": a} for a in new_arns]
                )
                result.details.append(f"Standards enabled: {', '.join(to_enable)}")

        # Cross-region aggregation
        if cfg.cross_region_aggregation:
            try:
                existing_agg = sh.list_finding_aggregators().get("FindingAggregators", [])
                if existing_agg:
                    sh.update_finding_aggregator(
                        FindingAggregatorArn=existing_agg[0]["FindingAggregatorArn"],
                        RegionLinkingMode="ALL_REGIONS",
                    )
                    result.details.append("Cross-region aggregation updated.")
                else:
                    sh.create_finding_aggregator(RegionLinkingMode="ALL_REGIONS")
                    result.details.append("Cross-region aggregation enabled.")
            except ClientError as exc:
                result.details.append(
                    f"Cross-region aggregation: {exc.response['Error']['Message']}"
                )

        result.success = True
        result.message = (
            f"auto-enable={auto}, standards=[{', '.join(to_enable) or 'none'}]"
        )
    except (ClientError, RuntimeError) as exc:
        result.message = str(exc)
    return result


def configure_macie(
    cfg,  # MacieConfig
    admin_account: str,
    role_name: str,
    region: str,
) -> ServiceApplyResult:
    result = ServiceApplyResult(service="macie", phase="configuration", success=False, message="")
    try:
        mc = _admin_client("macie2", admin_account, role_name, region)

        freq = cfg.session.finding_publishing_frequency
        auto = cfg.organization.auto_enable
        disc = cfg.automated_discovery

        # Enable Macie if not already enabled
        try:
            mc.enable_macie(findingPublishingFrequency=freq)
            result.details.append("Macie enabled.")
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("ValidationException", "ConflictException"):
                raise
            mc.update_macie_session(findingPublishingFrequency=freq)

        mc.update_organization_configuration(autoEnable=auto)

        disc_status = "ENABLED" if disc.enabled else "DISABLED"
        try:
            disc_kwargs: dict = {"status": disc_status}
            if disc.enabled:
                disc_kwargs["autoEnableOrganizationMembers"] = auto
            mc.update_automated_discovery_configuration(**disc_kwargs)
        except ClientError:
            pass  # not available in all regions

        result.success = True
        result.message = (
            f"auto-enable={auto}, freq={freq.lower()}, "
            f"automated-discovery={disc_status.lower()}"
            + (f" (sampling={disc.sampling_depth}%)" if disc.enabled else "")
        )
    except (ClientError, RuntimeError) as exc:
        result.message = str(exc)
    return result


def configure_inspector(
    cfg,  # InspectorConfig
    admin_account: str,
    role_name: str,
    region: str,
) -> ServiceApplyResult:
    result = ServiceApplyResult(service="inspector", phase="configuration", success=False, message="")
    try:
        ins = _admin_client("inspector2", admin_account, role_name, region)
        st = cfg.scan_types
        auto = cfg.organization.auto_enable

        resource_types: list[str] = []
        if st.ec2:
            resource_types.append("EC2")
        if st.ecr:
            resource_types.append("ECR")
        if st.lambda_functions:
            resource_types.append("LAMBDA")
        if st.lambda_code:
            resource_types.append("LAMBDA_CODE")

        if resource_types:
            try:
                ins.enable(accountIds=[admin_account], resourceTypes=resource_types)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ValidationException":
                    raise

        ins.update_organization_configuration(
            autoEnable={
                "ec2": st.ec2 and auto,
                "ecr": st.ecr and auto,
                "lambda": st.lambda_functions and auto,
                "lambdaCode": st.lambda_code and auto,
            }
        )

        result.success = True
        result.message = (
            f"auto-enable={auto}, "
            f"scan-types=[{', '.join(t.lower() for t in resource_types) or 'none'}]"
        )
    except (ClientError, RuntimeError) as exc:
        result.message = str(exc)
    return result


def configure_access_analyzer(
    cfg,  # AccessAnalyzerConfig
    admin_account: str,
    role_name: str,
    region: str,
) -> ServiceApplyResult:
    result = ServiceApplyResult(service="access_analyzer", phase="configuration", success=False, message="")
    try:
        aa = _admin_client("accessanalyzer", admin_account, role_name, region)

        existing = {
            a["name"]: a["type"]
            for a in aa.list_analyzers().get("analyzers", [])
        }

        for entry in cfg.analyzers:
            if entry.name not in existing:
                aa.create_analyzer(analyzerName=entry.name, type=entry.type)
                result.details.append(f"Created: {entry.name} ({entry.type})")
            else:
                result.details.append(f"Exists:  {entry.name} ({entry.type})")

        names = [e.name for e in cfg.analyzers]
        result.success = True
        result.message = f"analyzers=[{', '.join(names)}]"
    except (ClientError, RuntimeError) as exc:
        result.message = str(exc)
    return result


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------

def get_service_statuses(
    target_account: str,
    role_name: str,
    region: str,
) -> list[ServiceStatus]:
    """
    Read the current live state of each security service.
    Phase 1 info (delegated admin) comes from the management account.
    Phase 2 info (service config) comes from the delegated admin account.
    """
    delegation = {d.service: d for d in check_delegated_admins(target_account, region)}
    statuses: list[ServiceStatus] = []

    for svc in SERVICE_PRINCIPALS:
        d = delegation.get(svc)
        current_admin = d.current_admin if d else None
        base = ServiceStatus(
            service=svc,
            delegated_admin=current_admin,
            enabled=False,
            auto_enable="—",
            details={},
        )

        if current_admin != target_account:
            base.error = "Delegated admin not registered" if not current_admin else f"Different admin: {current_admin}"
            statuses.append(base)
            continue

        try:
            _fill_service_status(base, svc, target_account, role_name, region)
        except Exception as exc:
            base.error = str(exc)

        statuses.append(base)

    return statuses


def _fill_service_status(
    status: ServiceStatus,
    service: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> None:
    """Populate the service-specific fields of a ServiceStatus in-place."""
    if service == "guardduty":
        gd = _admin_client("guardduty", admin_account, role_name, region)
        detectors = gd.list_detectors().get("DetectorIds", [])
        if not detectors:
            return
        det = gd.get_detector(DetectorId=detectors[0])
        status.enabled = det.get("Status") == "ENABLED"
        status.auto_enable = det.get("FindingPublishingFrequency", "—")
        try:
            org_cfg = gd.describe_organization_configuration(DetectorId=detectors[0])
            status.auto_enable = org_cfg.get("AutoEnable", "—")
        except ClientError:
            pass

    elif service == "security_hub":
        sh = _admin_client("securityhub", admin_account, role_name, region)
        try:
            sh.describe_hub()
            status.enabled = True
            org_cfg = sh.describe_organization_configuration()
            status.auto_enable = "ALL" if org_cfg.get("AutoEnable") else "NONE"
            subs = sh.get_enabled_standards().get("StandardsSubscriptions", [])
            status.details["standards_count"] = str(len(subs))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidAccessException":
                status.enabled = False

    elif service == "macie":
        mc = _admin_client("macie2", admin_account, role_name, region)
        try:
            session = mc.get_macie_session()
            status.enabled = session.get("status") == "ENABLED"
            status.auto_enable = str(session.get("findingPublishingFrequency", "—"))
            org_cfg = mc.describe_organization_configuration()
            status.auto_enable = str(org_cfg.get("autoEnable", "—"))
            disc = mc.get_automated_discovery_configuration()
            status.details["automated_discovery"] = disc.get("status", "—")
        except ClientError:
            pass

    elif service == "inspector":
        ins = _admin_client("inspector2", admin_account, role_name, region)
        try:
            org_cfg = ins.describe_organization_configuration()
            auto = org_cfg.get("autoEnable", {})
            status.enabled = True
            status.auto_enable = "ON" if any(auto.values()) else "OFF"
            status.details = {k: str(v) for k, v in auto.items()}
        except ClientError:
            pass

    elif service == "access_analyzer":
        aa = _admin_client("accessanalyzer", admin_account, role_name, region)
        try:
            analyzers = aa.list_analyzers().get("analyzers", [])
            org_analyzers = [a for a in analyzers if "ORGANIZATION" in a.get("type", "")]
            status.enabled = bool(org_analyzers)
            status.auto_enable = "N/A"
            status.details["analyzers"] = ", ".join(a["name"] for a in org_analyzers) or "none"
        except ClientError:
            pass


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def apply_services(
    config: SecurityServicesConfig,
    role_name: str,
    region: str,
) -> tuple[list[ServiceApplyResult], list[ServiceApplyResult]]:
    """
    Run Phase 1 (delegation) and Phase 2 (configuration) for all enabled services.
    Returns (phase1_results, phase2_results).
    """
    admin = config.delegated_admin_account
    svc_cfg = config.services

    enabled_map = {
        "guardduty":       (svc_cfg.guardduty.enabled,       svc_cfg.guardduty),
        "security_hub":    (svc_cfg.security_hub.enabled,     svc_cfg.security_hub),
        "macie":           (svc_cfg.macie.enabled,            svc_cfg.macie),
        "inspector":       (svc_cfg.inspector.enabled,        svc_cfg.inspector),
        "access_analyzer": (svc_cfg.access_analyzer.enabled,  svc_cfg.access_analyzer),
    }

    # Phase 1 — delegation
    phase1: list[ServiceApplyResult] = []
    delegation_check = {d.service: d for d in check_delegated_admins(admin, region)}

    for svc, (enabled, _cfg) in enabled_map.items():
        if not enabled:
            continue
        d = delegation_check.get(svc)
        if d and d.action == "skip":
            phase1.append(ServiceApplyResult(
                service=svc, phase="delegation",
                success=True, message="Already registered (skipped).",
            ))
        elif d and d.action == "conflict":
            phase1.append(ServiceApplyResult(
                service=svc, phase="delegation",
                success=False,
                message=f"Another account ({d.current_admin}) is already delegated admin.",
            ))
        else:
            phase1.append(register_delegated_admin(svc, admin, region))

    # Abort Phase 2 for services that failed delegation
    failed_svcs = {r.service for r in phase1 if not r.success}

    # Phase 2 — configuration
    phase2: list[ServiceApplyResult] = []
    configurators = {
        "guardduty":       configure_guardduty,
        "security_hub":    configure_security_hub,
        "macie":           configure_macie,
        "inspector":       configure_inspector,
        "access_analyzer": configure_access_analyzer,
    }

    for svc, (enabled, svc_config) in enabled_map.items():
        if not enabled or svc in failed_svcs:
            continue
        phase2.append(configurators[svc](svc_config, admin, role_name, region))

    return phase1, phase2


# ---------------------------------------------------------------------------
# Assessment — per-account member coverage
# ---------------------------------------------------------------------------

def _members_guardduty(admin_account: str, role_name: str, region: str) -> dict[str, str]:
    """Return {account_id: RelationshipStatus} from the delegated admin's GD org."""
    gd = _admin_client("guardduty", admin_account, role_name, region)
    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return {}
    members: dict[str, str] = {}
    kwargs: dict = {"DetectorId": detectors[0], "OnlyAssociated": "false", "MaxResults": 50}
    while True:
        resp = gd.list_members(**kwargs)
        for m in resp.get("Members", []):
            members[m["AccountId"]] = m.get("RelationshipStatus", "Unknown")
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return members


def _members_security_hub(admin_account: str, role_name: str, region: str) -> dict[str, str]:
    """Return {account_id: MemberStatus} from the delegated admin's SH org."""
    sh = _admin_client("securityhub", admin_account, role_name, region)
    members: dict[str, str] = {}
    kwargs: dict = {"OnlyAssociated": False}
    while True:
        resp = sh.list_members(**kwargs)
        for m in resp.get("Members", []):
            members[m["AccountId"]] = m.get("MemberStatus", "Unknown")
        token = resp.get("NextToken")
        if not token:
            break
        kwargs["NextToken"] = token
    return members


def _members_macie(admin_account: str, role_name: str, region: str) -> dict[str, str]:
    """Return {account_id: relationshipStatus} from the delegated admin's Macie org."""
    mc = _admin_client("macie2", admin_account, role_name, region)
    members: dict[str, str] = {}
    kwargs: dict = {"onlyAssociated": "false", "maxResults": 25}
    while True:
        resp = mc.list_members(**kwargs)
        for m in resp.get("members", []):
            members[m["accountId"]] = m.get("relationshipStatus", "Unknown")
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    return members


def _members_inspector(admin_account: str, role_name: str, region: str) -> dict[str, str]:
    """Return {account_id: relationshipStatus} from the delegated admin's Inspector org."""
    ins = _admin_client("inspector2", admin_account, role_name, region)
    members: dict[str, str] = {}
    kwargs: dict = {}
    while True:
        resp = ins.list_members(**kwargs)
        for m in resp.get("members", []):
            members[m["accountId"]] = m.get("relationshipStatus", "Unknown")
        token = resp.get("nextToken")
        if not token:
            break
        kwargs["nextToken"] = token
    return members


_MEMBER_FETCHERS = {
    "guardduty":    _members_guardduty,
    "security_hub": _members_security_hub,
    "macie":        _members_macie,
    "inspector":    _members_inspector,
}

# These statuses mean the account is actively sending findings to the admin.
_ENABLED_STATUSES = {"enabled", "active", "member"}


def assess_member_accounts(
    config: "SecurityServicesConfig",
    role_name: str,
    region: str,
) -> list[AccountAssessment]:
    """
    For every active org account report whether each security service is
    enabled and routing findings to the delegated administrator.

    Access Analyzer is org-wide (no per-account membership concept) so it is
    reported as covered for all non-admin accounts when it is enabled.
    """
    from standstill.aws.organizations import all_accounts, build_ou_tree

    tree = build_ou_tree()
    accounts = all_accounts(tree)

    admin = config.delegated_admin_account
    svc_cfg = config.services

    # Identify the management account so we can label it appropriately.
    org_client = _state.state.get_client("organizations")
    mgmt_id: str = org_client.describe_organization()["Organization"]["MasterAccountId"]

    # Concurrently fetch member lists for every enabled service.
    enabled_fetchers: dict[str, tuple] = {
        svc: (fn, admin, role_name, region)
        for svc, fn in _MEMBER_FETCHERS.items()
        if getattr(svc_cfg, svc).enabled
    }

    raw_members: dict[str, dict[str, str]] = {}
    service_errors: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(fn, *args): svc
            for svc, (fn, *args) in enabled_fetchers.items()
        }
        for future in as_completed(futures):
            svc = futures[future]
            try:
                raw_members[svc] = future.result()
            except Exception as exc:
                service_errors[svc] = str(exc)
                raw_members[svc] = {}

    results: list[AccountAssessment] = []

    for acct in sorted(accounts, key=lambda a: (a.ou_name, a.name)):
        assessment = AccountAssessment(
            account_id=acct.id,
            account_name=acct.name,
            ou_name=acct.ou_name,
        )

        # Management account and delegated admin cannot be members of their own org.
        if acct.id == admin:
            for svc in enabled_fetchers:
                assessment.services[svc] = MemberServiceStatus(
                    enabled=True, member_status="delegated_admin"
                )
            if svc_cfg.access_analyzer.enabled:
                assessment.services["access_analyzer"] = MemberServiceStatus(
                    enabled=True, member_status="delegated_admin"
                )
            results.append(assessment)
            continue

        if acct.id == mgmt_id:
            for svc in enabled_fetchers:
                assessment.services[svc] = MemberServiceStatus(
                    enabled=True, member_status="management_account"
                )
            if svc_cfg.access_analyzer.enabled:
                assessment.services["access_analyzer"] = MemberServiceStatus(
                    enabled=True, member_status="management_account"
                )
            results.append(assessment)
            continue

        # Regular member accounts.
        for svc in enabled_fetchers:
            if svc in service_errors:
                assessment.services[svc] = MemberServiceStatus(
                    enabled=False, member_status="error", error=service_errors[svc]
                )
            else:
                raw = raw_members.get(svc, {}).get(acct.id)
                if raw is None:
                    assessment.services[svc] = MemberServiceStatus(
                        enabled=False, member_status="not_member"
                    )
                else:
                    is_enabled = raw.lower() in _ENABLED_STATUSES
                    assessment.services[svc] = MemberServiceStatus(
                        enabled=is_enabled, member_status=raw
                    )

        # Access Analyzer: org-wide analyzer covers all accounts automatically.
        if svc_cfg.access_analyzer.enabled:
            assessment.services["access_analyzer"] = MemberServiceStatus(
                enabled=True, member_status="org_wide"
            )

        results.append(assessment)

    return results
