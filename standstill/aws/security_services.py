from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Callable

import boto3
from botocore.exceptions import ClientError

from standstill import state as _state

if TYPE_CHECKING:
    from standstill.models.security_config import SecurityServicesConfig

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

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
# Service registry
# ---------------------------------------------------------------------------

@dataclass
class SecurityService:
    """
    Descriptor for a security service managed by standstill.

    Adding a new service means adding one entry to ``SERVICES`` below plus
    the four implementation functions (delegate, configure, fill_status,
    read_config).  No other code needs to change.

    ``fetch_members_fn`` is None for org-wide services (Access Analyzer,
    Security Lake) that cover all accounts automatically without a
    per-account membership concept.
    """
    key: str
    principal: str
    delegate_fn: Callable[[str, str], None]
    configure_fn: Callable[..., ServiceApplyResult]
    fill_status_fn: Callable[[ServiceStatus, str, str, str], None]
    read_config_fn: Callable[[str, str, str], dict]
    fetch_members_fn: Callable[[str, str, str], dict[str, str]] | None = None


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
# Delegation helpers — one per service
# ---------------------------------------------------------------------------

def _delegate_guardduty(target_account: str, region: str) -> None:
    gd = _state.state.get_client("guardduty", region_name=region)
    gd.enable_organization_admin_account(AdminAccountId=target_account)


def _delegate_security_hub(target_account: str, region: str) -> None:
    sh = _state.state.get_client("securityhub", region_name=region)
    sh.enable_organization_admin_account(AdminAccountId=target_account)


def _delegate_macie(target_account: str, region: str) -> None:
    mc = _state.state.get_client("macie2", region_name=region)
    mc.enable_organization_admin_account(AdminAccountId=target_account)


def _delegate_inspector(target_account: str, region: str) -> None:
    ins = _state.state.get_client("inspector2", region_name=region)
    ins.enable_delegated_admin_account(DelegatedAdminAccountId=target_account)


def _delegate_access_analyzer(target_account: str, region: str) -> None:
    org = _state.state.get_client("organizations", region_name=region)
    org.register_delegated_administrator(
        AccountId=target_account,
        ServicePrincipal="access-analyzer.amazonaws.com",
    )


def _delegate_security_lake(target_account: str, region: str) -> None:
    sl = _state.state.get_client("securitylake", region_name=region)
    sl.register_data_lake_delegated_administrator(accountId=target_account)


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


def configure_security_lake(
    cfg,  # SecurityLakeConfig
    admin_account: str,
    role_name: str,
    region: str,
) -> ServiceApplyResult:
    result = ServiceApplyResult(service="security_lake", phase="configuration", success=False, message="")
    try:
        sl = _admin_client("securitylake", admin_account, role_name, region)

        meta_role = cfg.meta_store_manager_role_arn or (
            f"arn:aws:iam::{admin_account}:role/AmazonSecurityLakeMetaStoreManagerV2"
        )

        # Determine which regions already have a data lake
        existing_regions: set[str] = set()
        try:
            existing = sl.list_data_lakes(regions=cfg.regions).get("dataLakes", [])
            existing_regions = {dl["region"] for dl in existing}
        except ClientError:
            pass

        # Build per-region lifecycle configuration
        lc: dict = {}
        if cfg.lifecycle.expiration_days > 0:
            lc["expiration"] = {"days": cfg.lifecycle.expiration_days}
        if cfg.lifecycle.transition_days > 0:
            lc["transitions"] = [{
                "days": cfg.lifecycle.transition_days,
                "storageClass": cfg.lifecycle.transition_storage_class,
            }]

        def _make_conf(r: str) -> dict:
            conf: dict = {"region": r}
            if lc:
                conf["lifecycleConfiguration"] = lc
            return conf

        to_create = [_make_conf(r) for r in cfg.regions if r not in existing_regions]
        to_update = [_make_conf(r) for r in cfg.regions if r in existing_regions]

        if to_create:
            sl.create_data_lake(configurations=to_create, metaStoreManagerRoleArn=meta_role)
            result.details.append(f"Created in: {', '.join(c['region'] for c in to_create)}")
        if to_update:
            try:
                sl.update_data_lake(configurations=to_update, metaStoreManagerRoleArn=meta_role)
                result.details.append(f"Updated in: {', '.join(c['region'] for c in to_update)}")
            except ClientError as exc:
                result.details.append(f"Update skipped: {exc.response['Error']['Message']}")

        # Configure org auto-enable for new accounts
        if cfg.organization.auto_enable_new_accounts and cfg.sources:
            auto_enable_conf = [
                {
                    "region": r,
                    "sources": [{"sourceName": s} for s in cfg.sources],
                }
                for r in cfg.regions
            ]
            try:
                sl.create_data_lake_organization_configuration(
                    autoEnableNewAccount=auto_enable_conf
                )
                result.details.append("Org auto-enable configured.")
            except ClientError as exc:
                result.details.append(
                    f"Org config: {exc.response['Error']['Message']}"
                )

        result.success = True
        result.message = (
            f"regions=[{', '.join(cfg.regions)}], "
            f"auto-enable={cfg.organization.auto_enable_new_accounts}, "
            f"sources=[{', '.join(cfg.sources) or 'none'}]"
        )
    except (ClientError, RuntimeError) as exc:
        result.message = str(exc)
    return result


# ---------------------------------------------------------------------------
# Status helpers — one per service
# ---------------------------------------------------------------------------

def _fill_guardduty_status(
    status: ServiceStatus, admin_account: str, role_name: str, region: str
) -> None:
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


def _fill_security_hub_status(
    status: ServiceStatus, admin_account: str, role_name: str, region: str
) -> None:
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


def _fill_macie_status(
    status: ServiceStatus, admin_account: str, role_name: str, region: str
) -> None:
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


def _fill_inspector_status(
    status: ServiceStatus, admin_account: str, role_name: str, region: str
) -> None:
    ins = _admin_client("inspector2", admin_account, role_name, region)
    try:
        org_cfg = ins.describe_organization_configuration()
        auto = org_cfg.get("autoEnable", {})
        status.enabled = True
        status.auto_enable = "ON" if any(auto.values()) else "OFF"
        status.details = {k: str(v) for k, v in auto.items()}
    except ClientError:
        pass


def _fill_access_analyzer_status(
    status: ServiceStatus, admin_account: str, role_name: str, region: str
) -> None:
    aa = _admin_client("accessanalyzer", admin_account, role_name, region)
    try:
        analyzers = aa.list_analyzers().get("analyzers", [])
        org_analyzers = [a for a in analyzers if "ORGANIZATION" in a.get("type", "")]
        status.enabled = bool(org_analyzers)
        status.auto_enable = "N/A"
        status.details["analyzers"] = ", ".join(a["name"] for a in org_analyzers) or "none"
    except ClientError:
        pass


def _fill_security_lake_status(
    status: ServiceStatus, admin_account: str, role_name: str, region: str
) -> None:
    sl = _admin_client("securitylake", admin_account, role_name, region)
    try:
        lakes = sl.list_data_lakes(regions=[region]).get("dataLakes", [])
        status.enabled = bool(lakes)
        status.auto_enable = "N/A"
        if lakes:
            status.details["regions"] = ", ".join(dl["region"] for dl in lakes)
            try:
                org_cfg = sl.get_data_lake_organization_configuration()
                auto = org_cfg.get("autoEnableNewAccount", [])
                status.auto_enable = "ON" if auto else "OFF"
            except ClientError:
                pass
    except ClientError:
        pass


# ---------------------------------------------------------------------------
# Config readers — one per service
# ---------------------------------------------------------------------------

def _read_guardduty_config(admin_account: str, role_name: str, region: str) -> dict:
    gd = _admin_client("guardduty", admin_account, role_name, region)
    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return {"enabled": False}
    det = gd.get_detector(DetectorId=detectors[0])
    enabled = det.get("Status") == "ENABLED"
    freq = det.get("FindingPublishingFrequency", "SIX_HOURS")
    auto_enable = "ALL"
    raw_features: dict[str, str] = {}
    try:
        org_cfg = gd.describe_organization_configuration(DetectorId=detectors[0])
        auto_enable = org_cfg.get("AutoEnableOrganizationMembers") or (
            "ALL" if org_cfg.get("AutoEnable") else "NONE"
        )
        raw_features = {
            f["Name"]: f.get("AutoEnable", "NONE")
            for f in org_cfg.get("Features", [])
        }
    except ClientError:
        pass
    protection_plans = {
        cfg_key: raw_features.get(api_name, "NONE") != "NONE"
        for cfg_key, api_name in GUARDDUTY_FEATURE_MAP.items()
    }
    return {
        "enabled": enabled,
        "detector": {"finding_publishing_frequency": freq},
        "organization": {"auto_enable": auto_enable},
        "protection_plans": protection_plans,
    }


def _read_security_hub_config(admin_account: str, role_name: str, region: str) -> dict:
    sh = _admin_client("securityhub", admin_account, role_name, region)
    sh_enabled = False
    try:
        sh.describe_hub()
        sh_enabled = True
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("InvalidAccessException", "ResourceNotFoundException"):
            raise
    if not sh_enabled:
        return {"enabled": False}
    org_cfg = sh.describe_organization_configuration()
    auto_enable = "ALL" if org_cfg.get("AutoEnable") else "NONE"
    subs = sh.get_enabled_standards().get("StandardsSubscriptions", [])
    enabled_arns = {s["StandardsArn"] for s in subs}
    standards = {
        key: arn_tmpl.replace("{r}", region) in enabled_arns
        for key, arn_tmpl in SECURITY_HUB_STANDARD_ARNS.items()
    }
    aggs = sh.list_finding_aggregators().get("FindingAggregators", [])
    return {
        "enabled": True,
        "organization": {"auto_enable": auto_enable},
        "standards": standards,
        "cross_region_aggregation": bool(aggs),
    }


def _read_macie_config(admin_account: str, role_name: str, region: str) -> dict:
    mc = _admin_client("macie2", admin_account, role_name, region)
    mc_enabled = False
    freq = "SIX_HOURS"
    try:
        session = mc.get_macie_session()
        mc_enabled = session.get("status") == "ENABLED"
        freq = session.get("findingPublishingFrequency", "SIX_HOURS")
    except ClientError:
        pass
    if not mc_enabled:
        return {"enabled": False}
    auto_enable = True
    try:
        org_cfg = mc.describe_organization_configuration()
        auto_enable = bool(org_cfg.get("autoEnable", True))
    except ClientError:
        pass
    discovery_enabled = False
    try:
        disc = mc.get_automated_discovery_configuration()
        discovery_enabled = disc.get("status") == "ENABLED"
    except ClientError:
        pass
    return {
        "enabled": True,
        "organization": {"auto_enable": auto_enable},
        "session": {"finding_publishing_frequency": freq},
        "automated_discovery": {
            "enabled": discovery_enabled,
            "sampling_depth": 100,
            "managed_identifiers": "RECOMMENDED",
        },
    }


def _read_inspector_config(admin_account: str, role_name: str, region: str) -> dict:
    ins = _admin_client("inspector2", admin_account, role_name, region)
    ins_enabled = False
    scan_types = {"ec2": False, "ecr": False, "lambda": False, "lambda_code": False}
    try:
        batch = ins.batch_get_account_status(accountIds=[admin_account])
        resource_state = batch.get("accounts", [{}])[0].get("resourceState", {})
        scan_types = {
            "ec2":         resource_state.get("ec2",         {}).get("status") == "ENABLED",
            "ecr":         resource_state.get("ecr",         {}).get("status") == "ENABLED",
            "lambda":      resource_state.get("lambda",      {}).get("status") == "ENABLED",
            "lambda_code": resource_state.get("lambdaCode",  {}).get("status") == "ENABLED",
        }
        ins_enabled = any(scan_types.values())
    except ClientError:
        pass
    return {
        "enabled": ins_enabled,
        "organization": {"auto_enable": True},
        "scan_types": scan_types,
    }


def _read_access_analyzer_config(admin_account: str, role_name: str, region: str) -> dict:
    aa = _admin_client("accessanalyzer", admin_account, role_name, region)
    analyzers = aa.list_analyzers().get("analyzers", [])
    org_analyzers = [a for a in analyzers if "ORGANIZATION" in a.get("type", "")]
    if not org_analyzers:
        return {"enabled": False}
    return {
        "enabled": True,
        "analyzers": [{"name": a["name"], "type": a["type"]} for a in org_analyzers],
    }


def _read_security_lake_config(admin_account: str, role_name: str, region: str) -> dict:
    sl = _admin_client("securitylake", admin_account, role_name, region)
    lakes = sl.list_data_lakes(regions=[region]).get("dataLakes", [])
    if not lakes:
        return {"enabled": False}
    lake_regions = [dl["region"] for dl in lakes]
    auto_enable = False
    sources: list[str] = []
    try:
        org_cfg = sl.get_data_lake_organization_configuration()
        auto_configs = org_cfg.get("autoEnableNewAccount", [])
        auto_enable = bool(auto_configs)
        if auto_configs:
            sources = [s["sourceName"] for s in auto_configs[0].get("sources", [])]
    except ClientError:
        pass
    return {
        "enabled": True,
        "regions": lake_regions,
        "organization": {"auto_enable_new_accounts": auto_enable},
        "sources": sources,
    }


# ---------------------------------------------------------------------------
# Member fetchers — services with per-account membership
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


# ---------------------------------------------------------------------------
# Registry — the single source of truth for all managed security services
# ---------------------------------------------------------------------------

SERVICES: list[SecurityService] = [
    SecurityService(
        key="guardduty",
        principal="guardduty.amazonaws.com",
        delegate_fn=_delegate_guardduty,
        configure_fn=configure_guardduty,
        fill_status_fn=_fill_guardduty_status,
        read_config_fn=_read_guardduty_config,
        fetch_members_fn=_members_guardduty,
    ),
    SecurityService(
        key="security_hub",
        principal="securityhub.amazonaws.com",
        delegate_fn=_delegate_security_hub,
        configure_fn=configure_security_hub,
        fill_status_fn=_fill_security_hub_status,
        read_config_fn=_read_security_hub_config,
        fetch_members_fn=_members_security_hub,
    ),
    SecurityService(
        key="macie",
        principal="macie.amazonaws.com",
        delegate_fn=_delegate_macie,
        configure_fn=configure_macie,
        fill_status_fn=_fill_macie_status,
        read_config_fn=_read_macie_config,
        fetch_members_fn=_members_macie,
    ),
    SecurityService(
        key="inspector",
        principal="inspector2.amazonaws.com",
        delegate_fn=_delegate_inspector,
        configure_fn=configure_inspector,
        fill_status_fn=_fill_inspector_status,
        read_config_fn=_read_inspector_config,
        fetch_members_fn=_members_inspector,
    ),
    SecurityService(
        key="access_analyzer",
        principal="access-analyzer.amazonaws.com",
        delegate_fn=_delegate_access_analyzer,
        configure_fn=configure_access_analyzer,
        fill_status_fn=_fill_access_analyzer_status,
        read_config_fn=_read_access_analyzer_config,
        fetch_members_fn=None,  # org-wide: no per-account membership
    ),
    SecurityService(
        key="security_lake",
        principal="securitylake.amazonaws.com",
        delegate_fn=_delegate_security_lake,
        configure_fn=configure_security_lake,
        fill_status_fn=_fill_security_lake_status,
        read_config_fn=_read_security_lake_config,
        fetch_members_fn=None,  # org-wide: no per-account membership
    ),
]

SERVICE_MAP: dict[str, SecurityService] = {s.key: s for s in SERVICES}
SERVICE_PRINCIPALS: dict[str, str] = {s.key: s.principal for s in SERVICES}

# These statuses mean the account is actively sending findings to the admin.
_ENABLED_STATUSES = {"enabled", "active", "member"}


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

    for svc in SERVICES:
        try:
            resp = org.list_delegated_administrators(ServicePrincipal=svc.principal)
            admins = resp.get("DelegatedAdministrators", [])
            current = admins[0]["Id"] if admins else None
        except ClientError as exc:
            statuses.append(DelegationStatus(
                service=svc.key, principal=svc.principal,
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
            service=svc.key, principal=svc.principal,
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
        SERVICE_MAP[service].delegate_fn(target_account, region)
        return ServiceApplyResult(
            service=service, phase="delegation", success=True,
            message=f"Delegated admin registered: {target_account}",
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        # Already registered by another path
        if code in ("AccountAlreadyRegisteredException", "AlreadyExistsException", "ConflictException"):
            return ServiceApplyResult(
                service=service, phase="delegation", success=True,
                message="Already registered (skipped).",
            )
        return ServiceApplyResult(
            service=service, phase="delegation", success=False,
            message=exc.response["Error"]["Message"],
        )


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

    for svc in SERVICES:
        d = delegation.get(svc.key)
        current_admin = d.current_admin if d else None
        base = ServiceStatus(
            service=svc.key,
            delegated_admin=current_admin,
            enabled=False,
            auto_enable="—",
            details={},
        )

        if current_admin != target_account:
            base.error = (
                "Delegated admin not registered" if not current_admin
                else f"Different admin: {current_admin}"
            )
            statuses.append(base)
            continue

        try:
            svc.fill_status_fn(base, target_account, role_name, region)
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
    SERVICE_MAP[service].fill_status_fn(status, admin_account, role_name, region)


# ---------------------------------------------------------------------------
# Import — read live configuration from delegated admin account
# ---------------------------------------------------------------------------

def read_service_configs(
    admin_account: str,
    role_name: str,
    region: str,
) -> tuple[dict, dict[str, str]]:
    """
    Read live service configurations from the delegated admin account.

    Returns (config_dict, errors) where config_dict matches the YAML schema
    and errors maps service names to error messages for any that failed.
    """
    errors: dict[str, str] = {}
    services: dict = {}

    for svc in SERVICES:
        try:
            services[svc.key] = svc.read_config_fn(admin_account, role_name, region)
        except (ClientError, RuntimeError) as exc:
            errors[svc.key] = str(exc)
            services[svc.key] = {"enabled": False}

    config_dict = {
        "version": "1",
        "delegated_admin_account": admin_account,
        "services": services,
    }
    return config_dict, errors


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

def apply_services(
    config: "SecurityServicesConfig",
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
        svc.key: (getattr(svc_cfg, svc.key).enabled, getattr(svc_cfg, svc.key))
        for svc in SERVICES
    }

    # Phase 1 — delegation
    phase1: list[ServiceApplyResult] = []
    delegation_check = {d.service: d for d in check_delegated_admins(admin, region)}

    for svc_key, (enabled, _cfg) in enabled_map.items():
        if not enabled:
            continue
        d = delegation_check.get(svc_key)
        if d and d.action == "skip":
            phase1.append(ServiceApplyResult(
                service=svc_key, phase="delegation",
                success=True, message="Already registered (skipped).",
            ))
        elif d and d.action == "conflict":
            phase1.append(ServiceApplyResult(
                service=svc_key, phase="delegation",
                success=False,
                message=f"Another account ({d.current_admin}) is already delegated admin.",
            ))
        else:
            phase1.append(register_delegated_admin(svc_key, admin, region))

    # Abort Phase 2 for services that failed delegation
    failed_svcs = {r.service for r in phase1 if not r.success}

    # Phase 2 — configuration
    # Resolve configure functions via module globals at call time so that
    # test patches (patch.object on the module attribute) take effect.
    _module_globals = globals()
    phase2: list[ServiceApplyResult] = []
    for svc_key, (enabled, svc_config) in enabled_map.items():
        if not enabled or svc_key in failed_svcs:
            continue
        configure_fn = _module_globals.get(
            f"configure_{svc_key}",
            SERVICE_MAP[svc_key].configure_fn,
        )
        phase2.append(configure_fn(svc_config, admin, role_name, region))

    return phase1, phase2


# ---------------------------------------------------------------------------
# Assessment — per-account member coverage
# ---------------------------------------------------------------------------

def assess_member_accounts(
    config: "SecurityServicesConfig",
    role_name: str,
    region: str,
) -> list[AccountAssessment]:
    """
    For every active org account report whether each security service is
    enabled and routing findings to the delegated administrator.

    Services with ``fetch_members_fn=None`` are org-wide and reported as
    covered for all accounts when enabled (no per-account membership concept).
    """
    from standstill.aws.organizations import all_accounts, build_ou_tree

    tree = build_ou_tree()
    accounts = all_accounts(tree)

    admin = config.delegated_admin_account
    svc_cfg = config.services

    # Identify the management account so we can label it appropriately.
    org_client = _state.state.get_client("organizations")
    mgmt_id: str = org_client.describe_organization()["Organization"]["MasterAccountId"]

    # Partition into per-account membership services vs org-wide services
    member_svcs = [
        svc for svc in SERVICES
        if svc.fetch_members_fn is not None and getattr(svc_cfg, svc.key).enabled
    ]
    org_wide_svcs = [
        svc for svc in SERVICES
        if svc.fetch_members_fn is None and getattr(svc_cfg, svc.key).enabled
    ]

    # Concurrently fetch member lists for every enabled membership service
    raw_members: dict[str, dict[str, str]] = {}
    service_errors: dict[str, str] = {}

    with ThreadPoolExecutor(max_workers=5) as pool:
        futures = {
            pool.submit(svc.fetch_members_fn, admin, role_name, region): svc.key
            for svc in member_svcs
        }
        for future in as_completed(futures):
            svc_key = futures[future]
            try:
                raw_members[svc_key] = future.result()
            except Exception as exc:
                service_errors[svc_key] = str(exc)
                raw_members[svc_key] = {}

    results: list[AccountAssessment] = []

    for acct in sorted(accounts, key=lambda a: (a.ou_name, a.name)):
        assessment = AccountAssessment(
            account_id=acct.id,
            account_name=acct.name,
            ou_name=acct.ou_name,
        )

        # Management account and delegated admin cannot be members of their own org.
        if acct.id in (admin, mgmt_id):
            sentinel = "delegated_admin" if acct.id == admin else "management_account"
            for svc in member_svcs:
                assessment.services[svc.key] = MemberServiceStatus(
                    enabled=True, member_status=sentinel
                )
            for svc in org_wide_svcs:
                assessment.services[svc.key] = MemberServiceStatus(
                    enabled=True, member_status=sentinel
                )
            results.append(assessment)
            continue

        # Regular member accounts — per-service membership
        for svc in member_svcs:
            if svc.key in service_errors:
                assessment.services[svc.key] = MemberServiceStatus(
                    enabled=False, member_status="error", error=service_errors[svc.key]
                )
            else:
                raw = raw_members.get(svc.key, {}).get(acct.id)
                if raw is None:
                    assessment.services[svc.key] = MemberServiceStatus(
                        enabled=False, member_status="not_member"
                    )
                else:
                    is_enabled = raw.lower() in _ENABLED_STATUSES
                    assessment.services[svc.key] = MemberServiceStatus(
                        enabled=is_enabled, member_status=raw
                    )

        # Org-wide services cover all accounts automatically
        for svc in org_wide_svcs:
            assessment.services[svc.key] = MemberServiceStatus(
                enabled=True, member_status="org_wide"
            )

        results.append(assessment)

    return results
