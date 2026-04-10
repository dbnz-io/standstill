from __future__ import annotations

import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

_ACCT_RE = re.compile(r"^\d{12}$")
_VALID_FREQ = {"FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"}
_VALID_AUTO_ENABLE_ORG = {"ALL", "NEW", "NONE"}
_VALID_MANAGED_IDENTIFIERS = {"RECOMMENDED", "ALL", "NONE", "EXCLUDE", "INCLUDE"}
_VALID_ANALYZER_TYPES = {"ORGANIZATION", "ORGANIZATION_UNUSED_ACCESS"}


# ---------------------------------------------------------------------------
# GuardDuty
# ---------------------------------------------------------------------------

class GuardDutyDetector(BaseModel):
    finding_publishing_frequency: str = "SIX_HOURS"

    @field_validator("finding_publishing_frequency")
    @classmethod
    def _freq(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_FREQ:
            raise ValueError(f"Must be one of: {', '.join(sorted(_VALID_FREQ))}")
        return u


class GuardDutyOrg(BaseModel):
    auto_enable: str = "ALL"

    @field_validator("auto_enable")
    @classmethod
    def _auto(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_AUTO_ENABLE_ORG:
            raise ValueError(f"Must be one of: {', '.join(sorted(_VALID_AUTO_ENABLE_ORG))}")
        return u


class GuardDutyProtectionPlans(BaseModel):
    s3_logs: bool = True
    rds_login_events: bool = True
    eks_audit_logs: bool = False
    eks_runtime: bool = False
    ecs_runtime: bool = False
    ec2_malware_scan: bool = False
    lambda_network_logs: bool = False


class GuardDutyConfig(BaseModel):
    enabled: bool = True
    detector: GuardDutyDetector = Field(default_factory=GuardDutyDetector)
    organization: GuardDutyOrg = Field(default_factory=GuardDutyOrg)
    protection_plans: GuardDutyProtectionPlans = Field(default_factory=GuardDutyProtectionPlans)


# ---------------------------------------------------------------------------
# Security Hub
# ---------------------------------------------------------------------------

class SecurityHubOrg(BaseModel):
    auto_enable: str = "ALL"

    @field_validator("auto_enable")
    @classmethod
    def _auto(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_AUTO_ENABLE_ORG:
            raise ValueError(f"Must be one of: {', '.join(sorted(_VALID_AUTO_ENABLE_ORG))}")
        return u


class SecurityHubStandards(BaseModel):
    fsbp: bool = True
    cis_1_4: bool = False
    cis_3_0: bool = False
    pci_dss: bool = False
    nist: bool = False


class SecurityHubConfig(BaseModel):
    enabled: bool = True
    organization: SecurityHubOrg = Field(default_factory=SecurityHubOrg)
    standards: SecurityHubStandards = Field(default_factory=SecurityHubStandards)
    cross_region_aggregation: bool = False
    aggregation_region: str | None = None


# ---------------------------------------------------------------------------
# Macie
# ---------------------------------------------------------------------------

class MacieOrg(BaseModel):
    auto_enable: bool = True


class MacieSession(BaseModel):
    finding_publishing_frequency: str = "SIX_HOURS"

    @field_validator("finding_publishing_frequency")
    @classmethod
    def _freq(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_FREQ:
            raise ValueError(f"Must be one of: {', '.join(sorted(_VALID_FREQ))}")
        return u


class MacieAutomatedDiscovery(BaseModel):
    enabled: bool = False
    sampling_depth: int = 100
    managed_identifiers: str = "RECOMMENDED"

    @field_validator("sampling_depth")
    @classmethod
    def _depth(cls, v: int) -> int:
        if not 1 <= v <= 100:
            raise ValueError("sampling_depth must be between 1 and 100.")
        return v

    @field_validator("managed_identifiers")
    @classmethod
    def _mi(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_MANAGED_IDENTIFIERS:
            raise ValueError(f"Must be one of: {', '.join(sorted(_VALID_MANAGED_IDENTIFIERS))}")
        return u


class MacieConfig(BaseModel):
    enabled: bool = True
    organization: MacieOrg = Field(default_factory=MacieOrg)
    session: MacieSession = Field(default_factory=MacieSession)
    automated_discovery: MacieAutomatedDiscovery = Field(default_factory=MacieAutomatedDiscovery)
    custom_data_identifiers: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Inspector
# ---------------------------------------------------------------------------

class InspectorOrg(BaseModel):
    auto_enable: bool = True


class InspectorScanTypes(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    ec2: bool = True
    ecr: bool = True
    lambda_functions: bool = Field(False, alias="lambda")
    lambda_code: bool = False


class InspectorConfig(BaseModel):
    enabled: bool = True
    organization: InspectorOrg = Field(default_factory=InspectorOrg)
    scan_types: InspectorScanTypes = Field(default_factory=InspectorScanTypes)


# ---------------------------------------------------------------------------
# Access Analyzer
# ---------------------------------------------------------------------------

class AnalyzerEntry(BaseModel):
    name: str
    type: str = "ORGANIZATION"

    @field_validator("type")
    @classmethod
    def _type(cls, v: str) -> str:
        u = v.upper()
        if u not in _VALID_ANALYZER_TYPES:
            raise ValueError(
                f"Analyzer type must be one of: {', '.join(sorted(_VALID_ANALYZER_TYPES))}"
            )
        return u


class AccessAnalyzerConfig(BaseModel):
    enabled: bool = True
    analyzers: list[AnalyzerEntry] = Field(
        default_factory=lambda: [AnalyzerEntry(name="standstill-org-analyzer", type="ORGANIZATION")]
    )


# ---------------------------------------------------------------------------
# Top-level
# ---------------------------------------------------------------------------

class ServicesConfig(BaseModel):
    guardduty: GuardDutyConfig = Field(default_factory=GuardDutyConfig)
    security_hub: SecurityHubConfig = Field(default_factory=SecurityHubConfig)
    macie: MacieConfig = Field(default_factory=MacieConfig)
    inspector: InspectorConfig = Field(default_factory=InspectorConfig)
    access_analyzer: AccessAnalyzerConfig = Field(default_factory=AccessAnalyzerConfig)


class SecurityServicesConfig(BaseModel):
    version: str = "1"
    delegated_admin_account: str
    services: ServicesConfig = Field(default_factory=ServicesConfig)

    @field_validator("delegated_admin_account", mode="before")
    @classmethod
    def _account(cls, v) -> str:
        s = str(v)
        if not _ACCT_RE.match(s):
            raise ValueError(
                f"Invalid account ID '{v}'. Expected 12 digits (e.g. 123456789012)."
            )
        return s


def load_config(path: Path) -> SecurityServicesConfig:
    """Load and validate a security services YAML file."""
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")
    raw = yaml.safe_load(path.read_text())
    if not raw:
        raise ValueError("Config file is empty.")
    try:
        return SecurityServicesConfig.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"Config validation failed:\n{exc}") from exc
