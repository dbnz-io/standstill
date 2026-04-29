"""Tests for standstill/models/security_config.py"""
from __future__ import annotations

import textwrap

import pytest
from pydantic import ValidationError

from standstill.models.security_config import (
    AccessAnalyzerConfig,
    AnalyzerEntry,
    GuardDutyConfig,
    GuardDutyDetector,
    GuardDutyOrg,
    GuardDutyProtectionPlans,
    InspectorConfig,
    InspectorScanTypes,
    MacieAutomatedDiscovery,
    MacieConfig,
    MacieSession,
    SecurityHubConfig,
    SecurityHubStandards,
    SecurityLakeConfig,
    SecurityLakeLifecycle,
    SecurityLakeOrg,
    SecurityServicesConfig,
    ServicesConfig,
    load_config,
)

# ---------------------------------------------------------------------------
# GuardDuty models
# ---------------------------------------------------------------------------

class TestGuardDutyDetector:
    def test_default(self):
        d = GuardDutyDetector()
        assert d.finding_publishing_frequency == "SIX_HOURS"

    def test_valid_frequencies(self):
        for freq in ("FIFTEEN_MINUTES", "ONE_HOUR", "SIX_HOURS"):
            d = GuardDutyDetector(finding_publishing_frequency=freq)
            assert d.finding_publishing_frequency == freq

    def test_case_insensitive(self):
        d = GuardDutyDetector(finding_publishing_frequency="six_hours")
        assert d.finding_publishing_frequency == "SIX_HOURS"

    def test_invalid_frequency(self):
        with pytest.raises(ValidationError):
            GuardDutyDetector(finding_publishing_frequency="TWELVE_HOURS")


class TestGuardDutyOrg:
    def test_default(self):
        assert GuardDutyOrg().auto_enable == "ALL"

    def test_valid_values(self):
        for v in ("ALL", "NEW", "NONE"):
            assert GuardDutyOrg(auto_enable=v).auto_enable == v

    def test_case_insensitive(self):
        assert GuardDutyOrg(auto_enable="new").auto_enable == "NEW"

    def test_invalid(self):
        with pytest.raises(ValidationError):
            GuardDutyOrg(auto_enable="SOME")


class TestGuardDutyProtectionPlans:
    def test_defaults(self):
        p = GuardDutyProtectionPlans()
        assert p.s3_logs is True
        assert p.rds_login_events is True
        assert p.eks_audit_logs is False
        assert p.ec2_malware_scan is False
        assert p.lambda_network_logs is False


class TestGuardDutyConfig:
    def test_defaults(self):
        c = GuardDutyConfig()
        assert c.enabled is True
        assert isinstance(c.detector, GuardDutyDetector)
        assert isinstance(c.organization, GuardDutyOrg)
        assert isinstance(c.protection_plans, GuardDutyProtectionPlans)

    def test_disabled(self):
        c = GuardDutyConfig(enabled=False)
        assert c.enabled is False


# ---------------------------------------------------------------------------
# Security Hub models
# ---------------------------------------------------------------------------

class TestSecurityHubConfig:
    def test_defaults(self):
        c = SecurityHubConfig()
        assert c.enabled is True
        assert c.cross_region_aggregation is False
        assert c.aggregation_region is None

    def test_standards_defaults(self):
        s = SecurityHubStandards()
        assert s.fsbp is True
        assert s.cis_1_4 is False
        assert s.pci_dss is False

    def test_cross_region(self):
        c = SecurityHubConfig(cross_region_aggregation=True, aggregation_region="eu-west-1")
        assert c.cross_region_aggregation is True
        assert c.aggregation_region == "eu-west-1"


# ---------------------------------------------------------------------------
# Macie models
# ---------------------------------------------------------------------------

class TestMacieAutomatedDiscovery:
    def test_defaults(self):
        d = MacieAutomatedDiscovery()
        assert d.enabled is False
        assert d.sampling_depth == 100
        assert d.managed_identifiers == "RECOMMENDED"

    def test_sampling_depth_bounds(self):
        MacieAutomatedDiscovery(sampling_depth=1)
        MacieAutomatedDiscovery(sampling_depth=100)
        with pytest.raises(ValidationError):
            MacieAutomatedDiscovery(sampling_depth=0)
        with pytest.raises(ValidationError):
            MacieAutomatedDiscovery(sampling_depth=101)

    def test_managed_identifiers_valid(self):
        for v in ("RECOMMENDED", "ALL", "NONE", "EXCLUDE", "INCLUDE"):
            d = MacieAutomatedDiscovery(managed_identifiers=v)
            assert d.managed_identifiers == v

    def test_managed_identifiers_case(self):
        d = MacieAutomatedDiscovery(managed_identifiers="all")
        assert d.managed_identifiers == "ALL"

    def test_managed_identifiers_invalid(self):
        with pytest.raises(ValidationError):
            MacieAutomatedDiscovery(managed_identifiers="CUSTOM")


class TestMacieSession:
    def test_default(self):
        assert MacieSession().finding_publishing_frequency == "SIX_HOURS"

    def test_invalid(self):
        with pytest.raises(ValidationError):
            MacieSession(finding_publishing_frequency="DAILY")


class TestMacieConfig:
    def test_defaults(self):
        c = MacieConfig()
        assert c.enabled is True
        assert c.custom_data_identifiers == []


# ---------------------------------------------------------------------------
# Inspector models
# ---------------------------------------------------------------------------

class TestInspectorScanTypes:
    def test_defaults(self):
        s = InspectorScanTypes()
        assert s.ec2 is True
        assert s.ecr is True
        assert s.lambda_functions is False
        assert s.lambda_code is False

    def test_lambda_alias(self):
        # Field uses alias="lambda" for YAML; populate_by_name allows both
        s = InspectorScanTypes(**{"lambda": True})
        assert s.lambda_functions is True

    def test_lambda_by_python_name(self):
        s = InspectorScanTypes(lambda_functions=True)
        assert s.lambda_functions is True


class TestInspectorConfig:
    def test_defaults(self):
        c = InspectorConfig()
        assert c.enabled is True
        assert c.organization.auto_enable is True


# ---------------------------------------------------------------------------
# Access Analyzer models
# ---------------------------------------------------------------------------

class TestAnalyzerEntry:
    def test_defaults(self):
        e = AnalyzerEntry(name="my-analyzer")
        assert e.type == "ORGANIZATION"

    def test_valid_types(self):
        for t in ("ORGANIZATION", "ORGANIZATION_UNUSED_ACCESS"):
            AnalyzerEntry(name="a", type=t)

    def test_case_insensitive_type(self):
        e = AnalyzerEntry(name="a", type="organization")
        assert e.type == "ORGANIZATION"

    def test_invalid_type(self):
        with pytest.raises(ValidationError):
            AnalyzerEntry(name="a", type="ACCOUNT")


class TestAccessAnalyzerConfig:
    def test_defaults(self):
        c = AccessAnalyzerConfig()
        assert c.enabled is True
        assert len(c.analyzers) == 1
        assert c.analyzers[0].name == "standstill-org-analyzer"
        assert c.analyzers[0].type == "ORGANIZATION"

    def test_multiple_analyzers(self):
        c = AccessAnalyzerConfig(analyzers=[
            AnalyzerEntry(name="a1", type="ORGANIZATION"),
            AnalyzerEntry(name="a2", type="ORGANIZATION_UNUSED_ACCESS"),
        ])
        assert len(c.analyzers) == 2


# ---------------------------------------------------------------------------
# SecurityServicesConfig
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Security Lake models
# ---------------------------------------------------------------------------

class TestSecurityLakeOrg:
    def test_default(self):
        o = SecurityLakeOrg()
        assert o.auto_enable_new_accounts is True

    def test_disable(self):
        o = SecurityLakeOrg(auto_enable_new_accounts=False)
        assert o.auto_enable_new_accounts is False


class TestSecurityLakeLifecycle:
    def test_defaults(self):
        lc = SecurityLakeLifecycle()
        assert lc.expiration_days == 365
        assert lc.transition_days == 0
        assert lc.transition_storage_class == "INTELLIGENT_TIERING"

    def test_valid_storage_classes(self):
        for sc in ("STANDARD_IA", "GLACIER_FLEXIBLE_RETRIEVAL", "DEEP_ARCHIVE"):
            lc = SecurityLakeLifecycle(transition_storage_class=sc)
            assert lc.transition_storage_class == sc

    def test_storage_class_case_insensitive(self):
        lc = SecurityLakeLifecycle(transition_storage_class="standard_ia")
        assert lc.transition_storage_class == "STANDARD_IA"

    def test_invalid_storage_class(self):
        with pytest.raises(ValidationError):
            SecurityLakeLifecycle(transition_storage_class="CASSETTE_TAPE")

    def test_negative_days_invalid(self):
        with pytest.raises(ValidationError):
            SecurityLakeLifecycle(expiration_days=-1)
        with pytest.raises(ValidationError):
            SecurityLakeLifecycle(transition_days=-1)

    def test_zero_days_valid(self):
        lc = SecurityLakeLifecycle(expiration_days=0, transition_days=0)
        assert lc.expiration_days == 0
        assert lc.transition_days == 0


class TestSecurityLakeConfig:
    def test_defaults(self):
        c = SecurityLakeConfig()
        assert c.enabled is False
        assert c.regions == ["us-east-1"]
        assert c.meta_store_manager_role_arn == ""
        assert isinstance(c.organization, SecurityLakeOrg)
        assert isinstance(c.lifecycle, SecurityLakeLifecycle)
        assert "CLOUD_TRAIL_MGMT" in c.sources

    def test_enabled(self):
        c = SecurityLakeConfig(enabled=True, regions=["us-east-1", "eu-west-1"])
        assert c.enabled is True
        assert len(c.regions) == 2

    def test_custom_role_arn(self):
        arn = "arn:aws:iam::123456789012:role/MyRole"
        c = SecurityLakeConfig(meta_store_manager_role_arn=arn)
        assert c.meta_store_manager_role_arn == arn

    def test_custom_sources(self):
        c = SecurityLakeConfig(sources=["VPC_FLOW", "WAFV2"])
        assert c.sources == ["VPC_FLOW", "WAFV2"]


class TestServicesConfigIncludesSecurityLake:
    def test_security_lake_field_present(self):
        s = ServicesConfig()
        assert hasattr(s, "security_lake")
        assert isinstance(s.security_lake, SecurityLakeConfig)
        assert s.security_lake.enabled is False


class TestSecurityServicesConfig:
    def test_valid(self):
        cfg = SecurityServicesConfig(delegated_admin_account="123456789012")
        assert cfg.version == "1"
        assert isinstance(cfg.services, ServicesConfig)

    def test_invalid_account_id(self):
        with pytest.raises(ValidationError):
            SecurityServicesConfig(delegated_admin_account="not-an-id")

    def test_account_too_short(self):
        with pytest.raises(ValidationError):
            SecurityServicesConfig(delegated_admin_account="12345")

    def test_account_with_letters(self):
        with pytest.raises(ValidationError):
            SecurityServicesConfig(delegated_admin_account="12345678901a")

    def test_account_coerced_to_string(self, tmp_path):
        # Numeric account IDs in YAML parse as int — validator coerces via str()
        f = tmp_path / "int_acct.yaml"
        f.write_text("version: '1'\ndelegated_admin_account: 123456789012\n")
        cfg = load_config(f)
        assert isinstance(cfg.delegated_admin_account, str)
        assert cfg.delegated_admin_account == "123456789012"


# ---------------------------------------------------------------------------
# load_config
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_file_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "missing.yaml")

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")
        with pytest.raises(ValueError, match="empty"):
            load_config(f)

    def test_valid_minimal(self, tmp_path):
        f = tmp_path / "cfg.yaml"
        f.write_text(textwrap.dedent("""\
            version: "1"
            delegated_admin_account: "123456789012"
            services:
              guardduty:
                enabled: true
        """))
        cfg = load_config(f)
        assert cfg.delegated_admin_account == "123456789012"
        assert cfg.services.guardduty.enabled is True

    def test_security_lake_round_trip(self, tmp_path):
        f = tmp_path / "sl.yaml"
        f.write_text(textwrap.dedent("""\
            version: "1"
            delegated_admin_account: "123456789012"
            services:
              security_lake:
                enabled: true
                regions:
                  - us-east-1
                  - eu-west-1
                organization:
                  auto_enable_new_accounts: true
                lifecycle:
                  expiration_days: 180
                  transition_days: 30
                  transition_storage_class: GLACIER_FLEXIBLE_RETRIEVAL
                sources:
                  - CLOUD_TRAIL_MGMT
                  - VPC_FLOW
        """))
        cfg = load_config(f)
        sl = cfg.services.security_lake
        assert sl.enabled is True
        assert sl.regions == ["us-east-1", "eu-west-1"]
        assert sl.organization.auto_enable_new_accounts is True
        assert sl.lifecycle.expiration_days == 180
        assert sl.lifecycle.transition_days == 30
        assert sl.lifecycle.transition_storage_class == "GLACIER_FLEXIBLE_RETRIEVAL"
        assert sl.sources == ["CLOUD_TRAIL_MGMT", "VPC_FLOW"]

    def test_validation_error_in_yaml(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text(textwrap.dedent("""\
            version: "1"
            delegated_admin_account: "123456789012"
            services:
              guardduty:
                detector:
                  finding_publishing_frequency: BAD_VALUE
        """))
        with pytest.raises(ValueError, match="validation"):
            load_config(f)

    def test_full_config(self, tmp_path):
        f = tmp_path / "full.yaml"
        f.write_text(textwrap.dedent("""\
            version: "1"
            delegated_admin_account: "999999999999"
            services:
              guardduty:
                enabled: true
                detector:
                  finding_publishing_frequency: ONE_HOUR
                organization:
                  auto_enable: NEW
                protection_plans:
                  s3_logs: true
                  rds_login_events: false
                  eks_audit_logs: false
                  eks_runtime: false
                  ecs_runtime: false
                  ec2_malware_scan: false
                  lambda_network_logs: false
              security_hub:
                enabled: false
              macie:
                enabled: true
                automated_discovery:
                  enabled: false
                  sampling_depth: 50
                  managed_identifiers: ALL
              inspector:
                enabled: true
                scan_types:
                  ec2: true
                  ecr: false
                  lambda: false
                  lambda_code: false
              access_analyzer:
                enabled: true
                analyzers:
                  - name: my-analyzer
                    type: ORGANIZATION
        """))
        cfg = load_config(f)
        assert cfg.delegated_admin_account == "999999999999"
        assert cfg.services.guardduty.detector.finding_publishing_frequency == "ONE_HOUR"
        assert cfg.services.guardduty.organization.auto_enable == "NEW"
        assert cfg.services.security_hub.enabled is False
        assert cfg.services.macie.automated_discovery.sampling_depth == 50
        assert cfg.services.macie.automated_discovery.managed_identifiers == "ALL"
        assert cfg.services.inspector.scan_types.ec2 is True
        assert cfg.services.inspector.scan_types.ecr is False
        assert cfg.services.access_analyzer.analyzers[0].name == "my-analyzer"
