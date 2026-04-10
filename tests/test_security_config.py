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
