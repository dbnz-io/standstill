"""Tests for standstill/aws/security_services.py"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from botocore.exceptions import ClientError

import standstill.aws.security_services as sec
from standstill import state as _state
from standstill.aws.organizations import Account
from standstill.models.security_config import (
    AccessAnalyzerConfig,
    GuardDutyConfig,
    InspectorConfig,
    MacieConfig,
    SecurityHubConfig,
    SecurityLakeConfig,
    SecurityServicesConfig,
    ServicesConfig,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(admin="123456789012", **service_overrides):
    """Build a minimal SecurityServicesConfig for testing."""
    return SecurityServicesConfig(
        delegated_admin_account=admin,
        services=ServicesConfig(),
    )


def _client_error(code, message="Some error"):
    response = {"Error": {"Code": code, "Message": message}}
    return ClientError(response, "TestOp")


# ---------------------------------------------------------------------------
# check_delegated_admins
# ---------------------------------------------------------------------------

class TestCheckDelegatedAdmins:
    def test_no_admins_registered(self):
        mock_org = MagicMock()
        mock_org.list_delegated_administrators.return_value = {"DelegatedAdministrators": []}
        with patch.object(_state.state, "get_client", return_value=mock_org):
            statuses = sec.check_delegated_admins("123456789012", "us-east-1")
        assert len(statuses) == len(sec.SERVICE_PRINCIPALS)
        for s in statuses:
            assert s.action == "register"
            assert s.current_admin is None

    def test_error_from_api(self):
        mock_org = MagicMock()
        mock_org.list_delegated_administrators.side_effect = _client_error("AccessDeniedException")
        with patch.object(_state.state, "get_client", return_value=mock_org):
            statuses = sec.check_delegated_admins("123456789012", "us-east-1")
        for s in statuses:
            assert s.action == "error"
            assert s.error != ""

    def test_already_registered_skip(self):
        mock_org = MagicMock()
        mock_org.list_delegated_administrators.return_value = {
            "DelegatedAdministrators": [{"Id": "123456789012"}]
        }
        with patch.object(_state.state, "get_client", return_value=mock_org):
            statuses = sec.check_delegated_admins("123456789012", "us-east-1")
        for s in statuses:
            assert s.action == "skip"

    def test_conflict_different_account(self):
        mock_org = MagicMock()
        mock_org.list_delegated_administrators.return_value = {
            "DelegatedAdministrators": [{"Id": "999999999999"}]
        }
        with patch.object(_state.state, "get_client", return_value=mock_org):
            statuses = sec.check_delegated_admins("123456789012", "us-east-1")
        for s in statuses:
            assert s.action == "conflict"
            assert s.current_admin == "999999999999"


# ---------------------------------------------------------------------------
# register_delegated_admin
# ---------------------------------------------------------------------------

class TestRegisterDelegatedAdmin:
    def _mock_client(self, service_name, side_effect=None):
        m = MagicMock()
        if side_effect:
            getattr(m, {
                "guardduty": "enable_organization_admin_account",
                "security_hub": "enable_organization_admin_account",
                "macie": "enable_organization_admin_account",
                "inspector": "enable_delegated_admin_account",
                "access_analyzer": "register_delegated_administrator",
                "security_lake": "register_data_lake_delegated_administrator",
            }[service_name]).side_effect = side_effect
        return m

    def _register(self, svc, mock_client):
        with patch.object(_state.state, "get_client", return_value=mock_client):
            return sec.register_delegated_admin(svc, "123456789012", "us-east-1")

    def test_guardduty_success(self):
        result = self._register("guardduty", self._mock_client("guardduty"))
        assert result.success

    def test_security_hub_success(self):
        result = self._register("security_hub", self._mock_client("security_hub"))
        assert result.success

    def test_macie_success(self):
        result = self._register("macie", self._mock_client("macie"))
        assert result.success

    def test_inspector_success(self):
        result = self._register("inspector", self._mock_client("inspector"))
        assert result.success

    def test_access_analyzer_success(self):
        result = self._register("access_analyzer", self._mock_client("access_analyzer"))
        assert result.success

    def test_security_lake_success(self):
        result = self._register("security_lake", self._mock_client("security_lake"))
        assert result.success

    def test_already_registered_is_success(self):
        m = MagicMock()
        m.enable_organization_admin_account.side_effect = _client_error(
            "AccountAlreadyRegisteredException"
        )
        result = self._register("guardduty", m)
        assert result.success
        assert "Already registered" in result.message

    def test_security_lake_conflict_is_success(self):
        m = MagicMock()
        m.register_data_lake_delegated_administrator.side_effect = _client_error(
            "ConflictException"
        )
        result = self._register("security_lake", m)
        assert result.success
        assert "Already registered" in result.message

    def test_other_error_is_failure(self):
        m = MagicMock()
        m.enable_organization_admin_account.side_effect = _client_error("AccessDeniedException")
        result = self._register("guardduty", m)
        assert not result.success


# ---------------------------------------------------------------------------
# configure_guardduty
# ---------------------------------------------------------------------------

class TestConfigureGuardDuty:
    def test_creates_detector_if_missing(self):
        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": []}
        mock_gd.create_detector.return_value = {"DetectorId": "abc123"}
        with patch.object(sec, "_admin_client", return_value=mock_gd):
            result = sec.configure_guardduty(GuardDutyConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_gd.create_detector.assert_called_once()

    def test_updates_existing_detector(self):
        mock_gd = MagicMock()
        mock_gd.list_detectors.return_value = {"DetectorIds": ["det-1"]}
        with patch.object(sec, "_admin_client", return_value=mock_gd):
            result = sec.configure_guardduty(GuardDutyConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_gd.update_detector.assert_called_once()
        mock_gd.update_organization_configuration.assert_called_once()

    def test_runtime_error(self):
        with patch.object(sec, "_admin_client", side_effect=RuntimeError("no creds")):
            result = sec.configure_guardduty(GuardDutyConfig(), "admin", "Role", "us-east-1")
        assert not result.success
        assert "no creds" in result.message


# ---------------------------------------------------------------------------
# configure_security_hub
# ---------------------------------------------------------------------------

class TestConfigureSecurityHub:
    def _mock_sh(self, already_enabled=False):
        m = MagicMock()
        if already_enabled:
            m.enable_security_hub.side_effect = _client_error("ResourceConflictException")
        m.get_enabled_standards.return_value = {"StandardsSubscriptions": []}
        m.list_finding_aggregators.return_value = {"FindingAggregators": []}
        return m

    def test_enables_hub(self):
        mock_sh = self._mock_sh()
        with patch.object(sec, "_admin_client", return_value=mock_sh):
            result = sec.configure_security_hub(SecurityHubConfig(), "admin", "Role", "us-east-1")
        assert result.success

    def test_hub_already_enabled_is_ok(self):
        mock_sh = self._mock_sh(already_enabled=True)
        with patch.object(sec, "_admin_client", return_value=mock_sh):
            result = sec.configure_security_hub(SecurityHubConfig(), "admin", "Role", "us-east-1")
        assert result.success

    def test_enables_standards(self):
        mock_sh = self._mock_sh()
        cfg = SecurityHubConfig(standards={"fsbp": True, "cis_1_4": True})
        with patch.object(sec, "_admin_client", return_value=mock_sh):
            result = sec.configure_security_hub(cfg, "admin", "Role", "us-east-1")
        assert result.success
        mock_sh.batch_enable_standards.assert_called_once()

    def test_skips_already_enabled_standard(self):
        mock_sh = self._mock_sh()
        mock_sh.get_enabled_standards.return_value = {
            "StandardsSubscriptions": [{
                "StandardsArn": "arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0"
            }]
        }
        cfg = SecurityHubConfig()  # fsbp=True by default
        with patch.object(sec, "_admin_client", return_value=mock_sh):
            result = sec.configure_security_hub(cfg, "admin", "Role", "us-east-1")
        assert result.success
        mock_sh.batch_enable_standards.assert_not_called()

    def test_cross_region_aggregation_creates(self):
        mock_sh = self._mock_sh()
        cfg = SecurityHubConfig(cross_region_aggregation=True)
        with patch.object(sec, "_admin_client", return_value=mock_sh):
            result = sec.configure_security_hub(cfg, "admin", "Role", "us-east-1")
        assert result.success
        mock_sh.create_finding_aggregator.assert_called_once_with(RegionLinkingMode="ALL_REGIONS")
        assert any("aggregation" in d.lower() for d in result.details)

    def test_cross_region_aggregation_updates_existing(self):
        mock_sh = self._mock_sh()
        mock_sh.list_finding_aggregators.return_value = {
            "FindingAggregators": [{"FindingAggregatorArn": "arn:aws:securityhub:us-east-1::aggregator/1"}]
        }
        cfg = SecurityHubConfig(cross_region_aggregation=True)
        with patch.object(sec, "_admin_client", return_value=mock_sh):
            result = sec.configure_security_hub(cfg, "admin", "Role", "us-east-1")
        assert result.success
        mock_sh.update_finding_aggregator.assert_called_once()

    def test_runtime_error(self):
        with patch.object(sec, "_admin_client", side_effect=RuntimeError("fail")):
            result = sec.configure_security_hub(SecurityHubConfig(), "admin", "Role", "us-east-1")
        assert not result.success


# ---------------------------------------------------------------------------
# configure_macie
# ---------------------------------------------------------------------------

class TestConfigureMacie:
    def test_enables_macie(self):
        mock_mc = MagicMock()
        with patch.object(sec, "_admin_client", return_value=mock_mc):
            result = sec.configure_macie(MacieConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_mc.enable_macie.assert_called_once()

    def test_macie_already_enabled(self):
        mock_mc = MagicMock()
        mock_mc.enable_macie.side_effect = _client_error("ValidationException")
        with patch.object(sec, "_admin_client", return_value=mock_mc):
            result = sec.configure_macie(MacieConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_mc.update_macie_session.assert_called_once()

    def test_runtime_error(self):
        with patch.object(sec, "_admin_client", side_effect=RuntimeError("fail")):
            result = sec.configure_macie(MacieConfig(), "admin", "Role", "us-east-1")
        assert not result.success


# ---------------------------------------------------------------------------
# configure_inspector
# ---------------------------------------------------------------------------

class TestConfigureInspector:
    def test_enables_scan_types(self):
        mock_ins = MagicMock()
        with patch.object(sec, "_admin_client", return_value=mock_ins):
            result = sec.configure_inspector(InspectorConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_ins.enable.assert_called_once()
        mock_ins.update_organization_configuration.assert_called_once()

    def test_no_scan_types_skips_enable(self):
        mock_ins = MagicMock()
        from standstill.models.security_config import InspectorScanTypes
        cfg = InspectorConfig(scan_types=InspectorScanTypes(ec2=False, ecr=False))
        with patch.object(sec, "_admin_client", return_value=mock_ins):
            result = sec.configure_inspector(cfg, "admin", "Role", "us-east-1")
        assert result.success
        mock_ins.enable.assert_not_called()

    def test_runtime_error(self):
        with patch.object(sec, "_admin_client", side_effect=RuntimeError("fail")):
            result = sec.configure_inspector(InspectorConfig(), "admin", "Role", "us-east-1")
        assert not result.success


# ---------------------------------------------------------------------------
# configure_access_analyzer
# ---------------------------------------------------------------------------

class TestConfigureAccessAnalyzer:
    def test_creates_analyzer_if_missing(self):
        mock_aa = MagicMock()
        mock_aa.list_analyzers.return_value = {"analyzers": []}
        with patch.object(sec, "_admin_client", return_value=mock_aa):
            result = sec.configure_access_analyzer(AccessAnalyzerConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_aa.create_analyzer.assert_called_once()

    def test_skips_existing_analyzer(self):
        mock_aa = MagicMock()
        mock_aa.list_analyzers.return_value = {
            "analyzers": [{"name": "standstill-org-analyzer", "type": "ORGANIZATION"}]
        }
        with patch.object(sec, "_admin_client", return_value=mock_aa):
            result = sec.configure_access_analyzer(AccessAnalyzerConfig(), "admin", "Role", "us-east-1")
        assert result.success
        mock_aa.create_analyzer.assert_not_called()
        assert "Exists" in result.details[0]

    def test_runtime_error(self):
        with patch.object(sec, "_admin_client", side_effect=RuntimeError("fail")):
            result = sec.configure_access_analyzer(AccessAnalyzerConfig(), "admin", "Role", "us-east-1")
        assert not result.success


# ---------------------------------------------------------------------------
# configure_security_lake
# ---------------------------------------------------------------------------

class TestConfigureSecurityLake:
    def _mock_sl(self, existing_regions=None):
        m = MagicMock()
        lakes = [{"region": r} for r in (existing_regions or [])]
        m.list_data_lakes.return_value = {"dataLakes": lakes}
        m.get_data_lake_organization_configuration.return_value = {"autoEnableNewAccount": []}
        return m

    def test_creates_new_lake(self):
        mock_sl = self._mock_sl(existing_regions=[])
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            result = sec.configure_security_lake(
                SecurityLakeConfig(enabled=True), "admin", "Role", "us-east-1"
            )
        assert result.success
        mock_sl.create_data_lake.assert_called_once()
        mock_sl.update_data_lake.assert_not_called()

    def test_updates_existing_lake(self):
        mock_sl = self._mock_sl(existing_regions=["us-east-1"])
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            result = sec.configure_security_lake(
                SecurityLakeConfig(enabled=True), "admin", "Role", "us-east-1"
            )
        assert result.success
        mock_sl.create_data_lake.assert_not_called()
        mock_sl.update_data_lake.assert_called_once()

    def test_org_auto_enable_configured(self):
        mock_sl = self._mock_sl()
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            result = sec.configure_security_lake(
                SecurityLakeConfig(enabled=True, sources=["CLOUD_TRAIL_MGMT"]),
                "admin", "Role", "us-east-1",
            )
        assert result.success
        mock_sl.create_data_lake_organization_configuration.assert_called_once()
        call_kwargs = mock_sl.create_data_lake_organization_configuration.call_args[1]
        assert any(
            s["sourceName"] == "CLOUD_TRAIL_MGMT"
            for entry in call_kwargs["autoEnableNewAccount"]
            for s in entry["sources"]
        )

    def test_no_auto_enable_when_disabled(self):
        from standstill.models.security_config import SecurityLakeOrg
        mock_sl = self._mock_sl()
        cfg = SecurityLakeConfig(
            enabled=True,
            organization=SecurityLakeOrg(auto_enable_new_accounts=False),
        )
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            result = sec.configure_security_lake(cfg, "admin", "Role", "us-east-1")
        assert result.success
        mock_sl.create_data_lake_organization_configuration.assert_not_called()

    def test_default_meta_role_derived_from_account(self):
        mock_sl = self._mock_sl()
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            sec.configure_security_lake(
                SecurityLakeConfig(enabled=True), "123456789012", "Role", "us-east-1"
            )
        call_kwargs = mock_sl.create_data_lake.call_args[1]
        assert call_kwargs["metaStoreManagerRoleArn"] == (
            "arn:aws:iam::123456789012:role/AmazonSecurityLakeMetaStoreManagerV2"
        )

    def test_custom_meta_role_used(self):
        mock_sl = self._mock_sl()
        custom_arn = "arn:aws:iam::123456789012:role/MyCustomRole"
        cfg = SecurityLakeConfig(enabled=True, meta_store_manager_role_arn=custom_arn)
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            sec.configure_security_lake(cfg, "123456789012", "Role", "us-east-1")
        call_kwargs = mock_sl.create_data_lake.call_args[1]
        assert call_kwargs["metaStoreManagerRoleArn"] == custom_arn

    def test_lifecycle_included_when_set(self):
        from standstill.models.security_config import SecurityLakeLifecycle
        mock_sl = self._mock_sl()
        cfg = SecurityLakeConfig(
            enabled=True,
            lifecycle=SecurityLakeLifecycle(expiration_days=90, transition_days=30),
        )
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            sec.configure_security_lake(cfg, "admin", "Role", "us-east-1")
        confs = mock_sl.create_data_lake.call_args[1]["configurations"]
        assert "lifecycleConfiguration" in confs[0]
        lc = confs[0]["lifecycleConfiguration"]
        assert lc["expiration"]["days"] == 90
        assert lc["transitions"][0]["days"] == 30

    def test_lifecycle_omitted_when_zero(self):
        from standstill.models.security_config import SecurityLakeLifecycle
        mock_sl = self._mock_sl()
        cfg = SecurityLakeConfig(
            enabled=True,
            lifecycle=SecurityLakeLifecycle(expiration_days=0, transition_days=0),
        )
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            sec.configure_security_lake(cfg, "admin", "Role", "us-east-1")
        confs = mock_sl.create_data_lake.call_args[1]["configurations"]
        assert "lifecycleConfiguration" not in confs[0]

    def test_runtime_error(self):
        with patch.object(sec, "_admin_client", side_effect=RuntimeError("no creds")):
            result = sec.configure_security_lake(
                SecurityLakeConfig(enabled=True), "admin", "Role", "us-east-1"
            )
        assert not result.success
        assert "no creds" in result.message

    def test_org_config_conflict_does_not_fail(self):
        mock_sl = self._mock_sl()
        mock_sl.create_data_lake_organization_configuration.side_effect = _client_error(
            "ConflictException", "already exists"
        )
        with patch.object(sec, "_admin_client", return_value=mock_sl):
            result = sec.configure_security_lake(
                SecurityLakeConfig(enabled=True), "admin", "Role", "us-east-1"
            )
        # Conflict on org config is logged as a detail, not a fatal error
        assert result.success


# ---------------------------------------------------------------------------
# apply_services
# ---------------------------------------------------------------------------

class TestApplyServices:
    def _all_skip_delegation(self):
        """Patch check_delegated_admins to always return 'skip'."""
        statuses = [
            sec.DelegationStatus(
                service=svc, principal=p,
                current_admin="123456789012", target_admin="123456789012",
                action="skip",
            )
            for svc, p in sec.SERVICE_PRINCIPALS.items()
        ]
        return statuses

    def test_happy_path(self):
        config = _make_config()
        mock_result = sec.ServiceApplyResult(
            service="guardduty", phase="configuration", success=True, message="ok"
        )
        with (
            patch.object(sec, "check_delegated_admins", return_value=self._all_skip_delegation()),
            patch.object(sec, "configure_guardduty", return_value=mock_result),
            patch.object(sec, "configure_security_hub", return_value=mock_result),
            patch.object(sec, "configure_macie", return_value=mock_result),
            patch.object(sec, "configure_inspector", return_value=mock_result),
            patch.object(sec, "configure_access_analyzer", return_value=mock_result),
            patch.object(sec, "configure_security_lake", return_value=mock_result),
        ):
            p1, p2 = sec.apply_services(config, "Role", "us-east-1")
        assert all(r.success for r in p1)
        assert all(r.success for r in p2)

    def test_delegation_conflict_skips_phase2(self):
        config = _make_config()
        conflict_statuses = [
            sec.DelegationStatus(
                service=svc, principal=p,
                current_admin="999999999999", target_admin="123456789012",
                action="conflict",
            )
            for svc, p in sec.SERVICE_PRINCIPALS.items()
        ]
        with patch.object(sec, "check_delegated_admins", return_value=conflict_statuses):
            p1, p2 = sec.apply_services(config, "Role", "us-east-1")
        assert all(not r.success for r in p1)
        assert p2 == []

    def test_disabled_service_skipped(self):
        from standstill.models.security_config import GuardDutyConfig
        config = SecurityServicesConfig(
            delegated_admin_account="123456789012",
            services=ServicesConfig(guardduty=GuardDutyConfig(enabled=False)),
        )
        ok = sec.ServiceApplyResult("x", "configuration", True, "ok")
        with (
            patch.object(sec, "check_delegated_admins", return_value=self._all_skip_delegation()),
            patch.object(sec, "configure_security_hub", return_value=ok),
            patch.object(sec, "configure_macie", return_value=ok),
            patch.object(sec, "configure_inspector", return_value=ok),
            patch.object(sec, "configure_access_analyzer", return_value=ok),
            patch.object(sec, "configure_security_lake", return_value=ok),
        ):
            p1, p2 = sec.apply_services(config, "Role", "us-east-1")
        gd_p2 = [r for r in p2 if r.service == "guardduty"]
        assert gd_p2 == []


# ---------------------------------------------------------------------------
# assess_member_accounts
# ---------------------------------------------------------------------------

class TestAssessMemberAccounts:
    def _mock_accounts(self):
        return [
            Account("111111111111", "arn:...", "Security", "s@x.com", "ACTIVE", "ou-1", "Security"),
            Account("222222222222", "arn:...", "Dev", "d@x.com", "ACTIVE", "ou-2", "Dev"),
            Account("123456789012", "arn:...", "Delegated", "da@x.com", "ACTIVE", "ou-3", "Infra"),
        ]

    def test_basic_coverage(self):
        config = _make_config(admin="123456789012")
        accounts = self._mock_accounts()
        member_data = {
            "111111111111": "Enabled",
            "222222222222": "Enabled",
        }

        with (
            patch("standstill.aws.organizations.build_ou_tree"),
            patch("standstill.aws.organizations.all_accounts", return_value=accounts),
            patch.object(_state.state, "get_client") as mock_get,
            patch.object(sec, "_members_guardduty", return_value=member_data),
            patch.object(sec, "_members_security_hub", return_value=member_data),
            patch.object(sec, "_members_macie", return_value=member_data),
            patch.object(sec, "_members_inspector", return_value=member_data),
        ):
            mock_org = MagicMock()
            mock_org.describe_organization.return_value = {
                "Organization": {"MasterAccountId": "000000000000"}
            }
            mock_get.return_value = mock_org
            results = sec.assess_member_accounts(config, "Role", "us-east-1")

        assert len(results) == 3
        # delegated admin account should be labelled as such
        admin_result = next(r for r in results if r.account_id == "123456789012")
        assert all(
            s.member_status == "delegated_admin"
            for s in admin_result.services.values()
        )

    def test_not_member_marked_unhealthy(self):
        config = _make_config(admin="123456789012")
        accounts = [
            Account("111111111111", "arn:...", "Dev", "d@x.com", "ACTIVE", "ou-1", "Dev"),
        ]

        with (
            patch("standstill.aws.organizations.build_ou_tree"),
            patch("standstill.aws.organizations.all_accounts", return_value=accounts),
            patch.object(_state.state, "get_client") as mock_get,
            patch.object(sec, "_members_guardduty", return_value={}),
            patch.object(sec, "_members_security_hub", return_value={}),
            patch.object(sec, "_members_macie", return_value={}),
            patch.object(sec, "_members_inspector", return_value={}),
        ):
            mock_org = MagicMock()
            mock_org.describe_organization.return_value = {
                "Organization": {"MasterAccountId": "000000000000"}
            }
            mock_get.return_value = mock_org
            results = sec.assess_member_accounts(config, "Role", "us-east-1")

        assert len(results) == 1
        assert not results[0].healthy

    def test_service_error_reported(self):
        config = _make_config(admin="123456789012")
        accounts = [
            Account("111111111111", "arn:...", "Dev", "d@x.com", "ACTIVE", "ou-1", "Dev"),
        ]

        with (
            patch("standstill.aws.organizations.build_ou_tree"),
            patch("standstill.aws.organizations.all_accounts", return_value=accounts),
            patch.object(_state.state, "get_client") as mock_get,
            patch.object(sec, "_members_guardduty", side_effect=RuntimeError("API error")),
            patch.object(sec, "_members_security_hub", return_value={}),
            patch.object(sec, "_members_macie", return_value={}),
            patch.object(sec, "_members_inspector", return_value={}),
        ):
            mock_org = MagicMock()
            mock_org.describe_organization.return_value = {
                "Organization": {"MasterAccountId": "000000000000"}
            }
            mock_get.return_value = mock_org
            results = sec.assess_member_accounts(config, "Role", "us-east-1")

        gd_status = results[0].services.get("guardduty")
        assert gd_status is not None
        assert gd_status.error != ""
