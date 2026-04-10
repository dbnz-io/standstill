"""Tests for standstill/config.py and standstill/state.py"""
from __future__ import annotations

from unittest.mock import patch

import boto3
import pytest
from moto import mock_aws

import standstill.config as cfg_module
from standstill.state import AppState

# ---------------------------------------------------------------------------
# Helpers — redirect config file to a temp dir
# ---------------------------------------------------------------------------

@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    config_path = tmp_path / ".standstill" / "config.yaml"
    monkeypatch.setattr(cfg_module, "_CONFIG_PATH", config_path)
    return config_path


# ---------------------------------------------------------------------------
# config.py
# ---------------------------------------------------------------------------

class TestStandstillConfig:
    def test_load_missing_returns_empty(self, isolated_config):
        assert cfg_module.load() == {}

    def test_set_and_get_management_role(self, isolated_config):
        role = "arn:aws:iam::123456789012:role/MyRole"
        cfg_module.set_management_role(role)
        assert cfg_module.get_management_role() == role

    def test_get_management_role_missing(self, isolated_config):
        assert cfg_module.get_management_role() is None

    def test_unset_management_role(self, isolated_config):
        cfg_module.set_management_role("arn:aws:iam::123456789012:role/MyRole")
        cfg_module.unset_management_role()
        assert cfg_module.get_management_role() is None

    def test_unset_when_not_set(self, isolated_config):
        cfg_module.unset_management_role()  # should not raise
        assert cfg_module.get_management_role() is None

    def test_creates_parent_dirs(self, isolated_config):
        cfg_module.set_management_role("arn:aws:iam::000000000000:role/R")
        assert isolated_config.exists()

    def test_save_preserves_other_keys(self, isolated_config):
        cfg_module.save({"other_key": "value", "management_role_arn": "arn:aws:iam::000000000000:role/R"})
        cfg_module.unset_management_role()
        data2 = cfg_module.load()
        assert "other_key" in data2
        assert "management_role_arn" not in data2


# ---------------------------------------------------------------------------
# state.py
# ---------------------------------------------------------------------------

class TestAppState:
    def test_defaults(self):
        s = AppState()
        assert s.profile is None
        assert s.region is None
        assert s.output == "table"

    def test_reset_clears_session(self):
        s = AppState()
        s._session = object()  # type: ignore[assignment]
        s.reset()
        assert s._session is None

    @mock_aws
    def test_session_no_role(self):
        s = AppState(region="us-east-1")
        with patch.object(cfg_module, "get_management_role", return_value=None):
            session = s.session()
        assert isinstance(session, boto3.Session)

    @mock_aws
    def test_session_cached(self):
        s = AppState(region="us-east-1")
        with patch.object(cfg_module, "get_management_role", return_value=None):
            sess1 = s.session()
            sess2 = s.session()
        assert sess1 is sess2

    @mock_aws
    def test_session_with_management_role(self):
        # moto STS will accept any assume_role call
        role_arn = "arn:aws:iam::123456789012:role/TestRole"
        s = AppState(region="us-east-1")
        with patch.object(cfg_module, "get_management_role", return_value=role_arn):
            session = s.session()
        assert isinstance(session, boto3.Session)

    @mock_aws
    def test_get_client(self):
        s = AppState(region="us-east-1")
        with patch.object(cfg_module, "get_management_role", return_value=None):
            client = s.get_client("sts")
        assert client is not None

    @mock_aws
    def test_management_role_arn_reads_config(self, isolated_config, monkeypatch):
        role = "arn:aws:iam::123456789012:role/R"
        cfg_module.set_management_role(role)
        s = AppState()
        assert s.management_role_arn == role

    def test_invalid_profile_raises(self):
        s = AppState(profile="nonexistent-profile-xyz")
        with pytest.raises(RuntimeError, match="profile"):
            s.session()
