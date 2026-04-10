
import boto3
import pytest
from moto import mock_aws

from standstill import state as _state


@pytest.fixture(autouse=True)
def aws_env(monkeypatch):
    """Inject fake AWS credentials for every test."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture(autouse=True)
def reset_state():
    """Reset the global AppState singleton before each test."""
    _state.state.profile = None
    _state.state.region = "us-east-1"
    _state.state.output = "table"
    _state.state.reset()
    yield
    _state.state.reset()


@pytest.fixture
def org_client():
    """Return a moto-backed Organizations client with a fresh org."""
    with mock_aws():
        client = boto3.client("organizations", region_name="us-east-1")
        client.create_organization(FeatureSet="ALL")
        yield client
