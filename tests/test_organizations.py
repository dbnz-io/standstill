import boto3
import pytest
from moto import mock_aws

from standstill.aws.organizations import (
    build_ou_tree,
    flatten_ous,
)


@mock_aws
def test_build_ou_tree_empty_org():
    """A brand-new org has no OUs → tree is empty."""
    boto3.client("organizations", region_name="us-east-1").create_organization(FeatureSet="ALL")
    nodes = build_ou_tree()
    assert nodes == []


@mock_aws
def test_build_ou_tree_with_ous():
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]

    ou = org.create_organizational_unit(ParentId=root_id, Name="Security")
    ou_id = ou["OrganizationalUnit"]["Id"]

    nodes = build_ou_tree()
    assert len(nodes) == 1
    assert nodes[0].name == "Security"
    assert nodes[0].id == ou_id


@mock_aws
def test_flatten_ous_nested():
    org = boto3.client("organizations", region_name="us-east-1")
    org.create_organization(FeatureSet="ALL")
    root_id = org.list_roots()["Roots"][0]["Id"]

    parent = org.create_organizational_unit(ParentId=root_id, Name="Parent")
    parent_id = parent["OrganizationalUnit"]["Id"]
    org.create_organizational_unit(ParentId=parent_id, Name="Child")

    nodes = build_ou_tree()
    flat = flatten_ous(nodes)
    assert len(flat) == 2
    names = {n.name for n in flat}
    assert names == {"Parent", "Child"}


@mock_aws
def test_schemas_model_validation():
    """ControlTarget rejects malformed OU IDs and ARNs."""
    from pydantic import ValidationError

    from standstill.models.schemas import ControlTarget

    with pytest.raises(ValidationError):
        ControlTarget(ou_id="not-a-valid-id", controls=["arn:aws:controltower:us-east-1::control/X"])

    with pytest.raises(ValidationError):
        ControlTarget(ou_id="ou-ab12-34cd5678", controls=["not-an-arn"])

    # Valid case should not raise
    t = ControlTarget(
        ou_id="ou-ab12-34cd5678",
        controls=["arn:aws:controltower:us-east-1::control/AWS-GR_ENCRYPTED_VOLUMES"],
    )
    assert t.ou_id == "ou-ab12-34cd5678"
