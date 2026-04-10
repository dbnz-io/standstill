from moto import mock_aws

from standstill.aws import session as aws_session


@mock_aws
def test_get_caller_identity_returns_account():
    identity = aws_session.get_caller_identity()
    assert "Account" in identity
    assert "Arn" in identity
    assert "UserId" in identity


@mock_aws
def test_check_ct_permissions_returns_dict():
    results = aws_session.check_ct_permissions()
    assert isinstance(results, dict)
    assert "organizations:DescribeOrganization" in results
    assert "controltower:ListLandingZones" in results
