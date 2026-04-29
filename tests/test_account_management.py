"""Tests for account and OU management commands."""
from __future__ import annotations

from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from standstill.main import app

runner = CliRunner()

# ---------------------------------------------------------------------------
# Shared fixtures
# ---------------------------------------------------------------------------

_ACCOUNT_INFO = {
    "Id": "123456789012",
    "Arn": "arn:aws:organizations::111111111111:account/o-xxx/123456789012",
    "Name": "TestAccount",
    "Email": "test@example.com",
    "Status": "ACTIVE",
    "JoinedMethod": "INVITED",
    "JoinedTimestamp": "2024-01-01",
    "ParentId": "ou-ab12-34cd5678",
}

_OU_INFO = {
    "Id": "ou-ab12-34cd5678",
    "Arn": "arn:aws:organizations::111111111111:ou/o-xxx/ou-ab12-34cd5678",
    "Name": "TestOU",
    "ParentId": "r-ab12",
    "ChildOUs": [],
    "Accounts": [],
}


# ===========================================================================
# accounts create
# ===========================================================================

class TestAccountsCreate:
    def test_missing_required_args(self):
        result = runner.invoke(app, ["accounts", "create"])
        assert result.exit_code != 0

    def test_create_no_wait(self):
        with patch(
            "standstill.commands.accounts.af_api.create_managed_account",
            return_value="op-12345",
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "create",
                    "--name", "TestAccount",
                    "--email", "test@example.com",
                    "--ou", "ou-ab12-34cd5678",
                    "--no-wait",
                ],
            )
        assert result.exit_code == 0
        assert "op-12345" in result.output

    def test_create_api_error(self):
        from botocore.exceptions import ClientError
        error = ClientError(
            {"Error": {"Code": "ValidationException", "Message": "Invalid OU"}},
            "CreateManagedAccount",
        )
        with patch(
            "standstill.commands.accounts.af_api.create_managed_account",
            side_effect=error,
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "create",
                    "--name", "TestAccount",
                    "--email", "test@example.com",
                    "--ou", "ou-bad",
                    "--no-wait",
                ],
            )
        assert result.exit_code == 1

    def test_create_wait_success(self):
        op_result = {"status": "SUCCEEDED", "operationType": "CREATE_MANAGED_ACCOUNT"}
        with (
            patch(
                "standstill.commands.accounts.af_api.create_managed_account",
                return_value="op-12345",
            ),
            patch(
                "standstill.commands.accounts._poll_with_progress",
                return_value=op_result,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "create",
                    "--name", "TestAccount",
                    "--email", "test@example.com",
                    "--ou", "ou-ab12-34cd5678",
                ],
            )
        assert result.exit_code == 0
        assert "created successfully" in result.output

    def test_create_wait_failed(self):
        op_result = {"status": "FAILED", "statusMessage": "Email already exists"}
        with (
            patch(
                "standstill.commands.accounts.af_api.create_managed_account",
                return_value="op-12345",
            ),
            patch(
                "standstill.commands.accounts._poll_with_progress",
                return_value=op_result,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "create",
                    "--name", "TestAccount",
                    "--email", "test@example.com",
                    "--ou", "ou-ab12-34cd5678",
                ],
            )
        assert result.exit_code == 1
        assert "Email already exists" in result.output


# ===========================================================================
# accounts enroll
# ===========================================================================

class TestAccountsEnroll:
    def test_missing_required_args(self):
        result = runner.invoke(app, ["accounts", "enroll"])
        assert result.exit_code != 0

    def test_enroll_no_wait(self):
        with patch(
            "standstill.commands.accounts.af_api.register_managed_account",
            return_value="op-enroll-1",
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "enroll",
                    "--account", "123456789012",
                    "--ou", "ou-ab12-34cd5678",
                    "--no-wait",
                ],
            )
        assert result.exit_code == 0
        assert "op-enroll-1" in result.output

    def test_enroll_wait_success(self):
        op_result = {"status": "SUCCEEDED", "operationType": "REGISTER_MANAGED_ACCOUNT"}
        with (
            patch(
                "standstill.commands.accounts.af_api.register_managed_account",
                return_value="op-enroll-1",
            ),
            patch(
                "standstill.commands.accounts._poll_with_progress",
                return_value=op_result,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "enroll",
                    "--account", "123456789012",
                    "--ou", "ou-ab12-34cd5678",
                ],
            )
        assert result.exit_code == 0
        assert "enrolled successfully" in result.output

    def test_enroll_wait_failed(self):
        op_result = {"status": "FAILED", "statusMessage": "Account already enrolled"}
        with (
            patch(
                "standstill.commands.accounts.af_api.register_managed_account",
                return_value="op-enroll-1",
            ),
            patch(
                "standstill.commands.accounts._poll_with_progress",
                return_value=op_result,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "enroll",
                    "--account", "123456789012",
                    "--ou", "ou-ab12-34cd5678",
                ],
            )
        assert result.exit_code == 1


# ===========================================================================
# accounts deregister
# ===========================================================================

class TestAccountsDeregister:
    def test_missing_required_args(self):
        result = runner.invoke(app, ["accounts", "deregister"])
        assert result.exit_code != 0

    def test_deregister_no_wait_with_yes(self):
        with patch(
            "standstill.commands.accounts.af_api.deregister_managed_account",
            return_value="op-deregister-1",
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "deregister",
                    "--account", "123456789012",
                    "--yes",
                    "--no-wait",
                ],
            )
        assert result.exit_code == 0
        assert "op-deregister-1" in result.output

    def test_deregister_prompts_without_yes(self):
        with patch(
            "standstill.commands.accounts.af_api.deregister_managed_account",
            return_value="op-deregister-1",
        ):
            # Simulate user typing "y" at confirmation
            result = runner.invoke(
                app,
                [
                    "accounts", "deregister",
                    "--account", "123456789012",
                    "--no-wait",
                ],
                input="y\n",
            )
        assert result.exit_code == 0

    def test_deregister_aborts_on_no(self):
        with patch(
            "standstill.commands.accounts.af_api.deregister_managed_account",
            return_value="op-deregister-1",
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "deregister",
                    "--account", "123456789012",
                    "--no-wait",
                ],
                input="n\n",
            )
        assert result.exit_code != 0

    def test_deregister_wait_success(self):
        op_result = {"status": "SUCCEEDED", "operationType": "DEREGISTER_MANAGED_ACCOUNT"}
        with (
            patch(
                "standstill.commands.accounts.af_api.deregister_managed_account",
                return_value="op-deregister-1",
            ),
            patch(
                "standstill.commands.accounts._poll_with_progress",
                return_value=op_result,
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "deregister",
                    "--account", "123456789012",
                    "--yes",
                ],
            )
        assert result.exit_code == 0
        assert "deregistered successfully" in result.output


# ===========================================================================
# accounts move
# ===========================================================================

class TestAccountsMove:
    def test_missing_required_args(self):
        result = runner.invoke(app, ["accounts", "move"])
        assert result.exit_code != 0

    def test_move_with_yes(self):
        with (
            patch(
                "standstill.commands.accounts.af_api.describe_account",
                return_value=_ACCOUNT_INFO,
            ),
            patch(
                "standstill.commands.accounts.af_api.move_account",
                return_value="ou-ab12-34cd5678",
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "move",
                    "--account", "123456789012",
                    "--ou", "ou-cd34-56ef7890",
                    "--yes",
                ],
            )
        assert result.exit_code == 0
        assert "moved to" in result.output

    def test_move_already_in_dest(self):
        with (
            patch(
                "standstill.commands.accounts.af_api.describe_account",
                return_value=_ACCOUNT_INFO,
            ),
            patch(
                "standstill.commands.accounts.af_api.move_account",
                side_effect=ValueError("Account 123456789012 is already in ou-cd34-56ef7890."),
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "move",
                    "--account", "123456789012",
                    "--ou", "ou-cd34-56ef7890",
                    "--yes",
                ],
            )
        assert result.exit_code == 0
        assert "Nothing to do" in result.output

    def test_move_prompts_without_yes(self):
        with (
            patch(
                "standstill.commands.accounts.af_api.describe_account",
                return_value=_ACCOUNT_INFO,
            ),
            patch(
                "standstill.commands.accounts.af_api.move_account",
                return_value="ou-ab12-34cd5678",
            ),
        ):
            result = runner.invoke(
                app,
                [
                    "accounts", "move",
                    "--account", "123456789012",
                    "--ou", "ou-cd34-56ef7890",
                ],
                input="y\n",
            )
        assert result.exit_code == 0


# ===========================================================================
# accounts describe
# ===========================================================================

class TestAccountsDescribe:
    def test_describe_success(self):
        with patch(
            "standstill.commands.accounts.af_api.describe_account",
            return_value=_ACCOUNT_INFO,
        ):
            result = runner.invoke(
                app,
                ["accounts", "describe", "--account", "123456789012"],
            )
        assert result.exit_code == 0
        assert "123456789012" in result.output
        assert "TestAccount" in result.output

    def test_describe_api_error(self):
        from botocore.exceptions import ClientError
        error = ClientError(
            {"Error": {"Code": "AccountNotFoundException", "Message": "Account not found"}},
            "DescribeAccount",
        )
        with patch(
            "standstill.commands.accounts.af_api.describe_account",
            side_effect=error,
        ):
            result = runner.invoke(
                app,
                ["accounts", "describe", "--account", "000000000000"],
            )
        assert result.exit_code == 1

    def test_describe_missing_arg(self):
        result = runner.invoke(app, ["accounts", "describe"])
        assert result.exit_code != 0


# ===========================================================================
# ou create
# ===========================================================================

class TestOUCreate:
    def test_create_with_parent(self):
        new_ou = {"Id": "ou-new-12345678", "Arn": "arn:aws:...", "Name": "NewOU"}
        with patch(
            "standstill.commands.ou.af_api.create_ou",
            return_value=new_ou,
        ):
            result = runner.invoke(
                app,
                ["ou", "create", "--name", "NewOU", "--parent", "ou-ab12-34cd5678"],
            )
        assert result.exit_code == 0
        assert "ou-new-12345678" in result.output
        assert "NewOU" in result.output

    def test_create_defaults_to_root(self):
        new_ou = {"Id": "ou-new-12345678", "Arn": "arn:aws:...", "Name": "TopLevel"}
        with (
            patch(
                "standstill.commands.ou.af_api.get_org_root_id",
                return_value="r-ab12",
            ),
            patch(
                "standstill.commands.ou.af_api.create_ou",
                return_value=new_ou,
            ) as mock_create,
        ):
            result = runner.invoke(app, ["ou", "create", "--name", "TopLevel"])
        assert result.exit_code == 0
        mock_create.assert_called_once_with(parent_id="r-ab12", name="TopLevel")

    def test_create_missing_name(self):
        result = runner.invoke(app, ["ou", "create"])
        assert result.exit_code != 0

    def test_create_api_error(self):
        from botocore.exceptions import ClientError
        error = ClientError(
            {"Error": {"Code": "DuplicateOrganizationalUnitException", "Message": "Duplicate name"}},
            "CreateOrganizationalUnit",
        )
        with patch("standstill.commands.ou.af_api.create_ou", side_effect=error):
            result = runner.invoke(
                app, ["ou", "create", "--name", "Duplicate", "--parent", "ou-ab12-34cd5678"]
            )
        assert result.exit_code == 1


# ===========================================================================
# ou delete
# ===========================================================================

class TestOUDelete:
    def test_delete_with_yes(self):
        with patch("standstill.commands.ou.af_api.delete_ou") as mock_delete:
            result = runner.invoke(
                app, ["ou", "delete", "--ou", "ou-ab12-34cd5678", "--yes"]
            )
        assert result.exit_code == 0
        mock_delete.assert_called_once_with(ou_id="ou-ab12-34cd5678")
        assert "deleted" in result.output

    def test_delete_prompts_without_yes(self):
        with patch("standstill.commands.ou.af_api.delete_ou"):
            result = runner.invoke(
                app, ["ou", "delete", "--ou", "ou-ab12-34cd5678"], input="y\n"
            )
        assert result.exit_code == 0

    def test_delete_aborts_on_no(self):
        with patch("standstill.commands.ou.af_api.delete_ou"):
            result = runner.invoke(
                app, ["ou", "delete", "--ou", "ou-ab12-34cd5678"], input="n\n"
            )
        assert result.exit_code != 0

    def test_delete_not_empty(self):
        from botocore.exceptions import ClientError
        error = ClientError(
            {
                "Error": {
                    "Code": "OrganizationalUnitNotEmptyException",
                    "Message": "OU contains accounts",
                }
            },
            "DeleteOrganizationalUnit",
        )
        with patch("standstill.commands.ou.af_api.delete_ou", side_effect=error):
            result = runner.invoke(
                app, ["ou", "delete", "--ou", "ou-ab12-34cd5678", "--yes"]
            )
        assert result.exit_code == 1

    def test_delete_missing_arg(self):
        result = runner.invoke(app, ["ou", "delete"])
        assert result.exit_code != 0


# ===========================================================================
# ou rename
# ===========================================================================

class TestOURename:
    def test_rename_success(self):
        updated = {"Id": "ou-ab12-34cd5678", "Arn": "arn:aws:...", "Name": "NewName"}
        with patch("standstill.commands.ou.af_api.rename_ou", return_value=updated):
            result = runner.invoke(
                app,
                ["ou", "rename", "--ou", "ou-ab12-34cd5678", "--name", "NewName"],
            )
        assert result.exit_code == 0
        assert "NewName" in result.output

    def test_rename_missing_args(self):
        result = runner.invoke(app, ["ou", "rename", "--ou", "ou-ab12-34cd5678"])
        assert result.exit_code != 0

    def test_rename_api_error(self):
        from botocore.exceptions import ClientError
        error = ClientError(
            {"Error": {"Code": "OrganizationalUnitNotFoundException", "Message": "OU not found"}},
            "UpdateOrganizationalUnit",
        )
        with patch("standstill.commands.ou.af_api.rename_ou", side_effect=error):
            result = runner.invoke(
                app,
                ["ou", "rename", "--ou", "ou-bad", "--name", "NewName"],
            )
        assert result.exit_code == 1


# ===========================================================================
# ou describe
# ===========================================================================

class TestOUDescribe:
    def test_describe_empty_ou(self):
        with patch(
            "standstill.commands.ou.af_api.describe_ou",
            return_value=_OU_INFO,
        ):
            result = runner.invoke(app, ["ou", "describe", "--ou", "ou-ab12-34cd5678"])
        assert result.exit_code == 0
        assert "ou-ab12-34cd5678" in result.output
        assert "TestOU" in result.output

    def test_describe_with_children_and_accounts(self):
        info = {
            **_OU_INFO,
            "ChildOUs": [
                {"Id": "ou-child-1234", "Arn": "arn:aws:...", "Name": "ChildOU"},
            ],
            "Accounts": [
                {
                    "Id": "123456789012",
                    "Arn": "arn:aws:...",
                    "Name": "TestAccount",
                    "Email": "test@example.com",
                    "Status": "ACTIVE",
                }
            ],
        }
        with patch("standstill.commands.ou.af_api.describe_ou", return_value=info):
            result = runner.invoke(app, ["ou", "describe", "--ou", "ou-ab12-34cd5678"])
        assert result.exit_code == 0
        assert "ChildOU" in result.output
        assert "TestAccount" in result.output

    def test_describe_api_error(self):
        from botocore.exceptions import ClientError
        error = ClientError(
            {"Error": {"Code": "OrganizationalUnitNotFoundException", "Message": "OU not found"}},
            "DescribeOrganizationalUnit",
        )
        with patch("standstill.commands.ou.af_api.describe_ou", side_effect=error):
            result = runner.invoke(app, ["ou", "describe", "--ou", "ou-bad"])
        assert result.exit_code == 1

    def test_describe_missing_arg(self):
        result = runner.invoke(app, ["ou", "describe"])
        assert result.exit_code != 0


# ===========================================================================
# account_factory module unit tests
# ===========================================================================

class TestAccountFactoryUnit:
    def test_move_account_already_in_dest(self):
        from standstill.aws.account_factory import move_account

        mock_org = MagicMock()
        mock_org.list_parents.return_value = {"Parents": [{"Id": "ou-dest-1234", "Type": "ORGANIZATIONAL_UNIT"}]}

        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            import pytest
            with pytest.raises(ValueError, match="already in"):
                move_account("123456789012", "ou-dest-1234")

    def test_move_account_calls_org_api(self):
        from standstill.aws.account_factory import move_account

        mock_org = MagicMock()
        mock_org.list_parents.return_value = {"Parents": [{"Id": "ou-source-0000", "Type": "ORGANIZATIONAL_UNIT"}]}

        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            result = move_account("123456789012", "ou-dest-1234")

        assert result == "ou-source-0000"
        mock_org.move_account.assert_called_once_with(
            AccountId="123456789012",
            SourceParentId="ou-source-0000",
            DestinationParentId="ou-dest-1234",
        )

    def test_describe_account_adds_parent(self):
        from standstill.aws.account_factory import describe_account

        mock_org = MagicMock()
        mock_org.describe_account.return_value = {
            "Account": {"Id": "123456789012", "Name": "Test", "Status": "ACTIVE"}
        }
        mock_org.list_parents.return_value = {"Parents": [{"Id": "ou-ab12-34cd5678"}]}

        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            info = describe_account("123456789012")

        assert info["ParentId"] == "ou-ab12-34cd5678"

    def test_get_org_root_id(self):
        from standstill.aws.account_factory import get_org_root_id

        mock_org = MagicMock()
        mock_org.list_roots.return_value = {"Roots": [{"Id": "r-ab12", "Arn": "arn:aws:...", "Name": "Root"}]}

        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            root_id = get_org_root_id()

        assert root_id == "r-ab12"

    def test_describe_ou_populates_children(self):
        from standstill.aws.account_factory import describe_ou

        mock_org = MagicMock()
        mock_org.describe_organizational_unit.return_value = {
            "OrganizationalUnit": {"Id": "ou-ab12-34cd5678", "Arn": "arn:aws:...", "Name": "TestOU"}
        }
        mock_org.list_parents.return_value = {"Parents": [{"Id": "r-ab12"}]}
        mock_org.list_organizational_units_for_parent.return_value = {
            "OrganizationalUnits": [{"Id": "ou-child-1111", "Arn": "arn:aws:...", "Name": "Child"}]
        }
        mock_org.list_accounts_for_parent.return_value = {"Accounts": []}

        with patch("standstill.aws.account_factory._state.state.get_client", return_value=mock_org):
            info = describe_ou("ou-ab12-34cd5678")

        assert info["ParentId"] == "r-ab12"
        assert len(info["ChildOUs"]) == 1
        assert info["ChildOUs"][0]["Id"] == "ou-child-1111"


# ===========================================================================
# accounts set-profile
# ===========================================================================

class TestSetProfile:
    _CREDS = {
        "AccessKeyId":     "ASIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "SessionToken":    "AQoXnyc4lcK4w",
        "Expiration":      "2099-01-01T00:00:00Z",
    }

    def _mock_state(self, mock_state, account_id="123456789012"):
        sts_mock = MagicMock()
        sts_mock.assume_role.return_value = {"Credentials": self._CREDS}
        mock_state.state.get_client.return_value = sts_mock
        mock_state.state.region = "us-east-1"

    def test_set_profile_by_account_id(self, tmp_path):
        with (
            patch("standstill.commands.accounts._state") as mock_state,
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            self._mock_state(mock_state)
            result = runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "123456789012",
                 "--profile", "staging"],
            )

        assert result.exit_code == 0, result.output
        assert "ss-staging" in result.output

    def test_credentials_file_written(self, tmp_path):
        import configparser

        with (
            patch("standstill.commands.accounts._state") as mock_state,
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            self._mock_state(mock_state)
            runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "123456789012",
                 "--profile", "staging"],
            )

        creds_path = tmp_path / ".aws" / "credentials"
        assert creds_path.exists()
        cfg = configparser.RawConfigParser()
        cfg.read(creds_path)
        assert cfg.has_section("ss-staging")
        assert cfg.get("ss-staging", "aws_access_key_id") == self._CREDS["AccessKeyId"]
        assert cfg.get("ss-staging", "aws_session_token") == self._CREDS["SessionToken"]

    def test_config_file_written(self, tmp_path):
        import configparser

        with (
            patch("standstill.commands.accounts._state") as mock_state,
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            self._mock_state(mock_state)
            runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "123456789012",
                 "--profile", "staging",
                 "--region", "eu-west-1"],
            )

        cfg_path = tmp_path / ".aws" / "config"
        assert cfg_path.exists()
        cfg = configparser.RawConfigParser()
        cfg.read(cfg_path)
        assert cfg.has_section("profile ss-staging")
        assert cfg.get("profile ss-staging", "region") == "eu-west-1"

    def test_set_profile_by_account_name(self, tmp_path):
        from standstill.aws.organizations import Account

        fake_account = Account(
            id="111222333444",
            arn="arn:aws:organizations::000000000000:account/o-xxx/111222333444",
            name="Production",
            email="prod@example.com",
            status="ACTIVE",
            ou_id="ou-root-1234",
            ou_name="Root",
        )

        with (
            patch("standstill.commands.accounts._state") as mock_state,
            patch("standstill.commands.accounts.org_api.build_ou_tree", return_value=[]),
            patch("standstill.commands.accounts.org_api.all_accounts",
                  return_value=[fake_account]),
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            self._mock_state(mock_state, "111222333444")
            result = runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "Production",
                 "--profile", "prod"],
            )

        assert result.exit_code == 0, result.output
        assert "ss-prod" in result.output

    def test_unresolvable_account_exits_1(self, tmp_path):
        with (
            patch("standstill.commands.accounts._state"),
            patch("standstill.commands.accounts.org_api.build_ou_tree", return_value=[]),
            patch("standstill.commands.accounts.org_api.all_accounts", return_value=[]),
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            result = runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "NonExistentAccount",
                 "--profile", "test"],
            )

        assert result.exit_code == 1

    def test_assume_role_failure_exits_1(self, tmp_path):
        from botocore.exceptions import ClientError

        error = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Not authorized"}},
            "AssumeRole",
        )
        with (
            patch("standstill.commands.accounts._state") as mock_state,
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            sts_mock = MagicMock()
            sts_mock.assume_role.side_effect = error
            mock_state.state.get_client.return_value = sts_mock
            mock_state.state.region = "us-east-1"
            result = runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "123456789012",
                 "--profile", "test"],
            )

        assert result.exit_code == 1
        assert "Not authorized" in result.output

    def test_existing_profile_is_overwritten(self, tmp_path):
        import configparser

        # Pre-populate the credentials file with an existing profile
        aws_dir = tmp_path / ".aws"
        aws_dir.mkdir(parents=True)
        existing = configparser.RawConfigParser()
        existing.add_section("ss-staging")
        existing.set("ss-staging", "aws_access_key_id", "OLD_KEY")
        with (aws_dir / "credentials").open("w") as fh:
            existing.write(fh)

        with (
            patch("standstill.commands.accounts._state") as mock_state,
            patch("standstill.commands.accounts.Path.home", return_value=tmp_path),
        ):
            self._mock_state(mock_state)
            result = runner.invoke(
                app,
                ["accounts", "set-profile",
                 "--account", "123456789012",
                 "--profile", "staging"],
            )

        assert result.exit_code == 0
        assert "updated existing" in result.output

        cfg = configparser.RawConfigParser()
        cfg.read(aws_dir / "credentials")
        assert cfg.get("ss-staging", "aws_access_key_id") == self._CREDS["AccessKeyId"]

    def test_missing_required_args(self):
        result = runner.invoke(app, ["accounts", "set-profile"])
        assert result.exit_code != 0
