"""Tests for standstill/aws/lake.py and standstill/commands/lake.py"""
from __future__ import annotations

from unittest.mock import MagicMock, call, patch

import pytest
from botocore.exceptions import ClientError
from typer.testing import CliRunner

import standstill.aws.lake as lake
from standstill.main import app

runner = CliRunner()


def _client_error(code: str, message: str = "Some error") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "Op")


# ---------------------------------------------------------------------------
# Helpers / fixtures
# ---------------------------------------------------------------------------

def _mock_sts(admin_account: str = "123456789012"):
    sts = MagicMock()
    sts.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "AK",
            "SecretAccessKey": "SK",
            "SessionToken": "ST",
        }
    }
    return sts


# ---------------------------------------------------------------------------
# build_view_sql
# ---------------------------------------------------------------------------

class TestBuildViewSql:
    def _sql(self, source: str) -> str:
        return lake.build_view_sql(
            source,
            sl_database="sl_db",
            sl_table="sl_table",
            view_database="view_db",
        )

    def test_cloudtrail_contains_key_columns(self):
        sql = self._sql("cloud_trail_mgmt")
        assert "api_call" in sql
        assert "user_name" in sql
        assert "user_arn" in sql
        assert "source_ip" in sql
        assert "user_agent" in sql
        assert "error_code" in sql
        assert "assumed_role" in sql
        assert "access_key" in sql
        assert "event_time" in sql
        assert "from_unixtime" in sql

    def test_cloudtrail_references_correct_table(self):
        sql = self._sql("cloud_trail_mgmt")
        assert "sl_db.sl_table" in sql
        assert "view_db.cloudtrail" in sql

    def test_vpc_flow_contains_network_columns(self):
        sql = self._sql("vpc_flow")
        assert "src_ip" in sql
        assert "dst_ip" in sql
        assert "src_port" in sql
        assert "dst_port" in sql
        assert "protocol" in sql
        assert "bytes" in sql
        assert "packets" in sql
        assert "action" in sql

    def test_route53_contains_dns_columns(self):
        sql = self._sql("route53")
        assert "query_name" in sql
        assert "query_type" in sql
        assert "response_code" in sql
        assert "answers" in sql
        assert "source_ip" in sql
        assert "vpc_id" in sql

    def test_sh_findings_contains_finding_columns(self):
        sql = self._sql("sh_findings")
        assert "finding_id" in sql
        assert "title" in sql
        assert "severity" in sql
        assert "compliance_status" in sql
        assert "affected_resources" in sql
        assert "first_seen" in sql
        assert "remediation" in sql

    def test_eks_audit_contains_k8s_columns(self):
        sql = self._sql("eks_audit")
        assert "api_call" in sql
        assert "api_group" in sql
        assert "user_groups" in sql
        assert "source_ip" in sql

    def test_all_views_are_create_or_replace(self):
        for source in lake.SOURCE_TABLE_SUFFIXES:
            sql = self._sql(source)
            assert sql.strip().upper().startswith("CREATE OR REPLACE VIEW"), source

    def test_unknown_source_raises(self):
        with pytest.raises(ValueError, match="No view definition"):
            lake.build_view_sql("unknown_source", "db", "tbl", "vdb")

    def test_all_views_include_epoch_ms(self):
        for source in lake.SOURCE_TABLE_SUFFIXES:
            sql = self._sql(source)
            assert "epoch_ms" in sql, f"{source} missing epoch_ms"

    def test_all_views_include_partition_columns(self):
        for source in lake.SOURCE_TABLE_SUFFIXES:
            sql = self._sql(source)
            assert "partition_account" in sql, f"{source} missing partition_account"
            assert "event_day" in sql, f"{source} missing event_day"


# ---------------------------------------------------------------------------
# detect_lake_tables
# ---------------------------------------------------------------------------

class TestDetectLakeTables:
    def _make_glue(self, tables: list[str], db_exists: bool = True):
        glue = MagicMock()
        if not db_exists:
            glue.get_database.side_effect = _client_error("EntityNotFoundException")
        else:
            glue.get_database.return_value = {"Database": {"Name": "test_db"}}
            paginator = MagicMock()
            paginator.paginate.return_value = [
                {"TableList": [{"Name": t} for t in tables]}
            ]
            glue.get_paginator.return_value = paginator
        return glue

    def test_returns_empty_when_no_database(self):
        glue = self._make_glue([], db_exists=False)
        with patch.object(lake, "_admin_client", return_value=glue):
            result = lake.detect_lake_tables("123456789012", "Role", "us-east-1")
        assert result == []

    def test_detects_cloudtrail_table(self):
        tbl = "amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0"
        glue = self._make_glue([tbl])
        with patch.object(lake, "_admin_client", return_value=glue):
            result = lake.detect_lake_tables("123456789012", "Role", "us-east-1")
        assert len(result) == 1
        assert result[0].source == "cloud_trail_mgmt"
        assert result[0].table_name == tbl

    def test_detects_multiple_tables(self):
        tables = [
            "amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0",
            "amazon_security_lake_table_us_east_1_vpc_flow_2_0",
            "amazon_security_lake_table_us_east_1_route_53_2_0",
        ]
        glue = self._make_glue(tables)
        with patch.object(lake, "_admin_client", return_value=glue):
            result = lake.detect_lake_tables("123456789012", "Role", "us-east-1")
        assert len(result) == 3
        sources = {r.source for r in result}
        assert sources == {"cloud_trail_mgmt", "vpc_flow", "route53"}

    def test_ignores_unknown_tables(self):
        tables = [
            "amazon_security_lake_table_us_east_1_cloud_trail_mgmt_2_0",
            "some_unrelated_table",
        ]
        glue = self._make_glue(tables)
        with patch.object(lake, "_admin_client", return_value=glue):
            result = lake.detect_lake_tables("123456789012", "Role", "us-east-1")
        assert len(result) == 1

    def test_region_suffix_applied_correctly(self):
        tbl = "amazon_security_lake_table_eu_west_1_vpc_flow_2_0"
        glue = self._make_glue([tbl])
        with patch.object(lake, "_admin_client", return_value=glue):
            result = lake.detect_lake_tables("123456789012", "Role", "eu-west-1")
        assert len(result) == 1
        assert result[0].source == "vpc_flow"


# ---------------------------------------------------------------------------
# get_workgroup
# ---------------------------------------------------------------------------

class TestGetWorkgroup:
    def test_returns_output_location(self):
        athena = MagicMock()
        athena.get_work_group.return_value = {
            "WorkGroup": {
                "Name": "primary",
                "State": "ENABLED",
                "Configuration": {
                    "ResultConfiguration": {"OutputLocation": "s3://my-bucket/prefix/"},
                    "EnforceWorkgroupConfiguration": True,
                },
            }
        }
        with patch.object(lake, "_admin_client", return_value=athena):
            info = lake.get_workgroup("primary", "123456789012", "Role", "us-east-1")
        assert info.output_location == "s3://my-bucket/prefix/"
        assert info.state == "ENABLED"
        assert info.enforce_config is True

    def test_returns_not_found_when_missing(self):
        athena = MagicMock()
        athena.get_work_group.side_effect = _client_error(
            "InvalidRequestException", "workgroup does not exist"
        )
        with patch.object(lake, "_admin_client", return_value=athena):
            info = lake.get_workgroup("missing", "123456789012", "Role", "us-east-1")
        assert info.state == "NOT_FOUND"
        assert info.output_location is None

    def test_returns_error_on_other_exceptions(self):
        athena = MagicMock()
        athena.get_work_group.side_effect = _client_error("AccessDeniedException")
        with patch.object(lake, "_admin_client", return_value=athena):
            info = lake.get_workgroup("primary", "123456789012", "Role", "us-east-1")
        assert info.state == "ERROR"
        assert info.error != ""


# ---------------------------------------------------------------------------
# set_workgroup_output
# ---------------------------------------------------------------------------

class TestSetWorkgroupOutput:
    def test_updates_existing_workgroup(self):
        athena = MagicMock()
        with patch.object(lake, "_admin_client", return_value=athena):
            lake.set_workgroup_output(
                "primary", "s3://bucket/prefix/", "123456789012", "Role", "us-east-1"
            )
        athena.update_work_group.assert_called_once()

    def test_creates_workgroup_when_not_found(self):
        athena = MagicMock()
        athena.update_work_group.side_effect = _client_error(
            "InvalidRequestException", "workgroup does not exist"
        )
        with patch.object(lake, "_admin_client", return_value=athena):
            lake.set_workgroup_output(
                "new-wg", "s3://bucket/prefix/", "123456789012", "Role", "us-east-1"
            )
        athena.create_work_group.assert_called_once()


# ---------------------------------------------------------------------------
# ensure_views_database
# ---------------------------------------------------------------------------

class TestEnsureViewsDatabase:
    def test_returns_false_when_already_exists(self):
        glue = MagicMock()
        glue.get_database.return_value = {"Database": {"Name": "existing_db"}}
        with patch.object(lake, "_admin_client", return_value=glue):
            created = lake.ensure_views_database("existing_db", "123456789012", "Role", "us-east-1")
        assert created is False
        glue.create_database.assert_not_called()

    def test_creates_and_returns_true_when_missing(self):
        glue = MagicMock()
        glue.get_database.side_effect = _client_error("EntityNotFoundException")
        with patch.object(lake, "_admin_client", return_value=glue):
            created = lake.ensure_views_database("new_db", "123456789012", "Role", "us-east-1")
        assert created is True
        glue.create_database.assert_called_once()
        call_kwargs = glue.create_database.call_args[1]
        assert call_kwargs["DatabaseInput"]["Name"] == "new_db"


# ---------------------------------------------------------------------------
# create_view
# ---------------------------------------------------------------------------

class TestCreateView:
    def _mock_athena(self, state: str = "SUCCEEDED", reason: str = "") -> MagicMock:
        athena = MagicMock()
        athena.start_query_execution.return_value = {"QueryExecutionId": "qid-123"}
        athena.get_query_execution.return_value = {
            "QueryExecution": {
                "Status": {"State": state, "StateChangeReason": reason}
            }
        }
        return athena

    def _table(self, source: str = "cloud_trail_mgmt") -> lake.LakeTable:
        return lake.LakeTable(
            source=source,
            table_name=f"amazon_security_lake_table_us_east_1_{lake.SOURCE_TABLE_SUFFIXES[source]}",
            database="amazon_security_lake_glue_db_us_east_1",
            region="us-east-1",
        )

    def test_success(self):
        athena = self._mock_athena("SUCCEEDED")
        with patch.object(lake, "_admin_client", return_value=athena):
            result = lake.create_view(
                self._table(), "view_db", "s3://bucket/prefix/",
                "primary", "123456789012", "Role", "us-east-1",
            )
        assert result.success
        assert result.view_name == "cloudtrail"
        assert result.query_id == "qid-123"

    def test_failure(self):
        athena = self._mock_athena("FAILED", "Syntax error")
        with patch.object(lake, "_admin_client", return_value=athena):
            result = lake.create_view(
                self._table(), "view_db", "s3://bucket/prefix/",
                "primary", "123456789012", "Role", "us-east-1",
            )
        assert not result.success
        assert "Syntax error" in result.message

    def test_runtime_error(self):
        with patch.object(lake, "_admin_client", side_effect=RuntimeError("no creds")):
            result = lake.create_view(
                self._table(), "view_db", "s3://bucket/prefix/",
                "primary", "123456789012", "Role", "us-east-1",
            )
        assert not result.success
        assert "no creds" in result.message

    def test_all_sources_produce_valid_ddl(self):
        """Every known source should be executable without ValueError."""
        athena = self._mock_athena("SUCCEEDED")
        for source in lake.SOURCE_TABLE_SUFFIXES:
            with patch.object(lake, "_admin_client", return_value=athena):
                result = lake.create_view(
                    lake.LakeTable(
                        source=source,
                        table_name=f"sl_table_{source}",
                        database="sl_db",
                        region="us-east-1",
                    ),
                    "view_db", "s3://bucket/prefix/",
                    "primary", "123456789012", "Role", "us-east-1",
                )
            # should not raise; success depends on mocked Athena
            assert result.source == source


# ---------------------------------------------------------------------------
# CLI — lake status
# ---------------------------------------------------------------------------

class TestLakeStatusCommand:
    def _mock_wg(self, output: str | None = "s3://my-bucket/prefix/") -> lake.WorkgroupInfo:
        return lake.WorkgroupInfo(
            name="primary",
            output_location=output,
            state="ENABLED",
            enforce_config=True,
        )

    def test_status_exits_ok(self):
        wg = self._mock_wg()
        tables = [lake.LakeTable("cloud_trail_mgmt", "tbl_ct", "sl_db", "us-east-1")]
        views = ["cloudtrail"]
        with (
            patch("standstill.commands.lake.lake_api.get_workgroup", return_value=wg),
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=tables),
            patch("standstill.commands.lake.lake_api.list_views", return_value=views),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, ["lake", "status", "--account", "123456789012"])
        assert result.exit_code == 0

    def test_status_no_account_exits_1(self):
        with patch("standstill.commands.lake._config.get_delegated_admin", return_value=None):
            result = runner.invoke(app, ["lake", "status"])
        assert result.exit_code == 1


# ---------------------------------------------------------------------------
# CLI — lake create-views
# ---------------------------------------------------------------------------

class TestLakeCreateViewsCommand:
    def _wg(self, output: str = "s3://bucket/prefix/") -> lake.WorkgroupInfo:
        return lake.WorkgroupInfo(
            name="primary", output_location=output,
            state="ENABLED", enforce_config=True,
        )

    def _table(self, source: str) -> lake.LakeTable:
        return lake.LakeTable(source=source, table_name=f"tbl_{source}", database="sl_db", region="us-east-1")

    def test_dry_run_prints_sql_and_exits_ok(self):
        tables = [self._table("cloud_trail_mgmt"), self._table("vpc_flow")]
        with (
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=tables),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, [
                "lake", "create-views",
                "--account", "123456789012",
                "--dry-run",
            ])
        assert result.exit_code == 0
        assert "CREATE OR REPLACE VIEW" in result.output
        assert "Dry run" in result.output

    def test_no_tables_found_exits_1(self):
        with (
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=[]),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, [
                "lake", "create-views",
                "--account", "123456789012",
            ])
        assert result.exit_code == 1

    def test_no_workgroup_output_exits_1(self):
        tables = [self._table("cloud_trail_mgmt")]
        wg_no_output = lake.WorkgroupInfo("primary", None, "ENABLED", False)
        with (
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=tables),
            patch("standstill.commands.lake.lake_api.get_workgroup", return_value=wg_no_output),
            patch("standstill.commands.lake.lake_api.ensure_views_database", return_value=False),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, [
                "lake", "create-views",
                "--account", "123456789012",
            ])
        assert result.exit_code == 1
        assert "setup-athena" in result.output

    def test_unknown_source_filter_exits_1(self):
        tables = [self._table("cloud_trail_mgmt")]
        with (
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=tables),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, [
                "lake", "create-views",
                "--account", "123456789012",
                "--sources", "totally_fake_source",
            ])
        assert result.exit_code == 1

    def test_successful_view_creation(self):
        tables = [self._table("cloud_trail_mgmt"), self._table("vpc_flow")]
        ok_result = lake.ViewResult("cloud_trail_mgmt", "cloudtrail", True, "Created.")
        ok_result2 = lake.ViewResult("vpc_flow", "vpc_flow", True, "Created.")
        with (
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=tables),
            patch("standstill.commands.lake.lake_api.get_workgroup", return_value=self._wg()),
            patch("standstill.commands.lake.lake_api.ensure_views_database", return_value=True),
            patch("standstill.commands.lake.lake_api.create_view", side_effect=[ok_result, ok_result2]),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, [
                "lake", "create-views",
                "--account", "123456789012",
            ])
        assert result.exit_code == 0

    def test_partial_failure_exits_1(self):
        tables = [self._table("cloud_trail_mgmt")]
        fail_result = lake.ViewResult("cloud_trail_mgmt", "cloudtrail", False, "FAILED")
        with (
            patch("standstill.commands.lake.lake_api.detect_lake_tables", return_value=tables),
            patch("standstill.commands.lake.lake_api.get_workgroup", return_value=self._wg()),
            patch("standstill.commands.lake.lake_api.ensure_views_database", return_value=False),
            patch("standstill.commands.lake.lake_api.create_view", return_value=fail_result),
            patch("standstill.commands.lake._config.get_delegated_admin", return_value="123456789012"),
        ):
            result = runner.invoke(app, [
                "lake", "create-views",
                "--account", "123456789012",
            ])
        assert result.exit_code == 1
