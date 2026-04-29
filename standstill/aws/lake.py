"""AWS operations for Security Lake — Athena output setup and OCSF view management."""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import ClientError

from standstill import state as _state

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Maps Security Lake source key → Glue table suffix (OCSF 2.0)
SOURCE_TABLE_SUFFIXES: dict[str, str] = {
    "cloud_trail_mgmt": "cloud_trail_mgmt_2_0",
    "vpc_flow":         "vpc_flow_2_0",
    "route53":          "route_53_2_0",
    "sh_findings":      "sh_findings_2_0",
    "eks_audit":        "eks_audit_2_0",
    "lambda_execution": "lambda_execution_2_0",
    "s3_data":          "s3_data_2_0",
    "wafv2":            "wafv2_2_0",
}

SOURCE_VIEW_NAMES: dict[str, str] = {
    "cloud_trail_mgmt": "cloudtrail",
    "vpc_flow":         "vpc_flow",
    "route53":          "route53",
    "sh_findings":      "sh_findings",
    "eks_audit":        "eks_audit",
    "lambda_execution": "lambda_exec",
    "s3_data":          "s3_data",
    "wafv2":            "wafv2",
}

SOURCE_LABELS: dict[str, str] = {
    "cloud_trail_mgmt": "CloudTrail Mgmt Events",
    "vpc_flow":         "VPC Flow Logs",
    "route53":          "Route 53 Query Logs",
    "sh_findings":      "Security Hub Findings",
    "eks_audit":        "EKS Audit Logs",
    "lambda_execution": "Lambda Execution",
    "s3_data":          "S3 Data Events",
    "wafv2":            "WAF v2 Logs",
}

DEFAULT_VIEWS_DATABASE = "standstill_security_lake"
DEFAULT_WORKGROUP     = "primary"
DEFAULT_OUTPUT_PREFIX = "athena-results/"


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------

@dataclass
class LakeTable:
    source: str
    table_name: str
    database: str
    region: str


@dataclass
class ViewResult:
    source: str
    view_name: str
    success: bool
    message: str
    query_id: str = ""


@dataclass
class WorkgroupInfo:
    name: str
    output_location: str | None
    state: str
    enforce_config: bool
    error: str = ""


# ---------------------------------------------------------------------------
# Session helper
# ---------------------------------------------------------------------------

def _admin_client(service: str, admin_account: str, role_name: str, region: str):
    """Assume the CT execution role in the admin account and return a boto3 client."""
    role_arn = f"arn:aws:iam::{admin_account}:role/{role_name}"
    sts = _state.state.get_client("sts")
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=f"standstill-lake-{os.getpid()}")
    except ClientError as exc:
        raise RuntimeError(
            f"Cannot assume {role_arn}: {exc.response['Error']['Message']}"
        ) from exc
    creds = resp["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    return session.client(service, region_name=region)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _region_to_suffix(region: str) -> str:
    return region.replace("-", "_")


def _wait_for_query(athena, query_execution_id: str, max_seconds: int = 60) -> tuple[str, str]:
    """Poll until Athena query completes. Returns (state, reason)."""
    for _ in range(max_seconds):
        resp = athena.get_query_execution(QueryExecutionId=query_execution_id)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            reason = resp["QueryExecution"]["Status"].get("StateChangeReason", "")
            return state, reason
        time.sleep(1)
    return "TIMEOUT", "Query did not complete within the wait period."


# ---------------------------------------------------------------------------
# Athena workgroup
# ---------------------------------------------------------------------------

def get_workgroup(
    workgroup: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> WorkgroupInfo:
    """Return the current configuration of an Athena workgroup."""
    try:
        athena = _admin_client("athena", admin_account, role_name, region)
        resp = athena.get_work_group(WorkGroup=workgroup)
        wg = resp["WorkGroup"]
        cfg = wg.get("Configuration", {})
        result_cfg = cfg.get("ResultConfiguration", {})
        return WorkgroupInfo(
            name=wg["Name"],
            output_location=result_cfg.get("OutputLocation"),
            state=wg.get("State", "UNKNOWN"),
            enforce_config=cfg.get("EnforceWorkgroupConfiguration", False),
        )
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "InvalidRequestException" and "does not exist" in exc.response["Error"]["Message"]:
            return WorkgroupInfo(
                name=workgroup, output_location=None,
                state="NOT_FOUND", enforce_config=False,
            )
        return WorkgroupInfo(
            name=workgroup, output_location=None,
            state="ERROR", enforce_config=False,
            error=exc.response["Error"]["Message"],
        )


def set_workgroup_output(
    workgroup: str,
    output_location: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> None:
    """Set (or create) an Athena workgroup with the given S3 output location."""
    athena = _admin_client("athena", admin_account, role_name, region)
    try:
        athena.update_work_group(
            WorkGroup=workgroup,
            ConfigurationUpdates={
                "ResultConfigurationUpdates": {"OutputLocation": output_location},
                "EnforceWorkgroupConfiguration": True,
            },
        )
    except ClientError as exc:
        msg = exc.response["Error"]["Message"]
        if "does not exist" in msg:
            athena.create_work_group(
                Name=workgroup,
                Configuration={
                    "ResultConfiguration": {"OutputLocation": output_location},
                    "EnforceWorkgroupConfiguration": True,
                },
                Description="Created by standstill lake setup-athena.",
            )
        else:
            raise


# ---------------------------------------------------------------------------
# S3 bucket
# ---------------------------------------------------------------------------

def bucket_exists(bucket_name: str, admin_account: str, role_name: str, region: str) -> bool:
    s3 = _admin_client("s3", admin_account, role_name, region)
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError:
        return False


def create_results_bucket(
    bucket_name: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> None:
    """Create an S3 bucket for Athena results with public access blocked."""
    s3 = _admin_client("s3", admin_account, role_name, region)
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": region},
        )
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )


# ---------------------------------------------------------------------------
# Security Lake table discovery
# ---------------------------------------------------------------------------

def detect_lake_tables(
    admin_account: str,
    role_name: str,
    region: str,
) -> list[LakeTable]:
    """Find existing Security Lake OCSF tables in the Glue catalog."""
    db_name = f"amazon_security_lake_glue_db_{_region_to_suffix(region)}"
    glue = _admin_client("glue", admin_account, role_name, region)

    try:
        glue.get_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFoundException":
            return []
        raise

    tables: list[LakeTable] = []
    paginator = glue.get_paginator("get_tables")
    for page in paginator.paginate(DatabaseName=db_name):
        for t in page["TableList"]:
            tname = t["Name"]
            for source, suffix in SOURCE_TABLE_SUFFIXES.items():
                expected = (
                    f"amazon_security_lake_table_{_region_to_suffix(region)}_{suffix}"
                )
                if tname == expected:
                    tables.append(LakeTable(
                        source=source,
                        table_name=tname,
                        database=db_name,
                        region=region,
                    ))
                    break
    return tables


# ---------------------------------------------------------------------------
# Glue database for views
# ---------------------------------------------------------------------------

def ensure_views_database(
    database: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> bool:
    """Create the Glue database for standstill views if it does not exist.

    Returns True when the database was newly created.
    """
    glue = _admin_client("glue", admin_account, role_name, region)
    try:
        glue.get_database(Name=database)
        return False
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise
    glue.create_database(DatabaseInput={
        "Name": database,
        "Description": "Standstill — flattened OCSF views over AWS Security Lake.",
    })
    return True


def list_views(
    database: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> list[str]:
    """List view names inside a Glue database."""
    glue = _admin_client("glue", admin_account, role_name, region)
    try:
        views: list[str] = []
        paginator = glue.get_paginator("get_tables")
        for page in paginator.paginate(DatabaseName=database):
            for t in page["TableList"]:
                if t.get("TableType") == "VIRTUAL_VIEW":
                    views.append(t["Name"])
        return views
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityNotFoundException":
            return []
        raise


# ---------------------------------------------------------------------------
# View creation
# ---------------------------------------------------------------------------

def build_view_sql(
    source: str,
    sl_database: str,
    sl_table: str,
    view_database: str,
) -> str:
    """Return the CREATE OR REPLACE VIEW DDL for the given Security Lake source."""
    view_name = SOURCE_VIEW_NAMES.get(source, source)
    builders = {
        "cloud_trail_mgmt": _cloudtrail_sql,
        "vpc_flow":         _vpc_flow_sql,
        "route53":          _route53_sql,
        "sh_findings":      _sh_findings_sql,
        "eks_audit":        _eks_audit_sql,
        "lambda_execution": _lambda_exec_sql,
        "s3_data":          _s3_data_sql,
        "wafv2":            _wafv2_sql,
    }
    builder = builders.get(source)
    if builder is None:
        raise ValueError(f"No view definition for source: {source!r}")
    return builder(view_database, view_name, sl_database, sl_table)


def create_view(
    lake_table: LakeTable,
    view_database: str,
    output_location: str,
    workgroup: str,
    admin_account: str,
    role_name: str,
    region: str,
) -> ViewResult:
    """Execute the CREATE OR REPLACE VIEW DDL via Athena and wait for the result."""
    source = lake_table.source
    view_name = SOURCE_VIEW_NAMES.get(source, source)
    try:
        sql = build_view_sql(source, lake_table.database, lake_table.table_name, view_database)
        athena = _admin_client("athena", admin_account, role_name, region)
        resp = athena.start_query_execution(
            QueryString=sql,
            QueryExecutionContext={"Database": view_database},
            ResultConfiguration={"OutputLocation": output_location},
            WorkGroup=workgroup,
        )
        qid = resp["QueryExecutionId"]
        state, reason = _wait_for_query(athena, qid)
        if state == "SUCCEEDED":
            return ViewResult(source=source, view_name=view_name,
                              success=True, message="Created.", query_id=qid)
        return ViewResult(source=source, view_name=view_name,
                          success=False, message=reason or state, query_id=qid)
    except (ClientError, RuntimeError, ValueError) as exc:
        return ViewResult(source=source, view_name=view_name,
                          success=False, message=str(exc))


# ---------------------------------------------------------------------------
# View SQL — one function per OCSF source
# ---------------------------------------------------------------------------

def _cloudtrail_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  api.operation                                                   AS api_call,
  api.service.name                                                AS service,
  actor.user.name                                                 AS user_name,
  actor.user.uid                                                  AS user_arn,
  actor.user.type                                                 AS user_type,
  actor.user.credential_uid                                       AS access_key,
  actor.user.account.uid                                          AS user_account_id,
  actor.session.issuer                                            AS assumed_role,
  actor.session.mfa                                               AS mfa_used,
  actor.invoked_by                                                AS invoked_by,
  src_endpoint.ip                                                 AS source_ip,
  src_endpoint.domain                                             AS source_domain,
  http_request.user_agent                                         AS user_agent,
  api.request.uid                                                 AS request_id,
  api.response.error                                              AS error_code,
  api.response.message                                            AS error_message,
  status,
  severity,
  array_join(
    transform(resources, r -> concat(coalesce(r.type,''), ':', coalesce(r.uid,''))),
    ' | '
  )                                                               AS resources,
  metadata.uid                                                    AS event_id,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _vpc_flow_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  from_unixtime(start_time / 1000)                               AS flow_start,
  from_unixtime(end_time / 1000)                                 AS flow_end,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  src_endpoint.ip                                                 AS src_ip,
  src_endpoint.port                                               AS src_port,
  src_endpoint.interface_uid                                      AS src_eni,
  src_endpoint.vpc_uid                                            AS src_vpc,
  dst_endpoint.ip                                                 AS dst_ip,
  dst_endpoint.port                                               AS dst_port,
  dst_endpoint.interface_uid                                      AS dst_eni,
  dst_endpoint.vpc_uid                                            AS dst_vpc,
  connection_info.protocol_name                                   AS protocol,
  connection_info.direction                                       AS direction,
  traffic.bytes                                                   AS bytes,
  traffic.packets                                                 AS packets,
  disposition                                                     AS action,
  status,
  severity,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _route53_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  query.hostname                                                  AS query_name,
  query.type                                                      AS query_type,
  rcode                                                           AS response_code,
  array_join(
    transform(answers, a -> concat(coalesce(a.type,''), ' ', coalesce(a.rdata,''))),
    ' | '
  )                                                               AS answers,
  src_endpoint.ip                                                 AS source_ip,
  src_endpoint.vpc_uid                                            AS vpc_id,
  src_endpoint.instance_uid                                       AS instance_id,
  activity_name,
  severity,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _sh_findings_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  finding.uid                                                     AS finding_id,
  finding.title                                                   AS title,
  finding.desc                                                    AS description,
  severity,
  severity_id,
  status,
  compliance.status                                               AS compliance_status,
  compliance.status_detail                                        AS compliance_detail,
  array_join(compliance.requirements, ', ')                       AS compliance_frameworks,
  finding.remediation.desc                                        AS remediation,
  array_join(finding.types, ' | ')                               AS finding_types,
  array_join(
    transform(resources, r -> concat(coalesce(r.type,''), ':', coalesce(r.uid,''))),
    ' | '
  )                                                               AS affected_resources,
  from_unixtime(finding.first_seen_time / 1000)                  AS first_seen,
  from_unixtime(finding.last_seen_time / 1000)                   AS last_seen,
  metadata.product.name                                           AS product,
  metadata.product.vendor_name                                    AS vendor,
  metadata.uid                                                    AS finding_uid,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _eks_audit_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  api.operation                                                   AS api_call,
  api.group.name                                                  AS api_group,
  api.version                                                     AS api_version,
  actor.user.name                                                 AS user_name,
  actor.user.uid                                                  AS user_arn,
  actor.user.type                                                 AS user_type,
  array_join(
    transform(actor.user.groups, g -> g.name),
    ', '
  )                                                               AS user_groups,
  src_endpoint.ip                                                 AS source_ip,
  http_request.user_agent                                         AS user_agent,
  api.response.error                                              AS error_code,
  api.response.message                                            AS error_message,
  status,
  severity,
  activity_name,
  metadata.uid                                                    AS event_id,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _lambda_exec_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  api.operation                                                   AS api_call,
  api.service.name                                                AS service,
  actor.user.name                                                 AS user_name,
  actor.user.uid                                                  AS user_arn,
  actor.user.type                                                 AS user_type,
  src_endpoint.ip                                                 AS source_ip,
  http_request.user_agent                                         AS user_agent,
  api.response.error                                              AS error_code,
  status,
  severity,
  activity_name,
  metadata.uid                                                    AS event_id,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _s3_data_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  api.operation                                                   AS api_call,
  actor.user.name                                                 AS user_name,
  actor.user.uid                                                  AS user_arn,
  actor.user.type                                                 AS user_type,
  actor.user.credential_uid                                       AS access_key,
  src_endpoint.ip                                                 AS source_ip,
  http_request.user_agent                                         AS user_agent,
  array_join(
    transform(resources, r -> concat(coalesce(r.type,''), ':', coalesce(r.uid,''))),
    ' | '
  )                                                               AS resources,
  api.response.error                                              AS error_code,
  status,
  severity,
  metadata.uid                                                    AS event_id,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""


def _wafv2_sql(view_db: str, view_name: str, sl_db: str, sl_table: str) -> str:
    return f"""\
CREATE OR REPLACE VIEW {view_db}.{view_name} AS
SELECT
  from_unixtime(time / 1000)                                     AS event_time,
  cloud.account.uid                                               AS account_id,
  cloud.region                                                    AS region,
  src_endpoint.ip                                                 AS source_ip,
  src_endpoint.domain                                             AS source_domain,
  http_request.user_agent                                         AS user_agent,
  http_request.url.path                                           AS url_path,
  http_request.url.hostname                                       AS url_host,
  http_request.http_method                                        AS http_method,
  http_request.version                                            AS http_version,
  disposition                                                     AS action,
  activity_name,
  severity,
  status,
  metadata.uid                                                    AS event_id,
  accountid                                                       AS partition_account,
  eventday                                                        AS event_day,
  time                                                            AS epoch_ms
FROM {sl_db}.{sl_table}"""
