from __future__ import annotations

import re
from dataclasses import dataclass, field

# Region-code prefix that CE prepends to many usage types, e.g. "USE1-", "EUW1-".
# Pattern: 2–4 uppercase letters + 1 digit + dash.
_REGION_PREFIX_RE = re.compile(r"^[A-Z]{2,4}\d-")


@dataclass
class UsageTypeInfo:
    service: str
    api_calls: list[str] = field(default_factory=list)
    event_type: str = ""   # e.g. "Data Event", "Management Event", "Insight Event"


# ---------------------------------------------------------------------------
# Mapping table — ordered from most-specific to least-specific prefix.
# Lookup strips the region prefix first, then walks this list with startswith().
# ---------------------------------------------------------------------------

_MAP: list[tuple[str, UsageTypeInfo]] = [

    # -------------------------------------------------------------------------
    # CloudWatch
    # -------------------------------------------------------------------------
    ("CW:Requests",               UsageTypeInfo("CloudWatch",       ["GetMetricData", "PutMetricData", "GetMetricStatistics", "ListMetrics"])),
    ("CW:GMD-Metrics",            UsageTypeInfo("CloudWatch",       ["GetMetricData"])),
    ("CW:MetricMonitorUsage",     UsageTypeInfo("CloudWatch",       ["PutMetricAlarm", "DescribeAlarms"])),
    ("CW:AlarmMonitorUsage",      UsageTypeInfo("CloudWatch",       ["PutMetricAlarm", "DescribeAlarms"])),
    ("CW:DashboardsUsage",        UsageTypeInfo("CloudWatch",       [])),
    ("CW:ContainerInsightUsage",  UsageTypeInfo("CloudWatch",       [])),
    ("CW:TimedStorage",           UsageTypeInfo("CloudWatch",       [])),
    ("CW:EventsMonitorUsage",     UsageTypeInfo("CloudWatch Events", ["PutEvents"])),
    ("CW:Logs-Bytes",             UsageTypeInfo("CloudWatch Logs",  ["PutLogEvents"])),
    ("CW:Logs-DataScanned",       UsageTypeInfo("CloudWatch Logs",  ["FilterLogEvents", "GetLogEvents", "StartQuery"])),
    ("CW:Logs-Delivered",         UsageTypeInfo("CloudWatch Logs",  ["PutLogEvents"])),
    ("CW:Logs-IncomingBytes",     UsageTypeInfo("CloudWatch Logs",  ["PutLogEvents"])),
    ("CW:",                       UsageTypeInfo("CloudWatch",       [])),

    # -------------------------------------------------------------------------
    # CloudTrail  (most specific patterns first)
    # -------------------------------------------------------------------------
    ("CloudTrail-DataEvent-S3",       UsageTypeInfo("CloudTrail", [], "Data Event")),
    ("CloudTrail-DataEvent-Lambda",   UsageTypeInfo("CloudTrail", ["InvokeFunction"], "Data Event")),
    ("CloudTrail-DataEvent-DynamoDB", UsageTypeInfo("CloudTrail", [], "Data Event")),
    ("CloudTrail-DataEvent",          UsageTypeInfo("CloudTrail", [], "Data Event")),
    ("CloudTrail-Insight",            UsageTypeInfo("CloudTrail", [], "Insight Event")),
    ("AWSCloudTrail",                 UsageTypeInfo("CloudTrail", [], "Management Event")),
    ("CloudTrail",                    UsageTypeInfo("CloudTrail", [], "Management Event")),

    # -------------------------------------------------------------------------
    # EC2 & EBS
    # -------------------------------------------------------------------------
    ("BoxUsage",           UsageTypeInfo("EC2",          ["RunInstances", "DescribeInstances"])),
    ("SpotUsage",          UsageTypeInfo("EC2",          ["RunInstances (Spot)"])),
    ("DedicatedUsage",     UsageTypeInfo("EC2",          ["RunInstances (Dedicated)"])),
    ("HostUsage",          UsageTypeInfo("EC2",          ["AllocateHosts"])),
    ("EBS:VolumeUsage",    UsageTypeInfo("EC2 (EBS)",    ["CreateVolume", "AttachVolume"])),
    ("EBS:SnapshotUsage",  UsageTypeInfo("EC2 (EBS)",    ["CreateSnapshot", "CopySnapshot"])),
    ("EBS:directAPI",      UsageTypeInfo("EC2 (EBS)",    ["GetSnapshotBlock", "PutSnapshotBlock"])),
    ("DataTransfer-Out",   UsageTypeInfo("EC2",          [], "Data Transfer")),
    ("DataTransfer-In",    UsageTypeInfo("EC2",          [], "Data Transfer")),
    ("DataTransfer-Regional", UsageTypeInfo("EC2",       [], "Data Transfer")),
    ("ElasticIP",          UsageTypeInfo("EC2",          [])),

    # -------------------------------------------------------------------------
    # S3
    # -------------------------------------------------------------------------
    ("S3-Requests-Tier1",  UsageTypeInfo("S3", ["PutObject", "CopyObject", "PostObject", "RestoreObject"])),
    ("S3-Requests-Tier2",  UsageTypeInfo("S3", ["GetObject", "HeadObject"])),
    ("S3-Requests-Tier3",  UsageTypeInfo("S3", ["ListBuckets", "ListObjects", "ListObjectVersions"])),
    ("S3-Requests-Tier4",  UsageTypeInfo("S3", ["LifecycleTransition"])),
    ("S3-Requests-Tier5",  UsageTypeInfo("S3", ["DeleteObject", "DeleteObjects"])),
    ("S3-Requests-Tier6",  UsageTypeInfo("S3", [])),
    ("S3-Storage",         UsageTypeInfo("S3", [])),
    ("TimedStorage-GlacierStagingStorage",  UsageTypeInfo("S3 Glacier", [])),
    ("TimedStorage-Glacier",                UsageTypeInfo("S3 Glacier", [])),
    ("TimedStorage-ZIA",                    UsageTypeInfo("S3", [])),
    ("TimedStorage",                        UsageTypeInfo("S3", [])),
    ("S3-DataTransfer",    UsageTypeInfo("S3", [], "Data Transfer")),
    ("S3-",                UsageTypeInfo("S3", [])),

    # -------------------------------------------------------------------------
    # Lambda
    # -------------------------------------------------------------------------
    ("Lambda-GB-Second",    UsageTypeInfo("Lambda",       ["InvokeFunction"])),
    ("Lambda-Requests",     UsageTypeInfo("Lambda",       ["InvokeFunction"])),
    ("Lambda-Edge-Request", UsageTypeInfo("Lambda@Edge",  ["InvokeFunction"])),
    ("Lambda-Edge-GB",      UsageTypeInfo("Lambda@Edge",  ["InvokeFunction"])),

    # -------------------------------------------------------------------------
    # RDS
    # -------------------------------------------------------------------------
    ("RDS:Multi-AZ",           UsageTypeInfo("RDS", [])),
    ("RDS:InstanceUsage",      UsageTypeInfo("RDS", [])),
    ("RDS:ServerlessUsage",    UsageTypeInfo("RDS", [])),
    ("RDS:GP2-Storage",        UsageTypeInfo("RDS", [])),
    ("RDS:GP3-Storage",        UsageTypeInfo("RDS", [])),
    ("RDS:IO-Requests",        UsageTypeInfo("RDS", [])),
    ("RDS:BackupUsage",        UsageTypeInfo("RDS", ["CreateDBSnapshot", "CopyDBSnapshot"])),
    ("RDS:ChargedIORequests",  UsageTypeInfo("RDS", [])),

    # -------------------------------------------------------------------------
    # DynamoDB
    # -------------------------------------------------------------------------
    ("DDB:ReadUnits",   UsageTypeInfo("DynamoDB", ["GetItem", "Query", "Scan", "BatchGetItem"])),
    ("DDB:WriteUnits",  UsageTypeInfo("DynamoDB", ["PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem"])),
    ("DDB:Storage",     UsageTypeInfo("DynamoDB", [])),
    ("DDB:",            UsageTypeInfo("DynamoDB", [])),

    # -------------------------------------------------------------------------
    # API Gateway
    # -------------------------------------------------------------------------
    ("ApiGatewayV2-Requests",    UsageTypeInfo("API Gateway (HTTP/WebSocket)", [])),
    ("ApiGatewayV2-Messages",    UsageTypeInfo("API Gateway (WebSocket)",      [])),
    ("ApiGateway-Requests",      UsageTypeInfo("API Gateway (REST)",           [])),

    # -------------------------------------------------------------------------
    # VPC – NAT Gateway & Endpoints
    # -------------------------------------------------------------------------
    ("NatGateway-Hours",   UsageTypeInfo("VPC (NAT Gateway)", [])),
    ("NatGateway-Bytes",   UsageTypeInfo("VPC (NAT Gateway)", [], "Data Transfer")),
    ("VpcEndpoint-Hours",  UsageTypeInfo("VPC Endpoint",      [])),
    ("VpcEndpoint-Bytes",  UsageTypeInfo("VPC Endpoint",      [], "Data Transfer")),

    # -------------------------------------------------------------------------
    # CloudFront
    # -------------------------------------------------------------------------
    ("CloudFront-Requests",          UsageTypeInfo("CloudFront", [])),
    ("CloudFront-Out-Bytes",         UsageTypeInfo("CloudFront", [], "Data Transfer")),
    ("CloudFront-DataTransfer",      UsageTypeInfo("CloudFront", [], "Data Transfer")),
    ("CloudFront-Invalidations",     UsageTypeInfo("CloudFront", ["CreateInvalidation"])),
    ("CloudFront-SSL-Cert",          UsageTypeInfo("CloudFront", [])),

    # -------------------------------------------------------------------------
    # SQS / SNS
    # -------------------------------------------------------------------------
    ("SQS-Requests",   UsageTypeInfo("SQS", ["SendMessage", "ReceiveMessage", "DeleteMessage"])),
    ("SNS-Requests",   UsageTypeInfo("SNS", ["Publish", "Subscribe", "CreateTopic"])),
    ("SNS-HTTP",       UsageTypeInfo("SNS", [], "Delivery - HTTP")),
    ("SNS-SQS",        UsageTypeInfo("SNS", [], "Delivery - SQS")),
    ("SNS-SMS",        UsageTypeInfo("SNS", [], "Delivery - SMS")),
    ("SNS-Email",      UsageTypeInfo("SNS", [], "Delivery - Email")),

    # -------------------------------------------------------------------------
    # KMS
    # -------------------------------------------------------------------------
    ("KMS-Requests",  UsageTypeInfo("KMS", ["Encrypt", "Decrypt", "GenerateDataKey", "Sign"])),
    ("KMS-Keys",      UsageTypeInfo("KMS", [])),

    # -------------------------------------------------------------------------
    # Secrets Manager
    # -------------------------------------------------------------------------
    ("AWSSecretsManager-Secrets",  UsageTypeInfo("Secrets Manager", [])),
    ("AWSSecretsManager-Calls",    UsageTypeInfo("Secrets Manager", ["GetSecretValue", "PutSecretValue", "RotateSecret"])),

    # -------------------------------------------------------------------------
    # ElastiCache
    # -------------------------------------------------------------------------
    ("ElastiCache:NodeUsage",   UsageTypeInfo("ElastiCache", [])),
    ("ElastiCache:BackupUsage", UsageTypeInfo("ElastiCache", ["CreateSnapshot"])),

    # -------------------------------------------------------------------------
    # ELB / ALB / NLB
    # -------------------------------------------------------------------------
    ("Application-LoadBalancerUsage",  UsageTypeInfo("ALB",          [])),
    ("Application-LoadBalancerLCU",    UsageTypeInfo("ALB",          [])),
    ("NetworkLoadBalancerUsage",       UsageTypeInfo("NLB",          [])),
    ("NetworkLoadBalancerLCU",         UsageTypeInfo("NLB",          [])),
    ("LoadBalancerUsage",              UsageTypeInfo("ELB (Classic)", [])),

    # -------------------------------------------------------------------------
    # EKS / ECS / Fargate
    # -------------------------------------------------------------------------
    ("EKS:Usage",           UsageTypeInfo("EKS",    [])),
    ("Fargate-vCPU-Hours",  UsageTypeInfo("Fargate", [])),
    ("Fargate-GB-Hours",    UsageTypeInfo("Fargate", [])),

    # -------------------------------------------------------------------------
    # Route 53
    # -------------------------------------------------------------------------
    ("Amazon-Route53-Queries",  UsageTypeInfo("Route 53", [])),
    ("Route53-HealthChecks",    UsageTypeInfo("Route 53", [])),
    ("Route53-HostedZone",      UsageTypeInfo("Route 53", [])),
    ("Route53-DNS-Queries",     UsageTypeInfo("Route 53", [])),

    # -------------------------------------------------------------------------
    # SES
    # -------------------------------------------------------------------------
    ("SES-Messages",      UsageTypeInfo("SES", ["SendEmail", "SendRawEmail"])),
    ("SES-Recipients",    UsageTypeInfo("SES", [])),
    ("SES-Attachments",   UsageTypeInfo("SES", [])),

    # -------------------------------------------------------------------------
    # Glue / Athena / Step Functions / EventBridge
    # -------------------------------------------------------------------------
    ("Glue-DPU-Hour",                        UsageTypeInfo("Glue",           [])),
    ("AmazonAthena",                         UsageTypeInfo("Athena",         [])),
    ("AmazonStates-StateTransitions",        UsageTypeInfo("Step Functions", [])),
    ("AmazonCloudWatch-Events",              UsageTypeInfo("EventBridge",    ["PutEvents"])),
    ("AmazonEventBridge",                    UsageTypeInfo("EventBridge",    ["PutEvents"])),

    # -------------------------------------------------------------------------
    # AWS Config
    # -------------------------------------------------------------------------
    ("AWSConfig-ConfigurationItemRecorded",  UsageTypeInfo("Config", [])),
    ("AWSConfig-RuleEvaluations",            UsageTypeInfo("Config", [])),
    ("AWSConfig-ConfigurationRecorder",      UsageTypeInfo("Config", [])),

    # -------------------------------------------------------------------------
    # Systems Manager
    # -------------------------------------------------------------------------
    ("AWSSystemsManager-Parameter",  UsageTypeInfo("SSM", ["GetParameter", "PutParameter", "GetParameters"])),
    ("AWSSystemsManager",            UsageTypeInfo("SSM", [])),

    # -------------------------------------------------------------------------
    # Kinesis
    # -------------------------------------------------------------------------
    ("AmazonKinesis-Hours",       UsageTypeInfo("Kinesis Data Streams", [])),
    ("AmazonKinesis-Shard",       UsageTypeInfo("Kinesis Data Streams", ["PutRecord", "PutRecords", "GetRecords"])),
    ("AmazonKinesisFirehose",     UsageTypeInfo("Kinesis Firehose",     ["PutRecord", "PutRecordBatch"])),

    # -------------------------------------------------------------------------
    # OpenSearch / Elasticsearch
    # -------------------------------------------------------------------------
    ("ESInstance",    UsageTypeInfo("OpenSearch", [])),
    ("ES:",           UsageTypeInfo("OpenSearch", [])),

    # -------------------------------------------------------------------------
    # Redshift
    # -------------------------------------------------------------------------
    ("Node",          UsageTypeInfo("Redshift",   [])),
    ("Redshift",      UsageTypeInfo("Redshift",   [])),

    # -------------------------------------------------------------------------
    # SageMaker
    # -------------------------------------------------------------------------
    ("ml.",           UsageTypeInfo("SageMaker",  [])),

    # -------------------------------------------------------------------------
    # Cognito
    # -------------------------------------------------------------------------
    ("AmazonCognito-MAU",         UsageTypeInfo("Cognito",  [])),
    ("AmazonCognito-",            UsageTypeInfo("Cognito",  [])),

    # -------------------------------------------------------------------------
    # Transfer Family
    # -------------------------------------------------------------------------
    ("AWSTransfer-",  UsageTypeInfo("Transfer Family", [])),
]


# ---------------------------------------------------------------------------
# Service → CloudTrail event source
# ---------------------------------------------------------------------------

_SERVICE_EVENT_SOURCES: dict[str, str] = {
    "CloudWatch":                    "monitoring.amazonaws.com",
    "CloudWatch Logs":               "logs.amazonaws.com",
    "CloudWatch Events":             "events.amazonaws.com",
    "EventBridge":                   "events.amazonaws.com",
    "CloudTrail":                    "cloudtrail.amazonaws.com",
    "EC2":                           "ec2.amazonaws.com",
    "EC2 (EBS)":                     "ec2.amazonaws.com",
    "S3":                            "s3.amazonaws.com",
    "Lambda":                        "lambda.amazonaws.com",
    "Lambda@Edge":                   "lambda.amazonaws.com",
    "RDS":                           "rds.amazonaws.com",
    "DynamoDB":                      "dynamodb.amazonaws.com",
    "SQS":                           "sqs.amazonaws.com",
    "SNS":                           "sns.amazonaws.com",
    "KMS":                           "kms.amazonaws.com",
    "Secrets Manager":               "secretsmanager.amazonaws.com",
    "ElastiCache":                   "elasticache.amazonaws.com",
    "ELB (Classic)":                 "elasticloadbalancing.amazonaws.com",
    "ALB":                           "elasticloadbalancing.amazonaws.com",
    "NLB":                           "elasticloadbalancing.amazonaws.com",
    "EKS":                           "eks.amazonaws.com",
    "ECS":                           "ecs.amazonaws.com",
    "ECR":                           "ecr.amazonaws.com",
    "Fargate":                       "ecs.amazonaws.com",
    "Route 53":                      "route53.amazonaws.com",
    "SES":                           "ses.amazonaws.com",
    "API Gateway (REST)":            "apigateway.amazonaws.com",
    "API Gateway (HTTP/WebSocket)":  "apigateway.amazonaws.com",
    "API Gateway (WebSocket)":       "apigateway.amazonaws.com",
    "VPC (NAT Gateway)":             "ec2.amazonaws.com",
    "VPC Endpoint":                  "ec2.amazonaws.com",
    "CloudFront":                    "cloudfront.amazonaws.com",
    "Glue":                          "glue.amazonaws.com",
    "Athena":                        "athena.amazonaws.com",
    "Step Functions":                "states.amazonaws.com",
    "Config":                        "config.amazonaws.com",
    "SSM":                           "ssm.amazonaws.com",
    "Kinesis Data Streams":          "kinesis.amazonaws.com",
    "Kinesis Firehose":              "firehose.amazonaws.com",
    "OpenSearch":                    "es.amazonaws.com",
    "Redshift":                      "redshift.amazonaws.com",
    "SageMaker":                     "sagemaker.amazonaws.com",
    "Cognito":                       "cognito-idp.amazonaws.com",
    "Transfer Family":               "transfer.amazonaws.com",
    "S3 Glacier":                    "glacier.amazonaws.com",
}


def get_event_source(service: str) -> str | None:
    """Return the CloudTrail event source domain for *service*, or ``None``."""
    return _SERVICE_EVENT_SOURCES.get(service)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_usage_type_info(usage_type: str) -> UsageTypeInfo | None:
    """
    Return enrichment info for *usage_type*, or ``None`` if unmapped.

    The region prefix (e.g. ``"USE1-"``, ``"EUW1-"``) is stripped before
    matching so that ``"USE1-CW:Requests"`` resolves the same as
    ``"CW:Requests"``.
    """
    base = _REGION_PREFIX_RE.sub("", usage_type)
    for prefix, info in _MAP:
        if base.startswith(prefix):
            return info
    return None
