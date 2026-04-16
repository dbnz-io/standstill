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
#
# Conventions:
#   - More-specific patterns (longer strings) precede catch-all prefixes.
#   - Security services listed early (this tool is security-focused).
#   - Prefixes use the exact strings CE produces after region-code stripping.
# ---------------------------------------------------------------------------

_MAP: list[tuple[str, UsageTypeInfo]] = [

    # =========================================================================
    # Security — GuardDuty
    # =========================================================================
    ("AmazonGuardDuty-MalwareProtection",   UsageTypeInfo("GuardDuty", [], "Malware Protection")),
    ("AmazonGuardDuty-RDSLoginMonitoring",  UsageTypeInfo("GuardDuty", [], "RDS Login Monitoring")),
    ("AmazonGuardDuty-RuntimeMonitoring",   UsageTypeInfo("GuardDuty", [], "Runtime Monitoring")),
    ("AmazonGuardDuty-EKSAuditLogs",        UsageTypeInfo("GuardDuty", [], "EKS Audit Log Monitoring")),
    ("AmazonGuardDuty-S3Protection",        UsageTypeInfo("GuardDuty", [], "S3 Protection")),
    ("AmazonGuardDuty-DataSources",         UsageTypeInfo("GuardDuty", [])),
    ("AmazonGuardDuty-",                    UsageTypeInfo("GuardDuty", [])),

    # =========================================================================
    # Security — Security Hub
    # =========================================================================
    ("AWSSecurityHub-FindingIngested",             UsageTypeInfo("Security Hub", [])),
    ("AWSSecurityHub-AutomationRulesEvaluations",  UsageTypeInfo("Security Hub", [])),
    ("AWSSecurityHub-",                            UsageTypeInfo("Security Hub", [])),

    # =========================================================================
    # Security — Inspector (v2 first, then v1)
    # =========================================================================
    ("AmazonInspector2-ContainerImageCoverage",  UsageTypeInfo("Inspector", [], "Container Image")),
    ("AmazonInspector2-EC2InstanceCoverage",     UsageTypeInfo("Inspector", [], "EC2 Instance")),
    ("AmazonInspector2-LambdaFunctionCoverage",  UsageTypeInfo("Inspector", [], "Lambda")),
    ("AmazonInspector2-",                        UsageTypeInfo("Inspector", [])),
    ("AmazonInspector-",                         UsageTypeInfo("Inspector", [])),

    # =========================================================================
    # Security — Macie (v2)
    # =========================================================================
    ("AmazonMacie2-SensitiveDataDiscovery",  UsageTypeInfo("Macie", [], "Sensitive Data Discovery")),
    ("AmazonMacie2-BucketMonitoring",        UsageTypeInfo("Macie", [])),
    ("AmazonMacie2-",                        UsageTypeInfo("Macie", [])),
    ("AmazonMacie-",                         UsageTypeInfo("Macie", [])),

    # =========================================================================
    # Security — Detective
    # =========================================================================
    ("AmazonDetective-Core",  UsageTypeInfo("Detective", [])),
    ("AmazonDetective-",      UsageTypeInfo("Detective", [])),

    # =========================================================================
    # Security — WAF (v2 first, then v1)
    # =========================================================================
    ("AWSWAFv2-BotControl",  UsageTypeInfo("WAF", [], "Bot Control")),
    ("AWSWAFv2-FraudControl", UsageTypeInfo("WAF", [], "Fraud Control")),
    ("AWSWAFv2-Rule",         UsageTypeInfo("WAF", [])),
    ("AWSWAFv2-WebACL",       UsageTypeInfo("WAF", [])),
    ("AWSWAFv2-Request",      UsageTypeInfo("WAF", [])),
    ("AWSWAFv2-",             UsageTypeInfo("WAF", [])),
    ("AWS-WAF-Rule",          UsageTypeInfo("WAF", [])),
    ("AWS-WAF-WebACL",        UsageTypeInfo("WAF", [])),
    ("AWS-WAF-",              UsageTypeInfo("WAF", [])),

    # =========================================================================
    # Security — Shield
    # =========================================================================
    ("AWSShield-DDoSProtection",  UsageTypeInfo("Shield", [], "Advanced")),
    ("AWSShield-DataTransfer",    UsageTypeInfo("Shield", [], "Data Transfer")),
    ("AWSShield-",                UsageTypeInfo("Shield", [])),

    # =========================================================================
    # Security — Network Firewall
    # =========================================================================
    ("AWSNetworkFirewall-Endpoint",  UsageTypeInfo("Network Firewall", [])),
    ("AWSNetworkFirewall-Traffic",   UsageTypeInfo("Network Firewall", [], "Data Transfer")),
    ("AWSNetworkFirewall-",          UsageTypeInfo("Network Firewall", [])),

    # =========================================================================
    # Security — Firewall Manager
    # =========================================================================
    ("AWSFirewallManager-Policy",  UsageTypeInfo("Firewall Manager", [])),
    ("AWSFirewallManager-",        UsageTypeInfo("Firewall Manager", [])),

    # =========================================================================
    # Security — Verified Access
    # =========================================================================
    ("AWSVerifiedAccess-Endpoint",  UsageTypeInfo("Verified Access", [])),
    ("AWSVerifiedAccess-",          UsageTypeInfo("Verified Access", [])),

    # =========================================================================
    # CloudWatch
    # =========================================================================
    ("CW:Requests",              UsageTypeInfo("CloudWatch",
                                               ["GetMetricData", "PutMetricData",
                                                "GetMetricStatistics", "ListMetrics"])),
    ("CW:GMD-Metrics",           UsageTypeInfo("CloudWatch",       ["GetMetricData"])),
    ("CW:MetricMonitorUsage",    UsageTypeInfo("CloudWatch",       ["PutMetricAlarm", "DescribeAlarms"])),
    ("CW:AlarmMonitorUsage",     UsageTypeInfo("CloudWatch",       ["PutMetricAlarm", "DescribeAlarms"])),
    ("CW:DashboardsUsage",       UsageTypeInfo("CloudWatch",       [])),
    ("CW:ContainerInsightUsage", UsageTypeInfo("CloudWatch",       [])),
    ("CW:TimedStorage",          UsageTypeInfo("CloudWatch",       [])),
    ("CW:EventsMonitorUsage",    UsageTypeInfo("CloudWatch Events", ["PutEvents"])),
    ("CW:Logs-Bytes",            UsageTypeInfo("CloudWatch Logs",  ["PutLogEvents"])),
    ("CW:Logs-DataScanned",      UsageTypeInfo("CloudWatch Logs",
                                               ["FilterLogEvents", "GetLogEvents", "StartQuery"])),
    ("CW:Logs-Delivered",        UsageTypeInfo("CloudWatch Logs",  ["PutLogEvents"])),
    ("CW:Logs-IncomingBytes",    UsageTypeInfo("CloudWatch Logs",  ["PutLogEvents"])),
    ("CW:",                      UsageTypeInfo("CloudWatch",       [])),

    # =========================================================================
    # CloudTrail  (most specific patterns first)
    # =========================================================================
    ("CloudTrail-DataEvent-S3",        UsageTypeInfo("CloudTrail", [], "Data Event")),
    ("CloudTrail-DataEvent-Lambda",    UsageTypeInfo("CloudTrail", ["InvokeFunction"], "Data Event")),
    ("CloudTrail-DataEvent-DynamoDB",  UsageTypeInfo("CloudTrail", [], "Data Event")),
    ("CloudTrail-DataEvent",           UsageTypeInfo("CloudTrail", [], "Data Event")),
    ("CloudTrail-Insight",             UsageTypeInfo("CloudTrail", [], "Insight Event")),
    ("AWSCloudTrail",                  UsageTypeInfo("CloudTrail", [], "Management Event")),
    ("CloudTrail",                     UsageTypeInfo("CloudTrail", [], "Management Event")),

    # =========================================================================
    # EC2 & EBS
    # =========================================================================
    ("BoxUsage",                  UsageTypeInfo("EC2", ["RunInstances", "DescribeInstances"])),
    ("SpotUsage",                 UsageTypeInfo("EC2", ["RunInstances (Spot)"])),
    ("DedicatedUsage",            UsageTypeInfo("EC2", ["RunInstances (Dedicated)"])),
    ("HostUsage",                 UsageTypeInfo("EC2", ["AllocateHosts"])),
    ("EBS:VolumeUsage.piops",     UsageTypeInfo("EC2 (EBS)", ["CreateVolume"])),
    ("EBS:VolumeUsage.gp3",       UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:VolumeUsage.gp2",       UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:VolumeUsage.io2",       UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:VolumeUsage.io1",       UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:VolumeUsage.st1",       UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:VolumeUsage.sc1",       UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:VolumeUsage",           UsageTypeInfo("EC2 (EBS)", ["CreateVolume", "AttachVolume"])),
    ("EBS:SnapshotUsage",         UsageTypeInfo("EC2 (EBS)", ["CreateSnapshot", "CopySnapshot"])),
    ("EBS:directAPI",             UsageTypeInfo("EC2 (EBS)", ["GetSnapshotBlock", "PutSnapshotBlock"])),
    ("EBS:PIOPS",                 UsageTypeInfo("EC2 (EBS)", [])),
    ("EBS:",                      UsageTypeInfo("EC2 (EBS)", [])),
    ("AmazonEC2-",                UsageTypeInfo("EC2", [])),
    ("DataTransfer-Out-Bytes",    UsageTypeInfo("EC2", [], "Data Transfer")),
    ("DataTransfer-Out",          UsageTypeInfo("EC2", [], "Data Transfer")),
    ("DataTransfer-In",           UsageTypeInfo("EC2", [], "Data Transfer")),
    ("DataTransfer-Regional",     UsageTypeInfo("EC2", [], "Data Transfer")),
    ("AWSDataTransfer-",          UsageTypeInfo("EC2", [], "Data Transfer")),
    ("ElasticIP",                 UsageTypeInfo("EC2", [])),
    ("UnusedBox",                 UsageTypeInfo("EC2", [], "Reserved Instance (unused)")),
    ("HeavyUsage:",               UsageTypeInfo("EC2", [], "Reserved Instance")),
    ("LightUsage:",               UsageTypeInfo("EC2", [], "Reserved Instance")),
    ("MediumUsage:",              UsageTypeInfo("EC2", [], "Reserved Instance")),

    # =========================================================================
    # S3
    # =========================================================================
    ("S3-Requests-Tier1",  UsageTypeInfo("S3", ["PutObject", "CopyObject", "PostObject", "RestoreObject"])),
    ("S3-Requests-Tier2",  UsageTypeInfo("S3", ["GetObject", "HeadObject"])),
    ("S3-Requests-Tier3",  UsageTypeInfo("S3", ["ListBuckets", "ListObjects", "ListObjectVersions"])),
    ("S3-Requests-Tier4",  UsageTypeInfo("S3", ["LifecycleTransition"])),
    ("S3-Requests-Tier5",  UsageTypeInfo("S3", ["DeleteObject", "DeleteObjects"])),
    ("S3-Requests-Tier6",  UsageTypeInfo("S3", [])),
    ("S3-Inventory",       UsageTypeInfo("S3", ["ListObjects"], "Inventory")),
    ("S3-Batch",           UsageTypeInfo("S3", [], "Batch Operations")),
    ("S3-Select",          UsageTypeInfo("S3", ["SelectObjectContent"])),
    ("S3-Replication",     UsageTypeInfo("S3", [], "Replication")),
    ("S3-ObjectLambda",    UsageTypeInfo("S3", [], "Object Lambda")),
    ("S3-Storage-INT",     UsageTypeInfo("S3", [], "Intelligent-Tiering")),
    ("S3-INT",             UsageTypeInfo("S3", [], "Intelligent-Tiering")),
    ("S3-Storage",         UsageTypeInfo("S3", [])),
    ("S3-DataTransfer",    UsageTypeInfo("S3", [], "Data Transfer")),
    ("TimedStorage-GlacierStagingStorage",    UsageTypeInfo("S3 Glacier", [])),
    ("TimedStorage-GlacierInstantStorage",    UsageTypeInfo("S3 Glacier Instant Retrieval", [])),
    ("TimedStorage-GlacierDeepArchiveStorage", UsageTypeInfo("S3 Glacier Deep Archive", [])),
    ("TimedStorage-Glacier",                  UsageTypeInfo("S3 Glacier", [])),
    ("TimedStorage-ZIA",                      UsageTypeInfo("S3", [])),
    ("TimedStorage",                          UsageTypeInfo("S3", [])),
    ("AmazonS3-",          UsageTypeInfo("S3", [])),
    ("S3-",                UsageTypeInfo("S3", [])),

    # =========================================================================
    # Lambda
    # =========================================================================
    ("Lambda-GB-Second",     UsageTypeInfo("Lambda", ["InvokeFunction"])),
    ("Lambda-Requests",      UsageTypeInfo("Lambda", ["InvokeFunction"])),
    ("Lambda-Edge-Request",  UsageTypeInfo("Lambda@Edge", ["InvokeFunction"])),
    ("Lambda-Edge-GB",       UsageTypeInfo("Lambda@Edge", ["InvokeFunction"])),
    ("Lambda-",              UsageTypeInfo("Lambda", [])),

    # =========================================================================
    # RDS & Aurora
    # =========================================================================
    ("RDS:Aurora:StorageIOUsage",     UsageTypeInfo("RDS (Aurora)", [])),
    ("RDS:AuroraServerless",          UsageTypeInfo("RDS (Aurora Serverless)", [])),
    ("RDS:AuroraStorage",             UsageTypeInfo("RDS (Aurora)", [])),
    ("RDS:Aurora",                    UsageTypeInfo("RDS (Aurora)", [])),
    ("RDS:Multi-AZ",                  UsageTypeInfo("RDS", [])),
    ("RDS:InstanceUsage",             UsageTypeInfo("RDS", [])),
    ("RDS:ServerlessUsage",           UsageTypeInfo("RDS", [])),
    ("RDS:GP2-Storage",               UsageTypeInfo("RDS", [])),
    ("RDS:GP3-Storage",               UsageTypeInfo("RDS", [])),
    ("RDS:IO-Requests",               UsageTypeInfo("RDS", [])),
    ("RDS:BackupUsage",               UsageTypeInfo("RDS", ["CreateDBSnapshot", "CopyDBSnapshot"])),
    ("RDS:ChargedIORequests",         UsageTypeInfo("RDS", [])),
    ("RDS:PIOPS",                     UsageTypeInfo("RDS", [])),
    ("RDS:",                          UsageTypeInfo("RDS", [])),

    # =========================================================================
    # DynamoDB
    # =========================================================================
    ("DDB:ReadUnits",   UsageTypeInfo("DynamoDB",
                                      ["GetItem", "Query", "Scan", "BatchGetItem"])),
    ("DDB:WriteUnits",  UsageTypeInfo("DynamoDB",
                                      ["PutItem", "UpdateItem", "DeleteItem", "BatchWriteItem"])),
    ("DDB:Storage",     UsageTypeInfo("DynamoDB", [])),
    ("DDB:",            UsageTypeInfo("DynamoDB", [])),

    # =========================================================================
    # DocumentDB
    # =========================================================================
    ("AmazonDocDB-InstanceUsage",  UsageTypeInfo("DocumentDB", [])),
    ("AmazonDocDB-StorageUsage",   UsageTypeInfo("DocumentDB", [])),
    ("AmazonDocDB-IOUsage",        UsageTypeInfo("DocumentDB", [])),
    ("AmazonDocDB-BackupUsage",    UsageTypeInfo("DocumentDB", [])),
    ("AmazonDocDB-",               UsageTypeInfo("DocumentDB", [])),

    # =========================================================================
    # Neptune
    # =========================================================================
    ("AmazonNeptune-InstanceUsage",  UsageTypeInfo("Neptune", [])),
    ("AmazonNeptune-StorageUsage",   UsageTypeInfo("Neptune", [])),
    ("AmazonNeptune-",               UsageTypeInfo("Neptune", [])),

    # =========================================================================
    # QLDB
    # =========================================================================
    ("AmazonQLDB-",  UsageTypeInfo("QLDB", [])),

    # =========================================================================
    # Timestream
    # =========================================================================
    ("AmazonTimestream-Writes",  UsageTypeInfo("Timestream", [])),
    ("AmazonTimestream-Queries", UsageTypeInfo("Timestream", [])),
    ("AmazonTimestream-",        UsageTypeInfo("Timestream", [])),

    # =========================================================================
    # MemoryDB for Redis
    # =========================================================================
    ("AmazonMemoryDB-NodeUsage",  UsageTypeInfo("MemoryDB", [])),
    ("AmazonMemoryDB-",           UsageTypeInfo("MemoryDB", [])),

    # =========================================================================
    # Keyspaces (Managed Apache Cassandra)
    # =========================================================================
    ("AmazonKeyspaces-ReadUnits",   UsageTypeInfo("Keyspaces", [])),
    ("AmazonKeyspaces-WriteUnits",  UsageTypeInfo("Keyspaces", [])),
    ("AmazonKeyspaces-",            UsageTypeInfo("Keyspaces", [])),

    # =========================================================================
    # API Gateway
    # =========================================================================
    ("ApiGatewayV2-Requests",   UsageTypeInfo("API Gateway (HTTP/WebSocket)", [])),
    ("ApiGatewayV2-Messages",   UsageTypeInfo("API Gateway (WebSocket)",      [])),
    ("ApiGateway-Requests",     UsageTypeInfo("API Gateway (REST)",           [])),

    # =========================================================================
    # VPC — NAT Gateway, Endpoints, Transit Gateway, VPN, Flow Logs, IPAM
    # =========================================================================
    ("NatGateway-Hours",              UsageTypeInfo("VPC (NAT Gateway)", [])),
    ("NatGateway-Bytes",              UsageTypeInfo("VPC (NAT Gateway)", [], "Data Transfer")),
    ("VpcEndpoint-Hours",             UsageTypeInfo("VPC Endpoint",      [])),
    ("VpcEndpoint-Bytes",             UsageTypeInfo("VPC Endpoint",      [], "Data Transfer")),
    ("TransitGateway-Hours",          UsageTypeInfo("Transit Gateway",   [])),
    ("TransitGateway-Bytes",          UsageTypeInfo("Transit Gateway",   [], "Data Transfer")),
    ("AmazonVPC-TransitGateway",      UsageTypeInfo("Transit Gateway",   [])),
    ("TransitGateway",                UsageTypeInfo("Transit Gateway",   [])),
    ("AmazonVPN-Connections",         UsageTypeInfo("VPN",               [])),
    ("VPN-ConnectionUsage",           UsageTypeInfo("VPN",               [])),
    ("AmazonVPN-",                    UsageTypeInfo("VPN",               [])),
    ("ClientVPN-Endpoint",            UsageTypeInfo("Client VPN",        [])),
    ("ClientVPN-",                    UsageTypeInfo("Client VPN",        [])),
    ("AmazonVPC-IPAM-",               UsageTypeInfo("VPC IPAM",          [])),
    ("VpcFlowLogs-",                  UsageTypeInfo("VPC Flow Logs",     [])),

    # =========================================================================
    # Direct Connect
    # =========================================================================
    ("AWSDirectConnect-DataTransfer",  UsageTypeInfo("Direct Connect", [], "Data Transfer")),
    ("AWSDirectConnect-PortUsage",     UsageTypeInfo("Direct Connect", [])),
    ("AWSDirectConnect-",              UsageTypeInfo("Direct Connect", [])),
    ("DirectConnect-",                 UsageTypeInfo("Direct Connect", [])),

    # =========================================================================
    # Global Accelerator
    # =========================================================================
    ("AWSGlobalAccelerator-DomainTraffic",   UsageTypeInfo("Global Accelerator", [], "Data Transfer")),
    ("AWSGlobalAccelerator-AcceleratorPort", UsageTypeInfo("Global Accelerator", [])),
    ("AWSGlobalAccelerator-",                UsageTypeInfo("Global Accelerator", [])),

    # =========================================================================
    # CloudFront
    # =========================================================================
    ("CloudFront-Requests",        UsageTypeInfo("CloudFront", [])),
    ("CloudFront-Out-Bytes",       UsageTypeInfo("CloudFront", [], "Data Transfer")),
    ("CloudFront-DataTransfer",    UsageTypeInfo("CloudFront", [], "Data Transfer")),
    ("CloudFront-Invalidations",   UsageTypeInfo("CloudFront", ["CreateInvalidation"])),
    ("CloudFront-SSL-Cert",        UsageTypeInfo("CloudFront", [])),
    ("CloudFront-",                UsageTypeInfo("CloudFront", [])),

    # =========================================================================
    # Route 53
    # =========================================================================
    ("Amazon-Route53-Queries",  UsageTypeInfo("Route 53", [])),
    ("Route53-HealthChecks",    UsageTypeInfo("Route 53", [])),
    ("Route53-HostedZone",      UsageTypeInfo("Route 53", [])),
    ("Route53-DNS-Queries",     UsageTypeInfo("Route 53", [])),
    ("Route53-",                UsageTypeInfo("Route 53", [])),

    # =========================================================================
    # ELB / ALB / NLB / GWLB
    # =========================================================================
    ("Application-LoadBalancerUsage",   UsageTypeInfo("ALB", [])),
    ("Application-LoadBalancerLCU",     UsageTypeInfo("ALB", [])),
    ("NetworkLoadBalancerUsage",        UsageTypeInfo("NLB", [])),
    ("NetworkLoadBalancerLCU",          UsageTypeInfo("NLB", [])),
    ("GatewayLoadBalancerUsage",        UsageTypeInfo("Gateway LB", [])),
    ("GatewayLoadBalancerLCU",          UsageTypeInfo("Gateway LB", [])),
    ("LoadBalancerUsage",               UsageTypeInfo("ELB (Classic)", [])),

    # =========================================================================
    # EKS / ECS / Fargate / ECR
    # =========================================================================
    ("EKS:Usage",                UsageTypeInfo("EKS", [])),
    ("EKS-AnywhereSupport",      UsageTypeInfo("EKS Anywhere", [])),
    ("Fargate-vCPU-Hours",       UsageTypeInfo("Fargate", [])),
    ("Fargate-GB-Hours",         UsageTypeInfo("Fargate", [])),
    ("AmazonECR-DataTransfer",   UsageTypeInfo("ECR", [], "Data Transfer")),
    ("AmazonECR-Storage",        UsageTypeInfo("ECR", [])),
    ("AmazonECR-",               UsageTypeInfo("ECR", [])),
    ("ECS-",                     UsageTypeInfo("ECS", [])),
    ("AmazonECS-",               UsageTypeInfo("ECS", [])),

    # =========================================================================
    # SQS / SNS / SWF / EventBridge
    # =========================================================================
    ("SQS-Requests",   UsageTypeInfo("SQS",
                                     ["SendMessage", "ReceiveMessage", "DeleteMessage"])),
    ("SQS-",           UsageTypeInfo("SQS", [])),
    ("SNS-Requests",   UsageTypeInfo("SNS", ["Publish", "Subscribe", "CreateTopic"])),
    ("SNS-HTTP",       UsageTypeInfo("SNS", [], "Delivery - HTTP")),
    ("SNS-SQS",        UsageTypeInfo("SNS", [], "Delivery - SQS")),
    ("SNS-SMS",        UsageTypeInfo("SNS", [], "Delivery - SMS")),
    ("SNS-Email",      UsageTypeInfo("SNS", [], "Delivery - Email")),
    ("SNS-",           UsageTypeInfo("SNS", [])),
    ("AmazonSWF-",     UsageTypeInfo("SWF", [])),
    ("AmazonEventBridge-Pipes",   UsageTypeInfo("EventBridge Pipes",    [])),
    ("AmazonEventBridge-Schemas", UsageTypeInfo("EventBridge Schemas",  [])),
    ("AmazonEventBridge-Archive", UsageTypeInfo("EventBridge",          [])),
    ("AmazonEventBridge-",        UsageTypeInfo("EventBridge",          ["PutEvents"])),
    ("AmazonCloudWatch-Events",   UsageTypeInfo("EventBridge",          ["PutEvents"])),

    # =========================================================================
    # KMS
    # =========================================================================
    ("KMS-Requests",  UsageTypeInfo("KMS",
                                    ["Encrypt", "Decrypt", "GenerateDataKey", "Sign"])),
    ("KMS-Keys",      UsageTypeInfo("KMS", [])),
    ("KMS-",          UsageTypeInfo("KMS", [])),

    # =========================================================================
    # Secrets Manager
    # =========================================================================
    ("AWSSecretsManager-Secrets",
     UsageTypeInfo("Secrets Manager", [])),
    ("AWSSecretsManager-Calls",
     UsageTypeInfo("Secrets Manager",
                   ["GetSecretValue", "PutSecretValue", "RotateSecret"])),
    ("AWSSecretsManager-",
     UsageTypeInfo("Secrets Manager", [])),

    # =========================================================================
    # SSM (Systems Manager)
    # =========================================================================
    ("AWSSystemsManager-Parameter",
     UsageTypeInfo("SSM", ["GetParameter", "PutParameter", "GetParameters"])),
    ("AWSSystemsManager-ManagedInstance",  UsageTypeInfo("SSM", [])),
    ("AWSSystemsManager-Automation",       UsageTypeInfo("SSM", [])),
    ("AWSSystemsManager-OpsCenter",        UsageTypeInfo("SSM", [])),
    ("AWSSystemsManager-SessionManager",   UsageTypeInfo("SSM", [])),
    ("AWSSystemsManager-PatchManager",     UsageTypeInfo("SSM", [])),
    ("AWSSystemsManager-",                 UsageTypeInfo("SSM", [])),

    # =========================================================================
    # ACM / ACM PCA / CloudHSM
    # =========================================================================
    ("AWSCertificateManagerPrivateCA-Certs",    UsageTypeInfo("ACM PCA", [])),
    ("AWSCertificateManagerPrivateCA-",         UsageTypeInfo("ACM PCA", [])),
    ("AWSCertificateManager-Issued",            UsageTypeInfo("ACM", [])),
    ("AWSCertificateManager-",                  UsageTypeInfo("ACM", [])),
    ("AWS-Certificate-Manager-",                UsageTypeInfo("ACM", [])),
    ("CloudHSM-HourlyUsage",                    UsageTypeInfo("CloudHSM", [])),
    ("CloudHSM-",                               UsageTypeInfo("CloudHSM", [])),

    # =========================================================================
    # ElastiCache / MemoryDB (catch-all after specific node patterns)
    # =========================================================================
    ("ElastiCache:NodeUsage",   UsageTypeInfo("ElastiCache", [])),
    ("ElastiCache:BackupUsage", UsageTypeInfo("ElastiCache", ["CreateSnapshot"])),
    ("ElastiCache:",            UsageTypeInfo("ElastiCache", [])),
    ("AmazonElastiCache-",      UsageTypeInfo("ElastiCache", [])),

    # =========================================================================
    # Kinesis — Data Streams / Firehose / Video Streams / Data Analytics
    # =========================================================================
    ("AmazonKinesis-Hours",       UsageTypeInfo("Kinesis Data Streams", [])),
    ("AmazonKinesis-Shard",       UsageTypeInfo("Kinesis Data Streams",
                                                ["PutRecord", "PutRecords", "GetRecords"])),
    ("AmazonKinesis-",            UsageTypeInfo("Kinesis Data Streams", [])),
    ("AmazonKinesisFirehose-",    UsageTypeInfo("Kinesis Firehose",
                                                ["PutRecord", "PutRecordBatch"])),
    ("AmazonKinesisAnalytics-",   UsageTypeInfo("Kinesis Data Analytics", [])),
    ("AmazonKinesisVideo-",       UsageTypeInfo("Kinesis Video Streams", [])),

    # =========================================================================
    # MSK (Managed Streaming for Kafka)
    # =========================================================================
    ("AmazonMSK-BrokerUsage",    UsageTypeInfo("MSK", [])),
    ("AmazonMSK-StorageUsage",   UsageTypeInfo("MSK", [])),
    ("AmazonMSK-",               UsageTypeInfo("MSK", [])),

    # =========================================================================
    # SES (Simple Email Service)
    # =========================================================================
    ("SES-Messages",    UsageTypeInfo("SES", ["SendEmail", "SendRawEmail"])),
    ("SES-Recipients",  UsageTypeInfo("SES", [])),
    ("SES-Attachments", UsageTypeInfo("SES", [])),
    ("SES-",            UsageTypeInfo("SES", [])),

    # =========================================================================
    # Glue / Athena / Lake Formation / QuickSight
    # =========================================================================
    ("Glue-DPU-Hour",              UsageTypeInfo("Glue", [])),
    ("Glue-",                      UsageTypeInfo("Glue", [])),
    ("AmazonAthena-Queries",       UsageTypeInfo("Athena", [])),
    ("AmazonAthena",               UsageTypeInfo("Athena", [])),
    ("AWSLakeFormation-",          UsageTypeInfo("Lake Formation", [])),
    ("AmazonQuickSight-",          UsageTypeInfo("QuickSight", [])),
    ("AWSDataExchange-",           UsageTypeInfo("Data Exchange", [])),

    # =========================================================================
    # EMR (Elastic MapReduce)
    # =========================================================================
    ("ElasticMapReduce-",   UsageTypeInfo("EMR", [])),
    ("AmazonEMR-",          UsageTypeInfo("EMR", [])),
    ("EMR-",                UsageTypeInfo("EMR", [])),

    # =========================================================================
    # Step Functions
    # =========================================================================
    ("AmazonStates-StateTransitions",  UsageTypeInfo("Step Functions", [])),
    ("AmazonStates-",                  UsageTypeInfo("Step Functions", [])),

    # =========================================================================
    # AWS Config
    # =========================================================================
    ("AWSConfig-ConfigurationItemRecorded",  UsageTypeInfo("Config", [])),
    ("AWSConfig-RuleEvaluations",            UsageTypeInfo("Config", [])),
    ("AWSConfig-ConfigurationRecorder",      UsageTypeInfo("Config", [])),
    ("AWSConfig-ConformancePack",            UsageTypeInfo("Config", [])),
    ("AWSConfig-",                           UsageTypeInfo("Config", [])),

    # =========================================================================
    # OpenSearch / Elasticsearch
    # =========================================================================
    ("ESInstance",         UsageTypeInfo("OpenSearch", [])),
    ("AmazonES-",          UsageTypeInfo("OpenSearch", [])),
    ("ES:",                UsageTypeInfo("OpenSearch", [])),
    ("AmazonOpenSearch-",  UsageTypeInfo("OpenSearch", [])),

    # =========================================================================
    # Redshift
    # =========================================================================
    ("AmazonRedshift-",    UsageTypeInfo("Redshift", [])),
    ("Redshift:",          UsageTypeInfo("Redshift", [])),
    ("Redshift",           UsageTypeInfo("Redshift", [])),

    # =========================================================================
    # EFS (Elastic File System)
    # =========================================================================
    ("AmazonEFS-InfrequentAccessDataRead",   UsageTypeInfo("EFS", [], "Infrequent Access")),
    ("AmazonEFS-InfrequentAccessDataWrite",  UsageTypeInfo("EFS", [], "Infrequent Access")),
    ("AmazonEFS-InfrequentAccessStorage",    UsageTypeInfo("EFS", [], "Infrequent Access")),
    ("AmazonEFS-StandardDataRead",           UsageTypeInfo("EFS", [])),
    ("AmazonEFS-StandardDataWrite",          UsageTypeInfo("EFS", [])),
    ("AmazonEFS-StandardStorage",            UsageTypeInfo("EFS", [])),
    ("AmazonEFS-",                           UsageTypeInfo("EFS", [])),

    # =========================================================================
    # FSx
    # =========================================================================
    ("AmazonFSxL-",  UsageTypeInfo("FSx for Lustre",   [])),
    ("AmazonFSxW-",  UsageTypeInfo("FSx for Windows",  [])),
    ("AmazonFSxN-",  UsageTypeInfo("FSx for ONTAP",    [])),
    ("AmazonFSxO-",  UsageTypeInfo("FSx for OpenZFS",  [])),
    ("AmazonFSx-",   UsageTypeInfo("FSx",               [])),

    # =========================================================================
    # AWS Backup / Storage Gateway / DataSync / Snow
    # =========================================================================
    ("AWSBackup-BackupStorage",  UsageTypeInfo("Backup", [])),
    ("AWSBackup-RestoreJobs",    UsageTypeInfo("Backup", [])),
    ("AWSBackup-",               UsageTypeInfo("Backup", [])),
    ("AWSStorageGateway-",       UsageTypeInfo("Storage Gateway", [])),
    ("AWSDataSync-DataTransferred", UsageTypeInfo("DataSync", [], "Data Transfer")),
    ("AWSDataSync-",             UsageTypeInfo("DataSync", [])),
    ("AWSSnowball-",             UsageTypeInfo("Snow Family", [])),

    # =========================================================================
    # SageMaker
    # =========================================================================
    ("SageMaker-Endpoint",         UsageTypeInfo("SageMaker", [])),
    ("SageMaker-Training",         UsageTypeInfo("SageMaker", [])),
    ("SageMaker-Processing",       UsageTypeInfo("SageMaker", [])),
    ("SageMaker-Studio",           UsageTypeInfo("SageMaker", [])),
    ("SageMaker-Canvas",           UsageTypeInfo("SageMaker", [])),
    ("SageMaker-",                 UsageTypeInfo("SageMaker", [])),
    ("ml.",                        UsageTypeInfo("SageMaker", [])),

    # =========================================================================
    # AI / ML — Bedrock
    # =========================================================================
    ("AmazonBedrock-InputTokens",   UsageTypeInfo("Bedrock", [])),
    ("AmazonBedrock-OutputTokens",  UsageTypeInfo("Bedrock", [])),
    ("AmazonBedrock-ModelUnits",    UsageTypeInfo("Bedrock", [])),
    ("AmazonBedrock-",              UsageTypeInfo("Bedrock", [])),

    # =========================================================================
    # AI / ML — Other services
    # =========================================================================
    ("AmazonRekognition-",   UsageTypeInfo("Rekognition", [])),
    ("AmazonTextract-",      UsageTypeInfo("Textract",    [])),
    ("AmazonComprehend-",    UsageTypeInfo("Comprehend",  [])),
    ("AmazonTranslate-",     UsageTypeInfo("Translate",   [])),
    ("AmazonPolly-",         UsageTypeInfo("Polly",       [])),
    ("AmazonLex-",           UsageTypeInfo("Lex",         [])),
    ("AmazonTranscribe-",    UsageTypeInfo("Transcribe",  [])),
    ("AmazonForecast-",      UsageTypeInfo("Forecast",    [])),
    ("AmazonPersonalize-",   UsageTypeInfo("Personalize", [])),
    ("AmazonCodeGuru-",      UsageTypeInfo("CodeGuru",    [])),
    ("AmazonDevOpsGuru-",    UsageTypeInfo("DevOps Guru", [])),
    ("AmazonKendra-",        UsageTypeInfo("Kendra",      [])),

    # =========================================================================
    # Cognito
    # =========================================================================
    ("AmazonCognito-MAU",  UsageTypeInfo("Cognito", [])),
    ("AmazonCognito-",     UsageTypeInfo("Cognito", [])),

    # =========================================================================
    # Observability — X-Ray / Managed Grafana / Managed Prometheus
    # =========================================================================
    ("AWSXRay-TracesStored",    UsageTypeInfo("X-Ray", [])),
    ("AWSXRay-TracesScanned",   UsageTypeInfo("X-Ray", [])),
    ("AWSXRay-",                UsageTypeInfo("X-Ray", [])),
    ("AmazonGrafana-",          UsageTypeInfo("Managed Grafana",     [])),
    ("AmazonPrometheus-",       UsageTypeInfo("Managed Prometheus",  [])),

    # =========================================================================
    # Developer Tools — CodeBuild / CodePipeline / CodeCommit / CodeDeploy / CodeArtifact
    # =========================================================================
    ("CodeBuild-Build",          UsageTypeInfo("CodeBuild",    [])),
    ("CodeBuild-",               UsageTypeInfo("CodeBuild",    [])),
    ("AWS-CodePipeline-",        UsageTypeInfo("CodePipeline", [])),
    ("AWSCodePipeline-",         UsageTypeInfo("CodePipeline", [])),
    ("AWSCodeCommit-",           UsageTypeInfo("CodeCommit",   [])),
    ("AWSCodeDeploy-",           UsageTypeInfo("CodeDeploy",   [])),
    ("CodeArtifact-",            UsageTypeInfo("CodeArtifact", [])),

    # =========================================================================
    # Management — CloudFormation / Organizations / Control Tower / Service Catalog
    # =========================================================================
    ("AWSCloudFormation-",      UsageTypeInfo("CloudFormation",  [])),
    ("AWSOrganizations-",       UsageTypeInfo("Organizations",   [])),
    ("AWSControlTower-",        UsageTypeInfo("Control Tower",   [])),
    ("AWSServiceCatalog-",      UsageTypeInfo("Service Catalog", [])),
    ("AWSAppConfig-",           UsageTypeInfo("AppConfig",       [])),

    # =========================================================================
    # App Services — AppSync / AppRunner / Connect / Pinpoint
    # =========================================================================
    ("AWSAppSync-Requests",  UsageTypeInfo("AppSync", [])),
    ("AWSAppSync-",          UsageTypeInfo("AppSync", [])),
    ("AppRunner-Memory",     UsageTypeInfo("App Runner", [])),
    ("AppRunner-vCPU",       UsageTypeInfo("App Runner", [])),
    ("AppRunner-",           UsageTypeInfo("App Runner", [])),
    ("AmazonConnect-",       UsageTypeInfo("Connect",   [])),
    ("AWSPinpoint-",         UsageTypeInfo("Pinpoint",  [])),

    # =========================================================================
    # End-User Computing — WorkSpaces / AppStream / Directory Service
    # =========================================================================
    ("AmazonWorkSpaces-",       UsageTypeInfo("WorkSpaces",        [])),
    ("AmazonAppStream-",        UsageTypeInfo("AppStream",         [])),
    ("AWSDirectoryService-",    UsageTypeInfo("Directory Service", [])),

    # =========================================================================
    # IoT Core / Greengrass
    # =========================================================================
    ("AWSIoT-",          UsageTypeInfo("IoT Core",      [])),
    ("AWSGreengrass-",   UsageTypeInfo("IoT Greengrass", [])),

    # =========================================================================
    # Media Services
    # =========================================================================
    ("AWSElementalMediaConvert-",  UsageTypeInfo("MediaConvert",          [])),
    ("AWSElementalMediaLive-",     UsageTypeInfo("MediaLive",             [])),
    ("AWSElementalMediaPackage-",  UsageTypeInfo("MediaPackage",          [])),
    ("AWSElementalMediaStore-",    UsageTypeInfo("MediaStore",            [])),
    ("AmazonElasticTranscoder-",   UsageTypeInfo("Elastic Transcoder",    [])),

    # =========================================================================
    # Transfer Family
    # =========================================================================
    ("AWSTransfer-",  UsageTypeInfo("Transfer Family", [])),

    # =========================================================================
    # Lightsail / Batch / GameLift
    # =========================================================================
    ("AmazonLightsail-",  UsageTypeInfo("Lightsail",  [])),
    ("AWSBatch-",         UsageTypeInfo("Batch",      [])),
    ("AmazonGameLift-",   UsageTypeInfo("GameLift",   [])),

    # =========================================================================
    # Cost management line items (appear as credits / adjustments)
    # =========================================================================
    ("AWSCostExplorer-",      UsageTypeInfo("Cost Explorer",    [])),
    ("AWSBudgets-",           UsageTypeInfo("Budgets",          [])),
    ("SavingsPlanNegation",   UsageTypeInfo("Savings Plans",    [], "Credit")),
    ("SavingsPlan-",          UsageTypeInfo("Savings Plans",    [])),

    # =========================================================================
    # Support
    # =========================================================================
    ("AWSSupportBusiness",     UsageTypeInfo("Support", [], "Business")),
    ("AWSSupportEnterprise",   UsageTypeInfo("Support", [], "Enterprise")),
    ("AWSSupportDeveloper",    UsageTypeInfo("Support", [], "Developer")),
    ("AWSSupport-",            UsageTypeInfo("Support", [])),
]


# ---------------------------------------------------------------------------
# Service → CloudTrail event source
# ---------------------------------------------------------------------------

_SERVICE_EVENT_SOURCES: dict[str, str] = {
    # Compute
    "EC2":                            "ec2.amazonaws.com",
    "EC2 (EBS)":                      "ec2.amazonaws.com",
    "Lambda":                         "lambda.amazonaws.com",
    "Lambda@Edge":                    "lambda.amazonaws.com",
    "Fargate":                        "ecs.amazonaws.com",
    "EKS":                            "eks.amazonaws.com",
    "EKS Anywhere":                   "eks.amazonaws.com",
    "ECS":                            "ecs.amazonaws.com",
    "ECR":                            "ecr.amazonaws.com",
    "App Runner":                     "apprunner.amazonaws.com",
    "Batch":                          "batch.amazonaws.com",
    "Lightsail":                      "lightsail.amazonaws.com",
    # Storage
    "S3":                             "s3.amazonaws.com",
    "S3 Glacier":                     "glacier.amazonaws.com",
    "S3 Glacier Instant Retrieval":   "glacier.amazonaws.com",
    "S3 Glacier Deep Archive":        "glacier.amazonaws.com",
    "EFS":                            "elasticfilesystem.amazonaws.com",
    "FSx":                            "fsx.amazonaws.com",
    "FSx for Lustre":                 "fsx.amazonaws.com",
    "FSx for Windows":                "fsx.amazonaws.com",
    "FSx for ONTAP":                  "fsx.amazonaws.com",
    "FSx for OpenZFS":                "fsx.amazonaws.com",
    "Backup":                         "backup.amazonaws.com",
    "Storage Gateway":                "storagegateway.amazonaws.com",
    "DataSync":                       "datasync.amazonaws.com",
    "Snow Family":                    "snowball.amazonaws.com",
    "Transfer Family":                "transfer.amazonaws.com",
    # Database
    "RDS":                            "rds.amazonaws.com",
    "RDS (Aurora)":                   "rds.amazonaws.com",
    "RDS (Aurora Serverless)":        "rds.amazonaws.com",
    "DynamoDB":                       "dynamodb.amazonaws.com",
    "ElastiCache":                    "elasticache.amazonaws.com",
    "MemoryDB":                       "memory-db.amazonaws.com",
    "DocumentDB":                     "docdb.amazonaws.com",
    "Neptune":                        "neptune.amazonaws.com",
    "QLDB":                           "qldb.amazonaws.com",
    "Timestream":                     "timestream.amazonaws.com",
    "Keyspaces":                      "cassandra.amazonaws.com",
    "OpenSearch":                     "es.amazonaws.com",
    "Redshift":                       "redshift.amazonaws.com",
    # Networking
    "CloudFront":                     "cloudfront.amazonaws.com",
    "Route 53":                       "route53.amazonaws.com",
    "API Gateway (REST)":             "apigateway.amazonaws.com",
    "API Gateway (HTTP/WebSocket)":   "apigateway.amazonaws.com",
    "API Gateway (WebSocket)":        "apigateway.amazonaws.com",
    "VPC (NAT Gateway)":              "ec2.amazonaws.com",
    "VPC Endpoint":                   "ec2.amazonaws.com",
    "VPC IPAM":                       "ec2.amazonaws.com",
    "VPC Flow Logs":                  "ec2.amazonaws.com",
    "Transit Gateway":                "ec2.amazonaws.com",
    "VPN":                            "ec2.amazonaws.com",
    "Client VPN":                     "ec2.amazonaws.com",
    "Direct Connect":                 "directconnect.amazonaws.com",
    "Global Accelerator":             "globalaccelerator.amazonaws.com",
    "ELB (Classic)":                  "elasticloadbalancing.amazonaws.com",
    "ALB":                            "elasticloadbalancing.amazonaws.com",
    "NLB":                            "elasticloadbalancing.amazonaws.com",
    "Gateway LB":                     "elasticloadbalancing.amazonaws.com",
    # Observability
    "CloudWatch":                     "monitoring.amazonaws.com",
    "CloudWatch Logs":                "logs.amazonaws.com",
    "CloudWatch Events":              "events.amazonaws.com",
    "EventBridge":                    "events.amazonaws.com",
    "EventBridge Pipes":              "pipes.amazonaws.com",
    "EventBridge Schemas":            "schemas.amazonaws.com",
    "CloudTrail":                     "cloudtrail.amazonaws.com",
    "X-Ray":                          "xray.amazonaws.com",
    "Managed Grafana":                "grafana.amazonaws.com",
    "Managed Prometheus":             "aps.amazonaws.com",
    # Security
    "GuardDuty":                      "guardduty.amazonaws.com",
    "Security Hub":                   "securityhub.amazonaws.com",
    "Inspector":                      "inspector2.amazonaws.com",
    "Macie":                          "macie2.amazonaws.com",
    "Detective":                      "detective.amazonaws.com",
    "WAF":                            "wafv2.amazonaws.com",
    "Shield":                         "shield.amazonaws.com",
    "Network Firewall":               "network-firewall.amazonaws.com",
    "Firewall Manager":               "fms.amazonaws.com",
    "Verified Access":                "verified-access.amazonaws.com",
    # Identity & PKI
    "KMS":                            "kms.amazonaws.com",
    "Secrets Manager":                "secretsmanager.amazonaws.com",
    "ACM":                            "acm.amazonaws.com",
    "ACM PCA":                        "acm-pca.amazonaws.com",
    "CloudHSM":                       "cloudhsm.amazonaws.com",
    "Cognito":                        "cognito-idp.amazonaws.com",
    "Directory Service":              "ds.amazonaws.com",
    # Messaging / integration
    "SQS":                            "sqs.amazonaws.com",
    "SNS":                            "sns.amazonaws.com",
    "SWF":                            "swf.amazonaws.com",
    "AppSync":                        "appsync.amazonaws.com",
    "Connect":                        "connect.amazonaws.com",
    "Pinpoint":                       "mobiletargeting.amazonaws.com",
    "SES":                            "ses.amazonaws.com",
    "Step Functions":                 "states.amazonaws.com",
    # Analytics / streaming
    "Glue":                           "glue.amazonaws.com",
    "Athena":                         "athena.amazonaws.com",
    "Lake Formation":                 "lakeformation.amazonaws.com",
    "QuickSight":                     "quicksight.amazonaws.com",
    "EMR":                            "elasticmapreduce.amazonaws.com",
    "MSK":                            "kafka.amazonaws.com",
    "Kinesis Data Streams":           "kinesis.amazonaws.com",
    "Kinesis Firehose":               "firehose.amazonaws.com",
    "Kinesis Data Analytics":         "kinesisanalytics.amazonaws.com",
    "Kinesis Video Streams":          "kinesisvideo.amazonaws.com",
    "Data Exchange":                  "dataexchange.amazonaws.com",
    # AI / ML
    "SageMaker":                      "sagemaker.amazonaws.com",
    "Bedrock":                        "bedrock.amazonaws.com",
    "Rekognition":                    "rekognition.amazonaws.com",
    "Textract":                       "textract.amazonaws.com",
    "Comprehend":                     "comprehend.amazonaws.com",
    "Translate":                      "translate.amazonaws.com",
    "Polly":                          "polly.amazonaws.com",
    "Lex":                            "lex.amazonaws.com",
    "Transcribe":                     "transcribe.amazonaws.com",
    "Forecast":                       "forecast.amazonaws.com",
    "Personalize":                    "personalize.amazonaws.com",
    "CodeGuru":                       "codeguru-reviewer.amazonaws.com",
    "DevOps Guru":                    "devops-guru.amazonaws.com",
    "Kendra":                         "kendra.amazonaws.com",
    # Developer tools
    "CodeBuild":                      "codebuild.amazonaws.com",
    "CodePipeline":                   "codepipeline.amazonaws.com",
    "CodeCommit":                     "codecommit.amazonaws.com",
    "CodeDeploy":                     "codedeploy.amazonaws.com",
    "CodeArtifact":                   "codeartifact.amazonaws.com",
    # Management
    "CloudFormation":                 "cloudformation.amazonaws.com",
    "Organizations":                  "organizations.amazonaws.com",
    "Control Tower":                  "controltower.amazonaws.com",
    "Service Catalog":                "servicecatalog.amazonaws.com",
    "AppConfig":                      "appconfig.amazonaws.com",
    "Config":                         "config.amazonaws.com",
    "SSM":                            "ssm.amazonaws.com",
    # End-user computing
    "WorkSpaces":                     "workspaces.amazonaws.com",
    "AppStream":                      "appstream.amazonaws.com",
    # IoT
    "IoT Core":                       "iot.amazonaws.com",
    "IoT Greengrass":                 "greengrass.amazonaws.com",
    # Media
    "MediaConvert":                   "mediaconvert.amazonaws.com",
    "MediaLive":                      "medialive.amazonaws.com",
    "MediaPackage":                   "mediapackage.amazonaws.com",
    "MediaStore":                     "mediastore.amazonaws.com",
    "Elastic Transcoder":             "elastictranscoder.amazonaws.com",
    # Misc
    "GameLift":                       "gamelift.amazonaws.com",
    "Cost Explorer":                  "ce.amazonaws.com",
    "Savings Plans":                  "savingsplans.amazonaws.com",
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
