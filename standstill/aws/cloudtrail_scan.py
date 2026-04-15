from __future__ import annotations

import gzip
import io
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class TrailEvent:
    event_id:     str
    event_name:   str
    event_time:   datetime
    event_source: str
    username:     str
    account_id:   str
    source_ip:    str
    user_agent:   str
    region:       str
    read_only:    bool
    resources:    list[str] = field(default_factory=list)
    error_code:   str = ""
    error_message: str = ""


@dataclass
class ScanResult:
    usage_type:          str
    service:             str
    event_source:        str
    api_calls_searched:  list[str]
    start:               str
    end:                 str
    events:              list[TrailEvent] = field(default_factory=list)

    # ---------------------------------------------------------------------------
    # Derived helpers
    # ---------------------------------------------------------------------------

    def summary_by_event(self) -> list[dict]:
        """Per-event-name count + first/last timestamp."""
        by_name: dict[str, list[TrailEvent]] = {}
        for ev in self.events:
            by_name.setdefault(ev.event_name, []).append(ev)
        rows = []
        for name, evs in sorted(by_name.items(), key=lambda x: len(x[1]), reverse=True):
            times = [e.event_time for e in evs]
            rows.append({
                "event_name": name,
                "count":      len(evs),
                "first":      min(times).isoformat(),
                "last":       max(times).isoformat(),
            })
        return rows

    def summary_by_caller(self) -> list[dict]:
        """Per-username call count, sorted descending."""
        counts: dict[str, int] = {}
        for ev in self.events:
            caller = ev.username or "(unknown)"
            counts[caller] = counts.get(caller, 0) + 1
        return [
            {"username": u, "count": c}
            for u, c in sorted(counts.items(), key=lambda x: x[1], reverse=True)
        ]

    def summary_by_identity_attribution(self) -> list[dict]:
        """
        Group events by the *effective identity* (account + IAM entity type + name),
        returning a breakdown that helps answer "who is generating these costs?".

        Each row includes:
          account_id, identity_type (Root/IAMUser/AssumedRole/FederatedUser/Service),
          identity_name (role/user/service name), call_count, error_count,
          first_seen, last_seen, regions (sorted list).
        """
        groups: dict[tuple, dict] = {}
        for ev in self.events:
            # Derive identity_type and identity_name from the username/ARN.
            username = ev.username or ""
            if username.startswith("arn:aws:sts") and ":assumed-role/" in username:
                parts = username.split("/")
                identity_type = "AssumedRole"
                identity_name = parts[1] if len(parts) > 1 else username
            elif username.startswith("arn:aws:iam") and ":user/" in username:
                identity_type = "IAMUser"
                identity_name = username.split(":user/")[-1]
            elif username.lower() == "root":
                identity_type = "Root"
                identity_name = "root"
            elif "@" in username and not username.startswith("arn:"):
                identity_type = "FederatedUser"
                identity_name = username
            elif username.endswith(".amazonaws.com"):
                identity_type = "Service"
                identity_name = username
            else:
                identity_type = "IAMUser"
                identity_name = username or "(unknown)"

            key = (ev.account_id, identity_type, identity_name)
            if key not in groups:
                groups[key] = {
                    "account_id":     ev.account_id,
                    "identity_type":  identity_type,
                    "identity_name":  identity_name,
                    "call_count":     0,
                    "error_count":    0,
                    "regions":        set(),
                    "first_seen":     ev.event_time,
                    "last_seen":      ev.event_time,
                }
            entry = groups[key]
            entry["call_count"] += 1
            if ev.error_code:
                entry["error_count"] += 1
            entry["regions"].add(ev.region)
            if ev.event_time < entry["first_seen"]:
                entry["first_seen"] = ev.event_time
            if ev.event_time > entry["last_seen"]:
                entry["last_seen"] = ev.event_time

        rows = []
        for entry in sorted(groups.values(), key=lambda x: x["call_count"], reverse=True):
            rows.append({
                "account_id":    entry["account_id"],
                "identity_type": entry["identity_type"],
                "identity_name": entry["identity_name"],
                "call_count":    entry["call_count"],
                "error_count":   entry["error_count"],
                "regions":       sorted(entry["regions"]),
                "first_seen":    entry["first_seen"].isoformat(),
                "last_seen":     entry["last_seen"].isoformat(),
            })
        return rows

    def to_dict(self) -> dict:
        return {
            "usage_type":         self.usage_type,
            "service":            self.service,
            "event_source":       self.event_source,
            "api_calls_searched": self.api_calls_searched,
            "period":             {"start": self.start, "end": self.end},
            "total_events":       len(self.events),
            "summary_by_event":   self.summary_by_event(),
            "summary_by_caller":  self.summary_by_caller(),
            "events": [
                {
                    "event_id":      e.event_id,
                    "event_name":    e.event_name,
                    "event_time":    e.event_time.isoformat(),
                    "event_source":  e.event_source,
                    "username":      e.username,
                    "account_id":    e.account_id,
                    "source_ip":     e.source_ip,
                    "user_agent":    e.user_agent,
                    "region":        e.region,
                    "read_only":     e.read_only,
                    "resources":     e.resources,
                    "error_code":    e.error_code,
                    "error_message": e.error_message,
                }
                for e in sorted(self.events, key=lambda x: x.event_time, reverse=True)
            ],
        }


# ---------------------------------------------------------------------------
# CloudTrail helpers
# ---------------------------------------------------------------------------

def _parse_event(raw: dict) -> TrailEvent:
    """Parse a single raw lookup_events entry into a :class:`TrailEvent`."""
    ct_json: dict = {}
    if raw.get("CloudTrailEvent"):
        try:
            ct_json = json.loads(raw["CloudTrailEvent"])
        except (ValueError, TypeError):
            pass

    resources = [
        r.get("ResourceName", "")
        for r in raw.get("Resources") or []
        if r.get("ResourceName")
    ]

    event_time = raw.get("EventTime")
    if isinstance(event_time, datetime):
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)
    else:
        event_time = datetime.now(timezone.utc)

    return TrailEvent(
        event_id      = raw.get("EventId", ""),
        event_name    = raw.get("EventName", ""),
        event_time    = event_time,
        event_source  = raw.get("EventSource", ct_json.get("eventSource", "")),
        username      = raw.get("Username", ct_json.get("userIdentity", {}).get("arn", "")),
        account_id    = ct_json.get("recipientAccountId", ""),
        source_ip     = ct_json.get("sourceIPAddress", ""),
        user_agent    = ct_json.get("userAgent", ""),
        region        = ct_json.get("awsRegion", ""),
        read_only     = str(raw.get("ReadOnly", "")).lower() == "true",
        resources     = resources,
        error_code    = ct_json.get("errorCode", ""),
        error_message = ct_json.get("errorMessage", ""),
    )


def _lookup_by_attribute(
    ct,
    attribute_key: str,
    attribute_value: str,
    start_time: datetime,
    end_time: datetime,
    max_events: int,
) -> list[TrailEvent]:
    """Paginate through lookup_events for a single attribute filter."""
    events: list[TrailEvent] = []
    kwargs: dict = {
        "LookupAttributes": [
            {"AttributeKey": attribute_key, "AttributeValue": attribute_value}
        ],
        "StartTime": start_time,
        "EndTime":   end_time,
        "MaxResults": min(50, max_events),  # API max per page is 50
    }

    while len(events) < max_events:
        resp = ct.lookup_events(**kwargs)
        for raw in resp.get("Events", []):
            events.append(_parse_event(raw))
            if len(events) >= max_events:
                break
        next_token = resp.get("NextToken")
        if not next_token or len(events) >= max_events:
            break
        kwargs["NextToken"] = next_token

    return events


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(
    ct,
    usage_type: str,
    event_source: str,
    api_calls: list[str],
    start: datetime,
    end: datetime,
    max_events: int = 200,
) -> ScanResult:
    """
    Fetch CloudTrail events for a given usage type.

    When *api_calls* is non-empty, one parallel lookup per call name is issued
    (results are OR-merged).  When empty, a single lookup by *event_source* is
    done instead.

    Args:
        ct:           boto3 ``cloudtrail`` client.
        usage_type:   CE usage type string (used only for the result label).
        event_source: CloudTrail event source domain, e.g. ``"monitoring.amazonaws.com"``.
        api_calls:    Specific API call names to search for.
        start:        Inclusive start datetime (UTC).
        end:          Exclusive end datetime (UTC).
        max_events:   Upper bound on total events returned.
    """
    from standstill.aws.usage_type_map import _REGION_PREFIX_RE, get_usage_type_info

    # Resolve the service name for the result label.
    base = _REGION_PREFIX_RE.sub("", usage_type)
    info = get_usage_type_info(base)
    service = info.service if info else usage_type

    all_events: list[TrailEvent] = []

    if api_calls:
        # One lookup per API call name, run in parallel.
        max_per_call = max(1, max_events // len(api_calls))
        with ThreadPoolExecutor(max_workers=min(len(api_calls), 8)) as pool:
            futures = {
                pool.submit(
                    _lookup_by_attribute,
                    ct, "EventName", name, start, end, max_per_call,
                ): name
                for name in api_calls
            }
            for future in as_completed(futures):
                all_events.extend(future.result())
    else:
        # Fall back to lookup by event source.
        all_events = _lookup_by_attribute(
            ct, "EventSource", event_source, start, end, max_events
        )

    # Deduplicate by event_id and sort newest first.
    seen: set[str] = set()
    unique: list[TrailEvent] = []
    for ev in sorted(all_events, key=lambda e: e.event_time, reverse=True):
        if ev.event_id not in seen:
            seen.add(ev.event_id)
            unique.append(ev)

    return ScanResult(
        usage_type         = usage_type,
        service            = service,
        event_source       = event_source,
        api_calls_searched = api_calls,
        start              = start.isoformat(),
        end                = end.isoformat(),
        events             = unique,
    )


# ---------------------------------------------------------------------------
# S3 backend
# ---------------------------------------------------------------------------

def _iter_date_range(start: datetime, end: datetime):
    """Yield each date from *start* to *end* (inclusive, day granularity)."""
    current = start.date()
    stop    = end.date()
    while current <= stop:
        yield current
        current += timedelta(days=1)


def _list_trail_keys(s3, bucket: str, key_prefix: str, start: datetime, end: datetime) -> list[str]:
    """Return all .json.gz CloudTrail keys in *bucket* within the date range."""
    keys: list[str] = []
    # Normalise prefix — ensure trailing slash
    prefix_root = key_prefix.rstrip("/") + "/" if key_prefix else ""

    paginator = s3.get_paginator("list_objects_v2")
    for day in _iter_date_range(start, end):
        day_prefix = f"{prefix_root}{day.strftime('%Y/%m/%d')}/"
        for page in paginator.paginate(Bucket=bucket, Prefix=day_prefix):
            for obj in page.get("Contents", []):
                if obj["Key"].endswith(".json.gz"):
                    keys.append(obj["Key"])
    return keys


def _parse_s3_object(s3, bucket: str, key: str, api_calls: list[str]) -> list[TrailEvent]:
    """Download, decompress, and parse a single CloudTrail log file."""
    body = s3.get_object(Bucket=bucket, Key=key)["Body"].read()
    with gzip.GzipFile(fileobj=io.BytesIO(body)) as gz:
        records = json.loads(gz.read()).get("Records", [])

    if api_calls:
        records = [r for r in records if r.get("eventName") in api_calls]

    events: list[TrailEvent] = []
    for r in records:
        raw_time = r.get("eventTime", "")
        try:
            ev_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ev_time = datetime.now(timezone.utc)

        identity = r.get("userIdentity", {})
        username = identity.get("arn") or identity.get("userName") or identity.get("type", "")

        resources = [
            res.get("ARN", res.get("accountId", ""))
            for res in r.get("resources") or []
            if res.get("ARN") or res.get("accountId")
        ]

        events.append(TrailEvent(
            event_id      = r.get("eventID", ""),
            event_name    = r.get("eventName", ""),
            event_time    = ev_time,
            event_source  = r.get("eventSource", ""),
            username      = username,
            account_id    = r.get("recipientAccountId", ""),
            source_ip     = r.get("sourceIPAddress", ""),
            user_agent    = r.get("userAgent", ""),
            region        = r.get("awsRegion", ""),
            read_only     = r.get("readOnly", False) in (True, "true", "True"),
            resources     = resources,
            error_code    = r.get("errorCode", ""),
            error_message = r.get("errorMessage", ""),
        ))
    return events


def scan_s3(
    s3,
    usage_type: str,
    event_source: str,
    api_calls: list[str],
    start: datetime,
    end: datetime,
    bucket: str,
    key_prefix: str,
    max_events: int = 2000,
) -> ScanResult:
    """
    Scan CloudTrail logs stored in S3.

    Files are listed by date prefix, downloaded, decompressed, and parsed in
    parallel (up to 8 workers).  Events are filtered by *api_calls* if
    provided, otherwise all events for the period are returned.

    Args:
        s3:         boto3 ``s3`` client.
        bucket:     S3 bucket containing CloudTrail logs.
        key_prefix: Path prefix up to (but not including) the date component,
                    e.g. ``"AWSLogs/123456789012/CloudTrail/us-east-1"``.
        max_events: Upper bound on total events returned.
    """
    from standstill.aws.usage_type_map import _REGION_PREFIX_RE, get_usage_type_info

    base    = _REGION_PREFIX_RE.sub("", usage_type)
    info    = get_usage_type_info(base)
    service = info.service if info else usage_type

    keys = _list_trail_keys(s3, bucket, key_prefix, start, end)

    all_events: list[TrailEvent] = []
    with ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(_parse_s3_object, s3, bucket, key, api_calls)
            for key in keys
        ]
        for future in as_completed(futures):
            all_events.extend(future.result())
            if len(all_events) >= max_events:
                break

    # Deduplicate and sort
    seen: set[str] = set()
    unique: list[TrailEvent] = []
    for ev in sorted(all_events, key=lambda e: e.event_time, reverse=True):
        if ev.event_id not in seen:
            seen.add(ev.event_id)
            unique.append(ev)
            if len(unique) >= max_events:
                break

    return ScanResult(
        usage_type         = usage_type,
        service            = service,
        event_source       = event_source,
        api_calls_searched = api_calls,
        start              = start.isoformat(),
        end                = end.isoformat(),
        events             = unique,
    )


# ---------------------------------------------------------------------------
# CloudWatch Logs Insights backend
# ---------------------------------------------------------------------------

def scan_cloudwatch(
    logs,
    usage_type: str,
    event_source: str,
    api_calls: list[str],
    start: datetime,
    end: datetime,
    log_group: str,
    max_events: int = 2000,
    poll_interval: float = 2.0,
) -> ScanResult:
    """
    Scan CloudTrail logs stored in a CloudWatch Logs log group using
    Logs Insights.

    Args:
        logs:          boto3 ``logs`` client.
        log_group:     CloudWatch Logs log group name, e.g.
                       ``"/aws/cloudtrail/management-events"``.
        poll_interval: Seconds between status polls (default 2 s).
        max_events:    Limit passed to the Insights ``limit`` clause.
    """
    from standstill.aws.usage_type_map import _REGION_PREFIX_RE, get_usage_type_info

    base    = _REGION_PREFIX_RE.sub("", usage_type)
    info    = get_usage_type_info(base)
    service = info.service if info else usage_type

    # Build the Logs Insights query.
    fields = (
        "fields eventTime, eventName, eventSource, "
        "userIdentity.arn, sourceIPAddress, userAgent, "
        "awsRegion, readOnly, errorCode, errorMessage, eventID"
    )
    if api_calls:
        calls_str = ", ".join(f'"{c}"' for c in api_calls)
        filter_clause = f"| filter eventName in [{calls_str}]"
    else:
        filter_clause = f'| filter eventSource = "{event_source}"'

    query_string = (
        f"{fields}\n"
        f"{filter_clause}\n"
        f"| sort eventTime desc\n"
        f"| limit {min(max_events, 10000)}"
    )

    resp = logs.start_query(
        logGroupName = log_group,
        startTime    = int(start.timestamp()),
        endTime      = int(end.timestamp()),
        queryString  = query_string,
    )
    query_id = resp["queryId"]

    # Poll until complete.
    while True:
        status_resp = logs.get_query_results(queryId=query_id)
        status = status_resp["status"]
        if status in ("Complete", "Failed", "Cancelled"):
            if status != "Complete":
                raise RuntimeError(
                    f"CloudWatch Logs Insights query {status.lower()}. "
                    "Check log group name and IAM permissions."
                )
            break
        time.sleep(poll_interval)

    # Parse results into TrailEvents.
    def _field(row: list[dict], name: str) -> str:
        return next((f["value"] for f in row if f["field"] == name), "")

    events: list[TrailEvent] = []
    for row in status_resp.get("results", []):
        raw_time = _field(row, "eventTime")
        try:
            ev_time = datetime.fromisoformat(raw_time.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            ev_time = datetime.now(timezone.utc)

        events.append(TrailEvent(
            event_id      = _field(row, "eventID"),
            event_name    = _field(row, "eventName"),
            event_time    = ev_time,
            event_source  = _field(row, "eventSource"),
            username      = _field(row, "userIdentity.arn"),
            account_id    = "",
            source_ip     = _field(row, "sourceIPAddress"),
            user_agent    = _field(row, "userAgent"),
            region        = _field(row, "awsRegion"),
            read_only     = _field(row, "readOnly") in ("true", "True", "1"),
            resources     = [],
            error_code    = _field(row, "errorCode"),
            error_message = _field(row, "errorMessage"),
        ))

    return ScanResult(
        usage_type         = usage_type,
        service            = service,
        event_source       = event_source,
        api_calls_searched = api_calls,
        start              = start.isoformat(),
        end                = end.isoformat(),
        events             = events,
    )
