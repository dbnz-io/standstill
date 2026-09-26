"""Lightweight, append-only audit log of CLI invocations.

A security tool that mutates org-wide controls needs an auditable record of what
was run. Every invocation is written as one JSON line to ``~/.standstill/audit.log``
(override with ``STANDSTILL_AUDIT_LOG``). The log is centralized at the CLI
entry point so it is comprehensive by construction — it cannot silently omit a
mutation the way per-command wiring could.

Writing is best-effort: an auditing failure must never break the command.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

_DEFAULT_AUDIT_FILE = Path.home() / ".standstill" / "audit.log"


def audit_path() -> Path:
    """Resolve the audit-log path, honouring the STANDSTILL_AUDIT_LOG override."""
    override = os.environ.get("STANDSTILL_AUDIT_LOG")
    return Path(override) if override else _DEFAULT_AUDIT_FILE


def record_invocation(
    args: list[str],
    exit_code: int,
    profile: str | None = None,
    region: str | None = None,
    timestamp: str | None = None,
) -> None:
    """Append one JSON-lines audit record for a CLI invocation.

    Best-effort: any error (unwritable path, serialization issue) is swallowed so
    auditing never affects the command's outcome.
    """
    try:
        record = {
            "ts": timestamp or datetime.now(timezone.utc).isoformat(),
            "args": list(args),
            "exit_code": exit_code,
            "profile": profile,
            "region": region,
            "pid": os.getpid(),
        }
        path = audit_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except Exception:
        pass  # auditing must never break the command
