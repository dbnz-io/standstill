from __future__ import annotations

import re

from pydantic import BaseModel, field_validator

_CONTROL_ARN_RE = re.compile(r"^arn:aws[^:]*:controltower:[^:]+::\S+$")
_OU_ID_RE = re.compile(r"^ou-[a-z0-9]+-[a-z0-9]+$")


class ControlTarget(BaseModel):
    ou_id: str
    controls: list[str]

    @field_validator("ou_id")
    @classmethod
    def validate_ou_id(cls, v: str) -> str:
        if not _OU_ID_RE.match(v):
            raise ValueError(
                f"Invalid OU ID '{v}'. Expected format: ou-<root>-<id> (e.g. ou-ab12-34cd5678)"
            )
        return v

    @field_validator("controls")
    @classmethod
    def validate_control_arns(cls, v: list[str]) -> list[str]:
        bad = [arn for arn in v if not _CONTROL_ARN_RE.match(arn)]
        if bad:
            raise ValueError(f"Invalid control ARN(s): {', '.join(bad)}")
        return v


class ApplyConfig(BaseModel):
    version: str = "1"
    targets: list[ControlTarget]
