from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

_STACK_NAME_RE = re.compile(r"^[a-zA-Z][-a-zA-Z0-9]{0,127}$")
_CAPABILITY_VALUES = {"CAPABILITY_IAM", "CAPABILITY_NAMED_IAM", "CAPABILITY_AUTO_EXPAND"}
_MAX_TEMPLATE_BYTES = 51_200


class BlueprintStack(BaseModel):
    stack_name: str
    template_file: Optional[str] = None      # path relative to blueprint file
    template: Optional[str] = None           # inline body (mutually exclusive with template_file)
    region: Optional[str] = None             # None = inherit CLI --region
    capabilities: list[str] = Field(default_factory=list)
    parameters: dict[str, str] = Field(default_factory=dict)
    tags: dict[str, str] = Field(default_factory=dict)
    termination_protection: bool = True      # default on for foundation stacks

    @field_validator("stack_name")
    @classmethod
    def _stack_name(cls, v: str) -> str:
        if not _STACK_NAME_RE.match(v):
            raise ValueError(
                f"stack_name '{v}' is invalid. Must start with a letter, "
                "contain only letters, digits, or hyphens, and be at most 128 characters."
            )
        return v

    @field_validator("capabilities", mode="before")
    @classmethod
    def _capabilities(cls, v: list | None) -> list[str]:
        result = [str(c).upper() for c in (v or [])]
        for c in result:
            if c not in _CAPABILITY_VALUES:
                raise ValueError(
                    f"Invalid capability '{c}'. Must be one of: "
                    f"{', '.join(sorted(_CAPABILITY_VALUES))}"
                )
        return result

    @model_validator(mode="after")
    def _template_xor(self) -> "BlueprintStack":
        if self.template_file is None and self.template is None:
            raise ValueError(
                f"Stack '{self.stack_name}': either 'template_file' or 'template' must be provided."
            )
        if self.template_file is not None and self.template is not None:
            raise ValueError(
                f"Stack '{self.stack_name}': 'template_file' and 'template' are mutually exclusive."
            )
        return self


class Blueprint(BaseModel):
    name: str
    version: str = "1"
    description: str = ""
    stacks: list[BlueprintStack] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Blueprint name must not be empty.")
        return v

    @field_validator("stacks")
    @classmethod
    def _stacks_not_empty(cls, v: list) -> list:
        if not v:
            raise ValueError("Blueprint must contain at least one stack.")
        return v


def load_blueprint(path: Path) -> Blueprint:
    """
    Load and validate a blueprint YAML file.

    Resolves all template_file references relative to the blueprint file's directory
    and checks template size at load time — not at deploy time — so that 'validate'
    and '--dry-run' catch missing or oversized templates early.

    Raises:
        FileNotFoundError — blueprint file or a referenced template_file not found.
        ValueError         — YAML is empty, schema validation fails, or a template exceeds
                             the CloudFormation 51,200-byte inline limit.
    """
    if not path.exists():
        raise FileNotFoundError(f"Blueprint file not found: {path}")
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not raw:
        raise ValueError("Blueprint file is empty.")
    try:
        bp = Blueprint.model_validate(raw)
    except ValidationError as exc:
        raise ValueError(f"Blueprint validation failed:\n{exc}") from exc

    blueprint_dir = path.parent
    for stack in bp.stacks:
        if stack.template_file is not None:
            tpl_path = blueprint_dir / stack.template_file
            if not tpl_path.exists():
                raise FileNotFoundError(
                    f"Stack '{stack.stack_name}': template_file not found: {tpl_path}"
                )
            body = tpl_path.read_text(encoding="utf-8")
            if len(body.encode("utf-8")) > _MAX_TEMPLATE_BYTES:
                raise ValueError(
                    f"Stack '{stack.stack_name}': template exceeds the CloudFormation "
                    f"51,200-byte inline limit ({len(body.encode('utf-8'))} bytes). "
                    "Split the template into nested stacks or reduce its size."
                )

    return bp
