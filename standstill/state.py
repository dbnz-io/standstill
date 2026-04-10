from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

import boto3
from botocore.exceptions import ClientError, ProfileNotFound


@dataclass
class AppState:
    profile: Optional[str] = None
    region: Optional[str] = None
    output: str = "table"

    def __post_init__(self) -> None:
        self._session: Optional[boto3.Session] = None

    def reset(self) -> None:
        self._session = None

    @property
    def effective_profile(self) -> Optional[str]:
        """--profile flag takes precedence; fall back to the saved config profile."""
        if self.profile:
            return self.profile
        from standstill.config import get_profile
        return get_profile()

    @property
    def management_role_arn(self) -> Optional[str]:
        from standstill.config import get_management_role
        return get_management_role()

    def session(self) -> boto3.Session:
        if self._session is None:
            kwargs: dict = {}
            if self.effective_profile:
                kwargs["profile_name"] = self.effective_profile
            if self.region:
                kwargs["region_name"] = self.region
            try:
                base_session = boto3.Session(**kwargs)
            except ProfileNotFound as e:
                raise RuntimeError(f"AWS profile not found: {e}") from e

            role_arn = self.management_role_arn
            if role_arn:
                sts = base_session.client("sts", region_name=self.region or "us-east-1")
                try:
                    resp = sts.assume_role(
                        RoleArn=role_arn,
                        RoleSessionName=f"standstill-{os.getpid()}",
                    )
                    creds = resp["Credentials"]
                    self._session = boto3.Session(
                        aws_access_key_id=creds["AccessKeyId"],
                        aws_secret_access_key=creds["SecretAccessKey"],
                        aws_session_token=creds["SessionToken"],
                        region_name=self.region,
                    )
                except ClientError as e:
                    raise RuntimeError(
                        f"Failed to assume management role {role_arn}: "
                        f"{e.response['Error']['Message']}"
                    ) from e
            else:
                self._session = base_session

        return self._session

    def get_client(self, service: str, **kwargs):
        session = self.session()
        client_kwargs: dict = {**kwargs}
        if self.region and "region_name" not in client_kwargs:
            client_kwargs["region_name"] = self.region
        return session.client(service, **client_kwargs)


# Module-level singleton shared across all commands
state = AppState()
