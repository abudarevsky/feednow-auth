"""Offline tests for profile, environment, and secret-safe operator behavior."""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from botocore.exceptions import ClientError

OPERATOR_PATH = Path(__file__).resolve().parents[3] / "deploy" / "aws" / "feednow_aws_operator.py"
spec = importlib.util.spec_from_file_location("feednow_aws_operator", OPERATOR_PATH)
assert spec is not None and spec.loader is not None
operator = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = operator
spec.loader.exec_module(operator)


def _not_found() -> ClientError:
    return ClientError({"Error": {"Code": "ResourceNotFoundException"}}, "GetFunctionConfiguration")


def test_settings_are_selected_by_environment_and_reject_aws_credentials(tmp_path: Path) -> None:
    directory = tmp_path / "deploy" / "aws" / "cdk"
    directory.mkdir(parents=True)
    (directory / ".env.prod").write_text(
        "FEEDNOW_ENV=prod\nAWS_ACCOUNT_ID=123456789012\nAWS_REGION=eu-north-1\n"
    )
    assert operator.load_settings(tmp_path, "prod") == {
        "FEEDNOW_ENV": "prod",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-north-1",
    }
    with pytest.raises(SystemExit, match="Missing environment configuration"):
        operator.load_settings(tmp_path, "dev")
    (directory / ".env.prod").write_text(
        "FEEDNOW_ENV=prod\nAWS_ACCOUNT_ID=123456789012\nAWS_REGION=eu-north-1\nAWS_PROFILE=default\n"
    )
    with pytest.raises(SystemExit, match="AWS_PROFILE must not be stored"):
        operator.load_settings(tmp_path, "prod")


def test_aws_session_uses_the_named_profile_and_checks_the_account(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, Any] = {}

    class Process:
        stdout = json.dumps(
            {
                "AccessKeyId": "access-key",
                "SecretAccessKey": "secret-key",
                "SessionToken": "session-token",
            }
        )

    class Sts:
        def get_caller_identity(self) -> dict[str, str]:
            return {"Account": "123456789012"}

    class Session:
        def client(self, service: str) -> Sts:
            assert service == "sts"
            return Sts()

    def export_credentials(command: list[str], **kwargs: Any) -> Process:
        seen["command"] = command
        assert kwargs == {"check": True, "capture_output": True, "text": True}
        return Process()

    def make_session(**kwargs: str) -> Session:
        seen["session"] = kwargs
        return Session()

    monkeypatch.setattr(operator.subprocess, "run", export_credentials)
    monkeypatch.setattr(operator.boto3, "Session", make_session)
    settings = {
        "FEEDNOW_ENV": "prod",
        "AWS_ACCOUNT_ID": "123456789012",
        "AWS_REGION": "eu-north-1",
    }
    assert isinstance(operator.aws_session("work", settings), Session)
    assert seen == {
        "command": [
            "aws",
            "configure",
            "export-credentials",
            "--profile",
            "work",
            "--format",
            "process",
        ],
        "session": {
            "aws_access_key_id": "access-key",
            "aws_secret_access_key": "secret-key",
            "aws_session_token": "session-token",
            "region_name": "eu-north-1",
        },
    }
    with pytest.raises(SystemExit, match="AWS account mismatch"):
        operator.aws_session("work", {**settings, "AWS_ACCOUNT_ID": "999999999999"})


def _configured_root(tmp_path: Path, env: str) -> Path:
    directory = tmp_path / "deploy" / "aws" / "cdk"
    directory.mkdir(parents=True)
    (directory / f".env.{env}").write_text(
        f"FEEDNOW_ENV={env}\nAWS_ACCOUNT_ID=123456789012\nAWS_REGION=eu-north-1\n"
    )
    return tmp_path


def test_new_production_pepper_is_kms_encrypted_and_only_ciphertext_is_saved(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    class CloudFormation:
        def describe_stacks(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Stacks": [
                    {"Outputs": [{"OutputKey": "PepperKmsKeyArn", "OutputValue": "arn:key"}]}
                ]
            }

    class Lambda:
        def get_function_configuration(self, **kwargs: Any) -> dict[str, Any]:
            raise _not_found()

    class Kms:
        request: dict[str, Any] | None = None

        def encrypt(self, **kwargs: Any) -> dict[str, bytes]:
            self.request = kwargs
            return {"CiphertextBlob": b"encrypted-pepper"}

    class Session:
        kms = Kms()

        def client(self, service: str) -> Any:
            clients = {"cloudformation": CloudFormation(), "lambda": Lambda(), "kms": self.kms}
            return clients[service]

    session = Session()
    root = _configured_root(tmp_path, "prod")
    operator.ensure_pepper_ciphertext(session, root, "prod")
    assert session.kms.request is not None
    assert session.kms.request["KeyId"] == "arn:key"
    assert len(session.kms.request["Plaintext"]) >= 32
    assert session.kms.request["EncryptionContext"] == {"environment": "prod"}
    saved = (root / "deploy/aws/cdk/.env.prod").read_text()
    encoded = base64.b64encode(b"encrypted-pepper").decode()
    assert f"FEEDNOW_PEPPER_CIPHERTEXT_B64={encoded}" in saved
    assert session.kms.request["Plaintext"].decode() not in saved
    assert session.kms.request["Plaintext"].decode() not in capsys.readouterr().out


def test_dev_pepper_is_migrated_from_legacy_source_without_writing_plaintext(
    tmp_path: Path,
) -> None:
    legacy_pepper = "legacy-development-pepper-value-that-is-long-enough"

    class CloudFormation:
        def describe_stacks(self, **kwargs: Any) -> dict[str, Any]:
            return {
                "Stacks": [
                    {"Outputs": [{"OutputKey": "PepperKmsKeyArn", "OutputValue": "arn:key"}]}
                ]
            }

    class Lambda:
        def get_function_configuration(self, **kwargs: Any) -> dict[str, Any]:
            raise _not_found()

    class SecretsManager:
        def get_secret_value(self, **kwargs: Any) -> dict[str, str]:
            return {"SecretString": json.dumps({"pepper": legacy_pepper})}

    class Kms:
        request: dict[str, Any] | None = None

        def encrypt(self, **kwargs: Any) -> dict[str, bytes]:
            self.request = kwargs
            return {"CiphertextBlob": b"dev-cipher"}

    class Session:
        kms = Kms()

        def client(self, service: str) -> Any:
            return {
                "cloudformation": CloudFormation(),
                "lambda": Lambda(),
                "secretsmanager": SecretsManager(),
                "kms": self.kms,
            }[service]

    root = _configured_root(tmp_path, "dev")
    session = Session()
    operator.ensure_pepper_ciphertext(session, root, "dev")
    assert session.kms.request is not None
    assert session.kms.request["Plaintext"] == legacy_pepper.encode()
    assert legacy_pepper not in (root / "deploy/aws/cdk/.env.dev").read_text()
