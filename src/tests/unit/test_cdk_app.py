"""Unit proofs for the Phase 07 CDK entrypoint scaffold.

Covers the contract from the Phase 07 breakdown task 1:
``deploy/aws/cdk/.env`` loading precedence (shell wins, file fills gaps,
comments/quotes handled, missing file is a no-op), the required-input
gate, ``FEEDNOW_ENV`` validation rejection, and the names derived from
the environment value object.
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path
from types import ModuleType

import pytest

CDK_DIR = Path(__file__).resolve().parents[3] / "deploy" / "aws" / "cdk"

REQUIRED_VARS = (
    "FEEDNOW_ENV",
    "CDK_DEFAULT_ACCOUNT",
    "AWS_REGION",
    "COGNITO_CALLBACK_URLS",
)


def _load_module(name: str, path: Path) -> ModuleType:
    """Import a CDK file under a fixed name without mutating the global ``sys.path``."""
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


# The stack module must be registered before app.py loads so that app.py's
# ``from feednow_auth_stack import ...`` resolves via the sys.modules cache
# (``app`` itself is imported under a unique name: it is the service package name).
stack_module = _load_module("feednow_auth_stack", CDK_DIR / "feednow_auth_stack.py")
cdk_app = _load_module("feednow_cdk_app", CDK_DIR / "app.py")
FeedNowAuthEnv = stack_module.FeedNowAuthEnv
FeedNowAuthStack = stack_module.FeedNowAuthStack


@pytest.fixture(autouse=True)
def _clean_inputs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Never inherit a developer's shell values for the required inputs."""
    for name in REQUIRED_VARS:
        monkeypatch.delenv(name, raising=False)


# --- .env loading precedence -------------------------------------------------


def test_load_cdk_env_does_not_override_shell(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("FEEDNOW_ENV=staging\n")
    monkeypatch.setenv("FEEDNOW_ENV", "dev")

    cdk_app.load_cdk_env(env_file)

    assert os.getenv("FEEDNOW_ENV") == "dev"


def test_load_cdk_env_fills_missing_and_strips_quotes(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# a comment\n"
        "\n"
        "NOT_A_PAIR\n"
        "FEEDNOW_ENV=prod\n"
        'CDK_DEFAULT_ACCOUNT="123456789012"\n'
        "AWS_REGION='eu-north-1'\n"
    )

    cdk_app.load_cdk_env(env_file)

    assert os.getenv("FEEDNOW_ENV") == "prod"
    assert os.getenv("CDK_DEFAULT_ACCOUNT") == "123456789012"
    assert os.getenv("AWS_REGION") == "eu-north-1"
    assert os.getenv("NOT_A_PAIR") is None


def test_load_cdk_env_missing_file_is_noop(tmp_path: Path) -> None:
    cdk_app.load_cdk_env(tmp_path / "absent.env")  # must not raise


def test_require_inputs_lists_every_missing_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FEEDNOW_ENV", "dev")

    with pytest.raises(SystemExit) as excinfo:
        cdk_app.require_inputs()

    message = str(excinfo.value)
    assert "CDK_DEFAULT_ACCOUNT" in message
    assert "AWS_REGION" in message
    assert "FEEDNOW_ENV" not in message


def test_require_inputs_returns_all_when_present(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("FEEDNOW_ENV", "dev")
    monkeypatch.setenv("CDK_DEFAULT_ACCOUNT", "123456789012")
    monkeypatch.setenv("AWS_REGION", "eu-north-1")
    monkeypatch.setenv("COGNITO_CALLBACK_URLS", "https://app.example.invalid/oauth/callback")

    assert cdk_app.require_inputs() == {
        "FEEDNOW_ENV": "dev",
        "CDK_DEFAULT_ACCOUNT": "123456789012",
        "AWS_REGION": "eu-north-1",
        "COGNITO_CALLBACK_URLS": "https://app.example.invalid/oauth/callback",
    }


# --- FEEDNOW_ENV validation ---------------------------------------------------


@pytest.mark.parametrize("name", ["dev", "staging", "prod"])
def test_env_accepts_the_three_environments(name: str) -> None:
    assert FeedNowAuthEnv(name).name == name


@pytest.mark.parametrize(
    "bad",
    ["", "qa", "Dev", "DEV", "development", "prod ", "prod\n", "preprod"],
)
def test_env_rejects_invalid_names(bad: str) -> None:
    with pytest.raises(ValueError, match="FEEDNOW_ENV must be one of"):
        FeedNowAuthEnv(bad)


def test_stack_construction_rejects_invalid_env_string() -> None:
    import aws_cdk as cdk

    app = cdk.App()
    with pytest.raises(ValueError, match="FEEDNOW_ENV must be one of"):
        FeedNowAuthStack(app, "whatever", feednow_env="qa")


# --- Derived naming -----------------------------------------------------------


@pytest.mark.parametrize(
    ("name", "stack_name", "resource_prefix", "cognito_domain_prefix"),
    [
        ("dev", "FeedNowAuth-dev", "feednow-auth-dev-", "feednow-auth-dev"),
        ("staging", "FeedNowAuth-staging", "feednow-auth-staging-", "feednow-auth-staging"),
        ("prod", "FeedNowAuth-prod", "feednow-auth-prod-", "feednow-auth-prod"),
    ],
)
def test_env_derives_all_names(
    name: str,
    stack_name: str,
    resource_prefix: str,
    cognito_domain_prefix: str,
) -> None:
    env = FeedNowAuthEnv(name)
    assert env.stack_name == stack_name
    assert env.resource_prefix == resource_prefix
    assert env.cognito_domain_prefix == cognito_domain_prefix


def test_stack_is_named_and_prefixed_from_env() -> None:
    import aws_cdk as cdk

    env = FeedNowAuthEnv("dev")
    app = cdk.App()
    stack = FeedNowAuthStack(
        app,
        env.stack_name,
        feednow_env=env,
        cognito_callback_urls=["https://app.example.invalid/oauth/callback"],
        env=cdk.Environment(account="123456789012", region="eu-north-1"),
    )

    assert stack.stack_name == "FeedNowAuth-dev"
    assert stack.table_prefix == "feednow-auth-dev-"
    assert stack.env.region == "eu-north-1"
