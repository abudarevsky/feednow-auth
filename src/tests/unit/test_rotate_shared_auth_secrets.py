from __future__ import annotations

import importlib.util
from pathlib import Path
from subprocess import CalledProcessError
from types import SimpleNamespace

import pytest


SCRIPT_PATH = (
    Path(__file__).resolve().parents[3]
    / "deploy"
    / "aws"
    / "rotate_shared_auth_secrets.py"
)
SPEC = importlib.util.spec_from_file_location("rotate_shared_auth_secrets", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _env_files(tmp_path: Path) -> tuple[Path, Path]:
    feednow = tmp_path / ".env.prod"
    vispector = tmp_path / "vispector.env"
    feednow.write_text(
        "FEEDNOW_ENV=prod\nAWS_ACCOUNT_ID=495599767705\n"
        "FEEDNOW_VISPECTOR_SERVICE_SECRET=old-shared\n"
    )
    vispector.write_text(
        "CDK_DEFAULT_ACCOUNT=495599767705\n"
        "FEEDNOW_SERVICE_SECRET=old-shared\n"
        "AUTH_CACHE_DIGEST_SECRET=old-digest\n"
        "FEEDNOW_SERVICE_SECRET_ROTATION_ID=old-rotation\n"
    )
    return feednow, vispector


def test_rotation_updates_shared_service_secret_and_independent_cache_digest(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feednow, vispector = _env_files(tmp_path)
    generated = iter(("new-shared", "new-independent-digest", "rotation-id"))
    monkeypatch.setattr(MODULE.secrets, "token_urlsafe", lambda _: next(generated))
    monkeypatch.setattr(MODULE.secrets, "token_hex", lambda _: next(generated))

    MODULE.rotate(feednow, vispector, environment="prod")

    feednow_values = dict(line.split("=", 1) for line in feednow.read_text().splitlines())
    vispector_values = dict(line.split("=", 1) for line in vispector.read_text().splitlines())
    assert feednow_values["FEEDNOW_VISPECTOR_SERVICE_SECRET"] == "new-shared"
    assert vispector_values["FEEDNOW_SERVICE_SECRET"] == "new-shared"
    assert vispector_values["AUTH_CACHE_DIGEST_SECRET"] == "new-independent-digest"
    assert vispector_values["FEEDNOW_SERVICE_SECRET_ROTATION_ID"].endswith("-rotation-id")
    assert (feednow.stat().st_mode & 0o777) == 0o600
    assert (vispector.stat().st_mode & 0o777) == 0o600


def test_rotation_rejects_cross_account_env_files_without_modifying_them(
    tmp_path: Path,
) -> None:
    feednow, vispector = _env_files(tmp_path)
    vispector.write_text(vispector.read_text().replace("495599767705", "111122223333"))
    before = (feednow.read_text(), vispector.read_text())

    with pytest.raises(ValueError, match="different AWS accounts"):
        MODULE.rotate(feednow, vispector, environment="prod")

    assert (feednow.read_text(), vispector.read_text()) == before


def test_remote_node_option_uses_existing_rotation_utility_and_syncs_envs(
    tmp_path: Path,
) -> None:
    feednow, vispector = _env_files(tmp_path)
    remote = tmp_path / "remote.env"
    remote.write_text("REMOTE_NODE_AUTH_KEY=old-auth\nREMOTE_NODE_CALLBACK_KEY=old-callback\n")
    MODULE.rotate(
        feednow,
        vispector,
        environment="prod",
        include_remote_node=True,
        remote_env=remote,
        remote_rotator=MODULE.workspace_paths("prod")[3],
    )

    vispector_values = dict(line.split("=", 1) for line in vispector.read_text().splitlines())
    remote_values = dict(line.split("=", 1) for line in remote.read_text().splitlines())
    assert vispector_values["REMOTE_NODE_AUTH_KEY"] == remote_values["REMOTE_NODE_AUTH_KEY"]
    assert vispector_values["REMOTE_NODE_CALLBACK_KEY"] == remote_values["REMOTE_NODE_CALLBACK_KEY"]
    assert vispector_values["REMOTE_NODE_AUTH_KEY"] != "old-auth"
    assert vispector_values["REMOTE_NODE_CALLBACK_KEY"] != "old-callback"
    assert (remote.stat().st_mode & 0o777) == 0o600


def test_remote_node_failure_restores_service_env_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    feednow, vispector = _env_files(tmp_path)
    remote = tmp_path / "remote.env"
    remote.write_text("REMOTE_NODE_AUTH_KEY=old-auth\nREMOTE_NODE_CALLBACK_KEY=old-callback\n")
    utility = tmp_path / "rotate_remote_node_keys.py"
    utility.touch()
    before = (feednow.read_text(), vispector.read_text(), remote.read_text())
    monkeypatch.setattr(MODULE.secrets, "token_urlsafe", lambda _: "new-shared")
    monkeypatch.setattr(MODULE.secrets, "token_hex", lambda _: "new-digest-or-id")

    def fail_after_partial_remote_update(command: list[str], **kwargs) -> None:
        remote.write_text("REMOTE_NODE_AUTH_KEY=partially-rotated\n")
        raise CalledProcessError(1, command)

    monkeypatch.setattr(MODULE.subprocess, "run", fail_after_partial_remote_update)

    with pytest.raises(CalledProcessError):
        MODULE.rotate(
            feednow,
            vispector,
            environment="prod",
            include_remote_node=True,
            remote_env=remote,
            remote_rotator=utility,
        )

    assert (feednow.read_text(), vispector.read_text(), remote.read_text()) == before


def test_main_is_read_only_without_update_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    feednow, vispector = _env_files(tmp_path)
    before = (feednow.read_text(), vispector.read_text())
    monkeypatch.setattr(
        MODULE,
        "parse_args",
        lambda: SimpleNamespace(env="prod", update=False, include_remote_node=False),
    )
    monkeypatch.setattr(
        MODULE,
        "workspace_paths",
        lambda _env: (feednow, vispector, tmp_path / "remote.env", tmp_path / "rotate.py"),
    )

    assert MODULE.main() == 0

    assert (feednow.read_text(), vispector.read_text()) == before
    assert "No files changed" in capsys.readouterr().out
