#!/usr/bin/env python3
"""Rotate FeedNow/Vispector local deployment credentials without deploying.

The shared service credential is written to FeedNow's owner-only, environment-specific CDK secrets file and Vispector's CDK file. Vispector's API-key cache digest secret is
rotated independently. Remote-node auth/callback keys can optionally be
rotated by invoking Vispector's established rotation utility.
"""

from __future__ import annotations

import argparse
import os
import secrets
import stat
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path


FEEDNOW_KEYS = ("FEEDNOW_VISPECTOR_SERVICE_SECRET",)
VISPECTOR_KEYS = (
    "FEEDNOW_SERVICE_SECRET",
    "AUTH_CACHE_DIGEST_SECRET",
    "FEEDNOW_SERVICE_SECRET_ROTATION_ID",
)


def workspace_paths(environment: str) -> tuple[Path, Path, Path, Path]:
    feednow_root = Path(__file__).resolve().parents[2]
    workspace_root = feednow_root.parent
    vispector_root = workspace_root / "vispector"
    feednow_env = feednow_root / "deploy" / "aws" / "cdk" / f".env.{environment}.secrets"
    vispector_env = vispector_root / "deploy" / "aws" / "cdk" / ".env"
    remote_env = vispector_root / "deploy" / "remote" / ".env"
    remote_rotator = vispector_root / "deploy" / "aws" / "cdk" / "rotate_remote_node_keys.py"
    return feednow_env, vispector_env, remote_env, remote_rotator


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--env",
        choices=("dev", "staging", "prod"),
        default="prod",
        help="FeedNow environment file to update (default: prod)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help=(
            "write newly generated credentials; without this option, only validate "
            "and report targets"
        ),
    )
    parser.add_argument(
        "--include-remote-node",
        "--remote-node",
        dest="include_remote_node",
        action="store_true",
        help="also rotate remote-node keys in Vispector CDK and deploy/remote/.env files",
    )
    return parser.parse_args()


def read_env(path: Path) -> tuple[str, dict[str, str]]:
    content = path.read_text(encoding="utf-8")
    values: dict[str, str] = {}
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key] = value
    return content, values


def validate_targets(
    feednow_env: Path,
    vispector_env: Path,
    *,
    remote_env: Path | None = None,
    remote_rotator: Path | None = None,
    environment: str,
) -> dict[Path, str]:
    feednow_config = (
        feednow_env.with_name(feednow_env.name.removesuffix(".secrets"))
        if feednow_env.name.endswith(".secrets")
        else feednow_env
    )
    paths = list(dict.fromkeys((feednow_config, feednow_env, vispector_env)))
    if remote_env is not None:
        paths.append(remote_env)
    if remote_rotator is not None and not remote_rotator.is_file():
        raise ValueError(f"remote-node rotation utility is missing: {remote_rotator}")

    contents: dict[Path, str] = {}
    parsed: dict[Path, dict[str, str]] = {}
    for path in paths:
        if not path.is_file():
            raise ValueError(f"dotenv file does not exist: {path}")
        content, values = read_env(path)
        contents[path] = content
        parsed[path] = values

    required = (
        (feednow_config, ("FEEDNOW_ENV", "AWS_ACCOUNT_ID")),
        (feednow_env, FEEDNOW_KEYS),
        (vispector_env, (*VISPECTOR_KEYS, "CDK_DEFAULT_ACCOUNT")),
    )
    if remote_env is not None:
        required += ((remote_env, ("REMOTE_NODE_AUTH_KEY", "REMOTE_NODE_CALLBACK_KEY")),)
    for path, names in required:
        missing = [name for name in names if name not in parsed[path] or not parsed[path][name]]
        if missing:
            raise ValueError(f"{path} is missing required settings: {', '.join(missing)}")

    feednow_values = parsed[feednow_config]
    vispector_values = parsed[vispector_env]
    if feednow_values["FEEDNOW_ENV"] != environment:
        raise ValueError(f"FEEDNOW_ENV in {feednow_config} does not match --env {environment}")
    if feednow_values["AWS_ACCOUNT_ID"] != vispector_values["CDK_DEFAULT_ACCOUNT"]:
        raise ValueError("FeedNow and Vispector environment files target different AWS accounts")
    return contents


def replace_env_values(content: str, updates: dict[str, str]) -> str:
    lines = content.splitlines(keepends=True)
    found: set[str] = set()
    result: list[str] = []
    for line in lines:
        key, separator, _ = line.partition("=")
        if separator and key in updates and not line.lstrip().startswith("#"):
            newline = "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""
            result.append(f"{key}={updates[key]}{newline}")
            found.add(key)
        else:
            result.append(line)
    missing = set(updates) - found
    if missing:
        raise ValueError(f"dotenv file is missing settings: {', '.join(sorted(missing))}")
    return "".join(result)


def write_atomically(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def rotate(
    feednow_env: Path,
    vispector_env: Path,
    *,
    environment: str,
    include_remote_node: bool = False,
    remote_env: Path | None = None,
    remote_rotator: Path | None = None,
) -> None:
    if include_remote_node and (remote_env is None or remote_rotator is None):
        raise ValueError("remote-node env and rotation utility paths are required")
    original_contents = validate_targets(
        feednow_env,
        vispector_env,
        remote_env=remote_env if include_remote_node else None,
        remote_rotator=remote_rotator if include_remote_node else None,
        environment=environment,
    )

    shared = secrets.token_urlsafe(48)
    cache_digest = secrets.token_hex(32)
    rotation_id = f"{environment}-{datetime.now(UTC):%Y%m%dT%H%M%SZ}-{secrets.token_hex(6)}"
    updates = {
        feednow_env: replace_env_values(
            original_contents[feednow_env], {"FEEDNOW_VISPECTOR_SERVICE_SECRET": shared}
        ),
        vispector_env: replace_env_values(
            original_contents[vispector_env],
            {
                "FEEDNOW_SERVICE_SECRET": shared,
                "AUTH_CACHE_DIGEST_SECRET": cache_digest,
                "FEEDNOW_SERVICE_SECRET_ROTATION_ID": rotation_id,
            },
        ),
    }

    try:
        for path, content in updates.items():
            write_atomically(path, content)
        if include_remote_node:
            assert remote_env is not None and remote_rotator is not None
            os.chmod(remote_env, 0o600)
            subprocess.run(
                [
                    sys.executable,
                    str(remote_rotator),
                    "--update",
                    "--env-file",
                    str(vispector_env),
                    "--env-file",
                    str(remote_env),
                ],
                check=True,
                text=True,
            )
    except BaseException:
        # Restore all participating files if the optional remote-node rotation
        # fails after either of its per-file atomic replacements.
        for path, original in original_contents.items():
            write_atomically(path, original)
        raise


def main() -> int:
    args = parse_args()
    feednow_env, vispector_env, remote_env, remote_rotator = workspace_paths(args.env)
    try:
        if args.update:
            rotate(
                feednow_env,
                vispector_env,
                environment=args.env,
                include_remote_node=args.include_remote_node,
                remote_env=remote_env,
                remote_rotator=remote_rotator,
            )
        else:
            validate_targets(
                feednow_env,
                vispector_env,
                environment=args.env,
                remote_env=remote_env if args.include_remote_node else None,
                remote_rotator=remote_rotator if args.include_remote_node else None,
            )
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        print(f"rotation failed: {error}", file=sys.stderr)
        return 1

    if not args.update:
        print("No files changed. Re-run with --update to rotate local deployment credentials.")
        return 0
    print("Rotated shared FeedNow/Vispector service credential and independent cache digest in:")
    print(f"- {feednow_env}")
    print(f"- {vispector_env}")
    if args.include_remote_node:
        print("Rotated remote-node auth and callback keys using Vispector's rotation utility.")
        print(f"- {remote_env}")
    print("No deployment was run. Secret values were not printed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
