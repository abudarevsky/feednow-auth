"""Non-production deployed smoke test for the feednow-auth runtime (Phase 07 task 7).

Proves, against a **deployed** stack (not local fakes), the Phase 07 §5/§6
proof path end to end: a Cognito-authenticated request resolves to an
internal ``usr_`` identity, and first-login provisioning persisted the user
plus its default organization membership server-side.

Prerequisite
    A deployed dev (or staging) stack from Phase 07 task 6 — the Lambda +
    HTTP API wired to the task-3 Cognito pool and the task-2 DynamoDB tables,
    e.g. (from ``deploy/aws/cdk``)::

        FEEDNOW_ENV=dev COGNITO_CALLBACK_URLS=... npx -y aws-cdk@2 deploy FeedNowAuth-dev

Inputs (stack outputs / console values — names and ids only, never secret
material; operator credentials need Cognito data-plane calls and reads on the
prefixed tables):

    --env            dev | staging (``prod`` is refused unless --force is given)
    --region         deployment region, e.g. ``eu-north-1``
    --user-pool-id   ``CognitoUserPoolId`` stack output
    --client-id      ``CognitoClientId`` stack output
    --api-url        ``feednow-auth-<env>`` HTTP API endpoint (``$default`` stage),
                     e.g. ``https://<api-id>.execute-api.<region>.amazonaws.com``
    --table-prefix   the stack's ``table_prefix``, i.e. ``feednow-auth-<env>-``

Run (from the repository root, operator AWS credentials in the environment)::

    PYTHONPATH=. python deploy/aws/smoke/smoke.py \
        --env dev --region eu-north-1 \
        --user-pool-id eu-north-1_XXXXXXXXX --client-id XXXXXXXXXXXXXXX \
        --api-url https://<api-id>.execute-api.eu-north-1.amazonaws.com \
        --table-prefix feednow-auth-dev-

Proof path (executed in exactly this order):

    1. ``sign_up`` a random throwaway user ``smoke+<ts>@example.com`` with a
       freshly generated password.
    2. ``admin_confirm_sign_up`` so the pool marks the email verified.
    3. ``initiate_auth`` with ``USER_PASSWORD_AUTH`` to obtain an access token.
    4. ``GET https://<api>/v1/me`` with the bearer token: HTTP 200 and the
       ``MeResponse`` body's user id starts with ``usr_`` (the payload carries
       only user fields — organization data is deliberately **not** asserted
       over HTTP; it is proven in the tables below).
    5. ``GetItem`` on ``<prefix>unique_constraints`` for
       ``external_identity#cognito#<sub>#`` — the identity-tuple guard written
       by provisioning, whose ``user_id`` must match the ``/v1/me`` id.
    6. ``GetItem`` on ``<prefix>users`` for that mapped ``usr_`` id.
    7. ``Query`` on the ``<prefix>memberships`` ``by-user`` GSI keyed by the
       ``usr_`` id to resolve the ``organization_id`` (no earlier step yields
       it) — exactly one default-tenancy row.
    8. ``GetItem`` the ``(organization_id, user_id)`` membership pair on the
       base table — active, role ``owner``.

Safety contract
    * Refuses ``prod`` unless an explicit ``--force`` flag is passed.
    * Prints **only** ids (Cognito sub, ``usr_``/``org_``/``mem_``) and a
      pass line — never tokens, passwords, or key material; failures carry
      fixed messages without echoed values.
    * The seams (:func:`default_cognito_client`, :func:`default_http_get`,
      :func:`default_dynamodb_resource`) are injectable so the whole proof
      path is unit-testable against fakes (see
      ``src/tests/unit/test_smoke_script.py``).
"""

from __future__ import annotations

import argparse
import json
import secrets
import string
import sys
import time
import urllib.error
import urllib.request
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

import boto3
from boto3.dynamodb.conditions import Key

#: Environments accepted by ``--env``; ``prod`` is guarded by ``--force``.
ALLOWED_ENVIRONMENTS: Final = ("dev", "staging", "prod")
PROD_ENV: Final = "prod"

#: The provider label in the ``external_identity`` constraint key (§6 schema).
COGNITO_PROVIDER: Final = "cognito"

#: Internal application identity prefix the ``/v1/me`` body must carry.
USER_ID_PREFIX: Final = "usr_"

#: Throwaway sign-up domain and password policy floor (Cognito default pool
#: policy: >= 8 chars with upper/lower/digit/symbol; we generate 24).
SMOKE_EMAIL_DOMAIN: Final = "example.com"
PASSWORD_LENGTH: Final = 24
_PASSWORD_SYMBOLS: Final = "!@#$%^&*"

#: Seconds before an HTTP call to the deployed API is declared failed.
HTTP_TIMEOUT_SECONDS: Final = 30


class SmokeError(RuntimeError):
    """A smoke step failed. Messages never echo tokens, passwords, or values."""


class ProdNotForcedError(SmokeError):
    """``--env prod`` was requested without the explicit ``--force`` flag."""


@dataclass(frozen=True)
class SmokeConfig:
    """Everything the proof path needs from the operator (ids, no secrets)."""

    env: str
    region: str
    user_pool_id: str
    client_id: str
    api_base_url: str
    table_prefix: str


@dataclass(frozen=True)
class SmokeResult:
    """The only facts the script surfaces — all of them safe ids."""

    cognito_sub: str
    user_id: str
    organization_id: str
    membership_id: str


def guard_environment(env: str, *, force: bool) -> None:
    """Refuse ``prod`` unless ``force`` — this script is non-production only."""
    if env == PROD_ENV and not force:
        msg = (
            "refusing to run the smoke path against prod: it signs up a real "
            "user and provisions a throwaway organization; pass --force to override"
        )
        raise ProdNotForcedError(msg)


def generate_password() -> str:
    """Mint a random Cognito-policy-compliant password (never printed)."""
    classes = (
        string.ascii_uppercase,
        string.ascii_lowercase,
        string.digits,
        _PASSWORD_SYMBOLS,
    )
    rng = secrets.SystemRandom()
    alphabet = "".join(classes)
    chars = [rng.choice(cls) for cls in classes]
    chars.extend(rng.choice(alphabet) for _ in range(PASSWORD_LENGTH - len(chars)))
    rng.shuffle(chars)
    return "".join(chars)


def _field(payload: Mapping[str, Any], name: str, *, context: str) -> Any:
    """One required response field, or a fixed failure message naming nothing."""
    value = payload.get(name)
    if value is None or value == "":
        raise SmokeError(f"{context} returned no {name}")
    return value


def _item(response: Mapping[str, Any], *, context: str) -> dict[str, Any]:
    """A DynamoDB ``GetItem`` item, or a failure that the row was not persisted."""
    item = response.get("Item")
    if not isinstance(item, dict):
        raise SmokeError(f"{context}: expected item is missing server-side")
    return item


def run_smoke(
    config: SmokeConfig,
    *,
    cognito_client: Callable[[str], Any] | None = None,
    http_get: Callable[[str, Mapping[str, str]], tuple[int, dict[str, Any]]] | None = None,
    dynamodb_resource: Callable[[str], Any] | None = None,
    force: bool = False,
) -> SmokeResult:
    """Execute the §5/§6 proof path and print only ids plus a pass line.

    The three seams are injectable for tests; ``None`` binds the real
    boto3/urllib defaults. The environment guard runs before any seam is
    touched, so a refused prod run performs zero AWS calls.
    """
    guard_environment(config.env, force=force)
    client_factory = cognito_client or default_cognito_client
    get_json = http_get or default_http_get
    resource_factory = dynamodb_resource or default_dynamodb_resource

    email = f"smoke+{time.time_ns()}@{SMOKE_EMAIL_DOMAIN}"
    password = generate_password()

    # 1-3: Cognito identity — sign up, confirm, exchange credentials for a token.
    cognito = client_factory(config.region)
    sign_up = cognito.sign_up(
        UserPoolId=config.user_pool_id,
        ClientId=config.client_id,
        Username=email,
        Password=password,
        AttributeList=[{"Name": "email", "Value": email}],
    )
    sub = str(_field(sign_up, "UserSub", context="sign_up"))

    cognito.admin_confirm_sign_up(UserPoolId=config.user_pool_id, Username=email)

    auth = cognito.initiate_auth(
        ClientId=config.client_id,
        AuthFlow="USER_PASSWORD_AUTH",
        AuthParameters={"USERNAME": email, "PASSWORD": password},
    )
    auth_result = auth.get("AuthenticationResult", {})
    access_token = str(_field(auth_result, "AccessToken", context="initiate_auth"))

    # 4: the deployed API resolves the token to an internal usr_ identity.
    url = f"{config.api_base_url.rstrip('/')}/v1/me"
    status, body = get_json(url, {"Authorization": f"Bearer {access_token}"})
    if status != 200:
        raise SmokeError(f"GET /v1/me returned HTTP {status}, expected 200")
    user_id = _field(body, "id", context="GET /v1/me")
    if not isinstance(user_id, str) or not user_id.startswith(USER_ID_PREFIX):
        raise SmokeError("GET /v1/me did not return an internal usr_ identity")

    # 5-8: the same truth persisted server-side by first-login provisioning.
    dynamodb = resource_factory(config.region)
    constraints = dynamodb.Table(f"{config.table_prefix}unique_constraints")
    identity_guard = _item(
        constraints.get_item(
            Key={"pk": f"external_identity#{COGNITO_PROVIDER}#{sub}#"},
            ConsistentRead=True,
        ),
        context="unique_constraints external_identity item",
    )
    if _field(identity_guard, "user_id", context="external_identity constraint item") != user_id:
        raise SmokeError("external_identity constraint maps to a different user than /v1/me")

    users = dynamodb.Table(f"{config.table_prefix}users")
    _item(
        users.get_item(Key={"pk": user_id}, ConsistentRead=True),
        context="users item",
    )

    memberships = dynamodb.Table(f"{config.table_prefix}memberships")
    rows = memberships.query(
        IndexName="by-user",
        KeyConditionExpression=Key("g_user").eq(user_id),
    ).get("Items", [])
    if not isinstance(rows, list) or len(rows) != 1:
        raise SmokeError("by-user membership query did not return exactly one default org")
    row = rows[0]
    organization_id = str(_field(row, "organization_id", context="by-user membership row"))

    pair = _item(
        memberships.get_item(
            Key={"organization_id": organization_id, "user_id": user_id},
            ConsistentRead=True,
        ),
        context="memberships base-table pair",
    )
    if _field(pair, "role", context="membership pair") != "owner":
        raise SmokeError("default membership is not owner")
    if _field(pair, "status", context="membership pair") != "active":
        raise SmokeError("default membership is not active")

    result = SmokeResult(
        cognito_sub=sub,
        user_id=user_id,
        organization_id=organization_id,
        membership_id=str(_field(row, "id", context="by-user membership row")),
    )
    print(f"cognito_sub={result.cognito_sub}")
    print(f"user_id={result.user_id}")
    print(f"organization_id={result.organization_id}")
    print(f"membership_id={result.membership_id}")
    print(f"SMOKE PASS env={config.env}")
    return result


# ---------------------------------------------------------------------------
# Real seams (operator credentials from the standard AWS chain).
# ---------------------------------------------------------------------------


def default_cognito_client(region: str) -> Any:
    """A boto3 Cognito IDP client for the deployed user pool."""
    return boto3.client("cognito-idp", region_name=region)


def default_dynamodb_resource(region: str) -> Any:
    """A boto3 DynamoDB resource for the prefixed application tables."""
    return boto3.resource("dynamodb", region_name=region)


def default_http_get(url: str, headers: Mapping[str, str]) -> tuple[int, dict[str, Any]]:
    """One GET returning ``(status, json-body-dict)``; non-2xx is data, not a crash.

    The body is parsed best-effort so the caller can assert the status code;
    a non-object payload degrades to ``{}`` — never an echoed response body.
    """
    request = urllib.request.Request(url, headers=dict(headers))
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            status, payload = int(response.status), response.read()
    except urllib.error.HTTPError as error:
        status, payload = int(error.code), error.read()
    try:
        body = json.loads(payload)
    except (json.JSONDecodeError, UnicodeDecodeError):
        body = None
    if not isinstance(body, dict):
        body = {}
    return status, body


def build_parser() -> argparse.ArgumentParser:
    """CLI surface: deployment ids plus the prod ``--force`` guard."""
    parser = argparse.ArgumentParser(
        prog="smoke",
        description="Non-production deployed smoke for feednow-auth (see module docstring).",
    )
    parser.add_argument("--env", required=True, choices=ALLOWED_ENVIRONMENTS)
    parser.add_argument("--region", required=True)
    parser.add_argument("--user-pool-id", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--table-prefix", required=True)
    parser.add_argument(
        "--force",
        action="store_true",
        help="allow --env prod (explicit override; prefer dev/staging)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse inputs, run the proof path, map failures to a nonzero exit code."""
    args = build_parser().parse_args(argv)
    config = SmokeConfig(
        env=args.env,
        region=args.region,
        user_pool_id=args.user_pool_id,
        client_id=args.client_id,
        api_base_url=args.api_url,
        table_prefix=args.table_prefix,
    )
    try:
        run_smoke(config, force=args.force)
    except SmokeError as error:
        print(f"SMOKE FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
