"""AWS infrastructure definition for feednow-auth.

``FeedNowAuthEnv`` validates the deployment environment and derives
environment-scoped names. ``FeedNowAuthStack`` imports user-provisioned
Cognito resources and creates DynamoDB tables, a KMS-encrypted pepper, the Lambda
runtime, and an HTTP API with redaction-safe access logs. Production data
resources use retention policies. See ``docs/operations.md`` for deployment
inputs and runtime behavior.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast
from urllib.parse import urlsplit

import aws_cdk as cdk
import jsii
from aws_cdk import BundlingOptions, ILocalBundling
from aws_cdk.aws_apigatewayv2 import CfnStage, HttpApi, HttpMethod
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration
from aws_cdk.aws_cognito import (
    UserPool,
    UserPoolClient,
)
from aws_cdk.aws_dynamodb import (
    Attribute,
    AttributeType,
    BillingMode,
    PointInTimeRecoverySpecification,
    ProjectionType,
    Table,
)
from aws_cdk.aws_iam import IPrincipal, IRole, PolicyStatement, Role, ServicePrincipal
from aws_cdk.aws_kms import Key, KeySpec, KeyUsage
from aws_cdk.aws_lambda import Architecture, Code, Function, IFunction, Runtime
from aws_cdk.aws_logs import LogGroup, RetentionDays
from constructs import Construct

VALID_ENVIRONMENTS = ("dev", "staging", "prod")

#: Runtime configuration keys injected into the Lambda. Duplicated rather than
#: imported:
#: the synth path (``requirements.txt``) carries no fastapi/boto3, so the
#: CDK app must not import ``deploy/aws/runtime/handler.py``.
#: ``test_cdk_lambda_api.py`` pins these against the handler's
#: ``REQUIRED_ENV_KEYS`` so the two can never drift.
LAMBDA_REGION_ENV: Final = "FEEDNOW_DYNAMODB_REGION"
LAMBDA_TABLE_PREFIX_ENV: Final = "FEEDNOW_TABLE_PREFIX"
LAMBDA_ISSUERS_ENV: Final = "FEEDNOW_COGNITO_ISSUERS"
LAMBDA_CLIENT_IDS_ENV: Final = "FEEDNOW_COGNITO_CLIENT_IDS"
LAMBDA_PEPPER_CIPHERTEXT_ENV: Final = "FEEDNOW_PEPPER_CIPHERTEXT_B64"
LAMBDA_COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV: Final = (
    "FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64"
)
LAMBDA_ENVIRONMENT_ENV: Final = "FEEDNOW_ENV"

#: The HTTP API stage the runtime is mounted on (matches ``handler.API_STAGE``
#: from task 5: no released Mangum accepts an ``api_stage`` keyword, so the
#: stage is a documented constant shared by both sides).
API_STAGE: Final = "$default"

#: Redaction-safe HTTP API access-log format (task 6): request id, http
#: method, path, status, and integration latency -- and nothing else. No
#: ``$context.requestHeader.*`` (the Authorization bearer token) and no
#: ``$context.requestQueryString`` token may ever appear, so credentials
#: and query parameters can never reach CloudWatch.
API_ACCESS_LOG_FORMAT: Final = (
    '{"requestId":"$context.requestId",'
    '"httpMethod":"$context.httpMethod",'
    '"path":"$context.path",'
    '"status":"$context.status",'
    '"integrationLatency":"$context.integrationLatency"}'
)


def parse_cognito_callback_urls(raw: Sequence[str] | str | None) -> tuple[str, ...]:
    """Normalize the ``FEEDNOW_COGNITO_CALLBACK_URLS`` input into an ordered URL tuple.

    Accepts either the raw comma-separated ``.env`` string or an already
    split sequence. Blank entries and surrounding whitespace are dropped and
    duplicates collapse while the given order is preserved.
    """
    values: tuple[str, ...] = (
        () if raw is None else ((raw,) if isinstance(raw, str) else tuple(raw))
    )
    entries = (url for value in values for url in value.split(","))
    return tuple(dict.fromkeys(url.strip() for url in entries if url.strip()))


@dataclass(frozen=True)
class _IndexSpec:
    """One global secondary index: name plus its key attribute names."""

    name: str
    partition_key: str
    sort_key: str


@dataclass(frozen=True)
class _TableSpec:
    """One table's name suffix, key schema (design choice 2's layout), and TTL.

    ``ttl_attribute`` (session) names a non-key numeric attribute
    DynamoDB should expire items on; it is ``None`` for every DynamoDB table.
    """

    name: str
    partition_key: str
    sort_key: str | None = None
    indexes: tuple[_IndexSpec, ...] = ()
    ttl_attribute: str | None = None


#: The table schema, transcribed verbatim from ``SCHEMA`` in
#: ``src/app/storage/dynamodb.py`` (see ``docs/storage.md``), plus the two
#: session tables, the additive ``users/by-email`` GSI (an access path for
#: the non-unique email lookup, never a constraint), and the additive
#: ``users/by-application-role`` GSI (``g_role`` = the ``application_role``
#: value the
#: runtime ``user_item`` codec writes on every path and the role transition
#: rewrites in lockstep — the index mirrors that write; a GSI add is online,
#: tables are never replaced). Duplicated
#: rather than imported on purpose: the synth path (``requirements.txt``)
#: carries no boto3, so the CDK app must not import the runtime adapter
#: module. ``test_cdk_dynamodb.py`` pins this copy against the runtime
#: ``SCHEMA`` (name + key schema + indexes) so the two can never drift.
_SCHEMA: Final[tuple[_TableSpec, ...]] = (
    _TableSpec(
        name="users",
        partition_key="pk",
        indexes=(
            _IndexSpec(name="by-email", partition_key="g_email", sort_key="pk"),
            _IndexSpec(name="by-application-role", partition_key="g_role", sort_key="pk"),
        ),
    ),
    _TableSpec(name="organizations", partition_key="pk"),
    _TableSpec(name="external_identities", partition_key="pk"),
    _TableSpec(name="audit_events", partition_key="pk"),
    _TableSpec(
        name="api_keys",
        partition_key="pk",
        indexes=(_IndexSpec(name="by-organization", partition_key="g_org", sort_key="g_created"),),
    ),
    _TableSpec(
        name="memberships",
        partition_key="organization_id",
        sort_key="user_id",
        indexes=(
            _IndexSpec(name="by-organization", partition_key="g_org", sort_key="g_created"),
            _IndexSpec(name="by-user", partition_key="g_user", sort_key="g_org_created"),
        ),
    ),
    _TableSpec(name="unique_constraints", partition_key="pk"),
    # Login-state and session stores, TTL-enabled on the
    # numeric ``expires_at_epoch`` attribute the task-7 adapter writes.
    _TableSpec(name="oauth_login_states", partition_key="pk", ttl_attribute="expires_at_epoch"),
    _TableSpec(name="app_sessions", partition_key="pk", ttl_attribute="expires_at_epoch"),
)

#: The actions the DynamoDB adapter performs *only* inside
#: ``TransactWriteItems`` (see ``docs/storage.md``), so
#: their grants are pinned with the ``dynamodb:EnclosingOperation``
#: condition and the role can never write outside a transaction.
#: ``UpdateItem`` and ``DeleteItem`` are unpinned because CAS updates,
#: membership changes, and administrator cleanup use standalone writes.
_TRANSACTIONAL_ACTIONS: Final[frozenset[str]] = frozenset({"PutItem", "ConditionCheckItem"})

#: The session/login-state tables are written by the runtime
#: adapter as *standalone* conditional operations (``put_item`` with
#: ``attribute_not_exists``, ``delete_item`` with ``attribute_exists``) and
#: read by ``get_item`` -- never inside ``TransactWriteItems``. Their grants
#: therefore carry no ``EnclosingOperation`` pin (pinning ``PutItem`` here
#: would deny the standalone write the adapter actually performs).
_STANDALONE_WRITE_TABLES: Final[frozenset[str]] = frozenset({"oauth_login_states", "app_sessions"})

#: Per-table runtime grant matrix. Global-administrator operations require
#: Scan and DeleteItem on application tables; these actions are granted only
#: on the environment's named table ARNs. No table-administration actions
#: (CreateTable/DeleteTable/DescribeTable) are granted to the runtime role.
_DYNAMODB_GRANTS: Final[Mapping[str, frozenset[str]]] = {
    # ``Query`` on users/by-email is authorized against both table and index ARN.
    "users": frozenset(
        {"GetItem", "PutItem", "UpdateItem", "DeleteItem", "Query", "ConditionCheckItem"}
    ),
    "organizations": frozenset(
        {
            "GetItem",
            "PutItem",
            "UpdateItem",
            "DeleteItem",
            "BatchGetItem",
            "Scan",
            "ConditionCheckItem",
        }
    ),
    "external_identities": frozenset({"PutItem", "DeleteItem", "Scan"}),
    "audit_events": frozenset({"PutItem", "DeleteItem", "Scan"}),
    "api_keys": frozenset({"GetItem", "PutItem", "DeleteItem", "UpdateItem", "Query", "Scan"}),
    "memberships": frozenset({"GetItem", "PutItem", "DeleteItem", "Query", "Scan"}),
    "unique_constraints": frozenset({"GetItem", "PutItem", "DeleteItem", "Scan"}),
    # Login states need conditional consume; sessions support admin cleanup.
    "oauth_login_states": frozenset({"PutItem", "DeleteItem"}),
    "app_sessions": frozenset({"GetItem", "PutItem", "DeleteItem", "Scan"}),
}


def _runtime_policy_statements(
    *,
    tables: Mapping[str, Table],
    pepper_kms_key_arn: str,
    environment: str,
    log_group_arn: str,
) -> list[PolicyStatement]:
    """One statement per matrix row for the Lambda execution role (implementation).

    Each table gets a non-transactional statement (point reads, the CAS
    ``UpdateItem``, the conditional ``DeleteItem``, base-table ``Query``)
    and, when the matrix lists them, a ``PutItem``/``ConditionCheckItem``
    statement pinned to ``TransactWriteItems``. The session session tables
    (:data:`_STANDALONE_WRITE_TABLES`) are the documented exception: their
    writes are standalone conditional operations, so all their actions are
    granted unpinned. Each GSI gets ``Query`` only. The pepper grant is
    ``kms:Decrypt`` on the environment's KMS key, restricted to its encryption
    context; the log grant is
    ``CreateLogStream``/``PutLogEvents`` on the function's log group ARN
    pattern -- nothing else, no wildcards anywhere.
    """
    statements: list[PolicyStatement] = []
    for spec in _SCHEMA:
        table_arn = tables[spec.name].table_arn
        granted = _DYNAMODB_GRANTS[spec.name]
        if spec.name in _STANDALONE_WRITE_TABLES:
            transactional: frozenset[str] = frozenset()
        else:
            transactional = granted & _TRANSACTIONAL_ACTIONS
        plain_actions = sorted(f"dynamodb:{action}" for action in granted - transactional)
        if plain_actions:
            statements.append(PolicyStatement(actions=plain_actions, resources=[table_arn]))
        transaction_actions = sorted(f"dynamodb:{action}" for action in transactional)
        if transaction_actions:
            statements.append(
                PolicyStatement(
                    actions=transaction_actions,
                    resources=[table_arn],
                    conditions={
                        "StringEquals": {"dynamodb:EnclosingOperation": "TransactWriteItems"}
                    },
                )
            )
        for index in spec.indexes:
            statements.append(
                PolicyStatement(
                    actions=["dynamodb:Query"],
                    resources=[f"{table_arn}/index/{index.name}"],
                )
            )
    statements.append(
        PolicyStatement(
            actions=["kms:Decrypt"],
            resources=[pepper_kms_key_arn],
            conditions={
                "StringEquals": {"kms:EncryptionContext:environment": environment}
            },
        )
    )
    statements.append(
        PolicyStatement(
            actions=["logs:CreateLogStream", "logs:PutLogEvents"],
            resources=[log_group_arn],
        )
    )
    return statements


def _project_root() -> Path:
    """Repository root, resolved from this module's location."""
    return Path(__file__).resolve().parents[3]


@jsii.implements(ILocalBundling)
class _LocalBundling:
    """Build the Linux x86_64 Python 3.13 Lambda payload without Docker.

    Modeled on Vispector's ``_LocalBundling`` (``deploy/aws/cdk`` of the
    vispector repo): ``uv`` installs the pinned payload requirements as
    manylinux wheels -- native extensions such as ``pydantic-core`` land as
    Lambda-platform binaries even when synthesis runs on macOS -- while the
    application code is copied in: every ``deploy/aws/runtime/*.py`` module
    at the bundle root (so ``handler.handler`` resolves) and ``src/app`` as
    ``app/`` (so the handler's ``from app...`` imports resolve). Returning
    ``True`` keeps CDK from ever invoking the Docker fallback declared in
    :func:`_runtime_lambda_code`, so synth needs no Docker.
    """

    def try_bundle(self, output_dir: str, *, image: object = None, **kwargs: object) -> bool:
        project_root = _project_root()
        out = Path(output_dir)

        for module in sorted((project_root / "deploy" / "aws" / "runtime").glob("*.py")):
            shutil.copy(module, out / module.name)
        shutil.copytree(
            project_root / "src" / "app",
            out / "app",
            dirs_exist_ok=True,
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )

        try:
            subprocess.run(
                [
                    "uv",
                    "pip",
                    "install",
                    "--python-version",
                    "3.13",
                    "--python-platform",
                    "x86_64-manylinux2014",
                    "--only-binary",
                    ":all:",
                    "-r",
                    str(project_root / "deploy" / "aws" / "lambda-requirements.txt"),
                    "--target",
                    str(out),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                "Lambda dependency installation failed:\n"
                f"{exc.stderr or exc.stdout or 'pip returned a non-zero exit status'}"
            ) from exc
        except FileNotFoundError as exc:
            raise RuntimeError("uv executable was not found while bundling the Lambda") from exc

        return True


def _runtime_lambda_code() -> Code:
    """The implementation asset bundle: runtime modules + ``app/`` + payload wheels.

    The asset source is the repository root (the bundling class selects the
    payload itself); the ``command`` is the Docker fallback that never runs
    while local bundling succeeds, kept only as documentation of the
    equivalent in-image build.
    """
    return Code.from_asset(
        str(_project_root()),
        bundling=BundlingOptions(
            # Mirrors the deployed runtime; only consulted if local
            # bundling is disabled (it is not -- ``local`` always wins).
            image=Runtime.PYTHON_3_13.bundling_image,
            platform="linux/amd64",
            command=[
                "bash",
                "-c",
                "pip install -r deploy/aws/lambda-requirements.txt -t /asset-output "
                "&& cp -au deploy/aws/runtime/. /asset-output/ "
                "&& cp -au src/app /asset-output/app",
            ],
            local=_LocalBundling(),
        ),
    )


@dataclass(frozen=True)
class FeedNowAuthEnv:
    """Validated deployment environment; the single source of derived names.

    ``name`` must be one of ``dev``, ``staging``, or ``prod`` exactly
    (case-sensitive). All stack and resource names come from this value so
    environments can never collide.
    """

    name: str

    def __post_init__(self) -> None:
        if self.name not in VALID_ENVIRONMENTS:
            msg = f"FEEDNOW_ENV must be one of {', '.join(VALID_ENVIRONMENTS)}; got {self.name!r}."
            raise ValueError(msg)

    @property
    def stack_name(self) -> str:
        """CloudFormation stack name, e.g. ``FeedNowAuth-dev``."""
        return f"FeedNowAuth-{self.name}"

    @property
    def resource_prefix(self) -> str:
        """Prefix for physical resource names, e.g. ``feednow-auth-dev-``.

        Matches the runtime ``table_prefix`` contract from DynamoDB: table
        names are ``<resource_prefix><table-name>``.
        """
        return f"feednow-auth-{self.name}-"

    @property
    def cognito_domain_prefix(self) -> str:
        """Cognito user pool domain prefix, e.g. ``feednow-auth-dev``."""
        return f"feednow-auth-{self.name}"

    @property
    def cognito_client_name(self) -> str:
        """Cognito app client name, e.g. ``feednow-auth-dev`` (implementation)."""
        return f"feednow-auth-{self.name}"

    @property
    def pepper_kms_alias(self) -> str:
        """Environment-specific KMS alias for encrypting the runtime pepper."""
        return f"alias/feednow-auth-{self.name}-api-pepper"

    @property
    def lambda_function_name(self) -> str:
        """Runtime Lambda function name, e.g. ``feednow-auth-dev`` (implementation).

        Fixed here because the implementation log grant is scoped to this
        function's log group ARN pattern.
        """
        return f"feednow-auth-{self.name}"

    @property
    def lambda_role_name(self) -> str:
        """Least-privilege Lambda execution role name (implementation), e.g.
        ``feednow-auth-dev-lambda``."""
        return f"feednow-auth-{self.name}-lambda"

    @property
    def http_api_name(self) -> str:
        """HTTP API name (implementation), e.g. ``feednow-auth-dev``."""
        return f"feednow-auth-{self.name}"


class FeedNowAuthStack(cdk.Stack):
    """Environment-bound data, identity, KMS, Lambda, and HTTP API stack."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        feednow_env: FeedNowAuthEnv | str,
        cognito_callback_urls: Sequence[str] | str | None = None,
        cognito_domain: str | None = None,
        account_origin: str | None = None,
        vispector_url: str | None = None,
        existing_user_pool_id: str | None = None,
        existing_client_id: str | None = None,
        **kwargs: object,
    ) -> None:
        resolved = (
            feednow_env if isinstance(feednow_env, FeedNowAuthEnv) else FeedNowAuthEnv(feednow_env)
        )
        super().__init__(scope, id, **kwargs)
        self.feednow_env = resolved
        # Resolved prefix for runtime wiring.
        self.table_prefix = resolved.resource_prefix
        origin = (account_origin or "").strip().rstrip("/")
        parsed_origin = urlsplit(origin)
        local_dev_origin = (
            resolved.name == "dev"
            and parsed_origin.scheme == "http"
            and parsed_origin.hostname in {"localhost", "127.0.0.1", "[::1]", "::1"}
            and existing_user_pool_id is not None
            and existing_client_id is not None
        )
        if (
            (parsed_origin.scheme != "https" and not local_dev_origin)
            or not parsed_origin.netloc
            or parsed_origin.path
            or parsed_origin.query
            or parsed_origin.fragment
        ):
            raise ValueError("ACCOUNT_ORIGIN is required and must be an HTTPS origin")
        self.account_origin = origin
        callback_urls = parse_cognito_callback_urls(cognito_callback_urls) or (
            f"{origin}/api/oauth/callback",
        )
        if any(
            (urlsplit(url).scheme != "https" and not (
                resolved.name == "dev"
                and existing_user_pool_id is not None
                and existing_client_id is not None
                and urlsplit(url).scheme == "http"
                and urlsplit(url).hostname in {"localhost", "127.0.0.1", "[::1]", "::1"}
            ))
            or not urlsplit(url).netloc
            for url in callback_urls
        ):
            raise ValueError(
                "FEEDNOW_COGNITO_CALLBACK_URLS entries must be HTTPS "
                "(dev import permits loopback HTTP)"
            )
        if not existing_user_pool_id or not existing_client_id:
            raise ValueError(
                "User-provisioned Cognito pool and client IDs are required for every environment"
            )
        self.cognito_callback_urls = callback_urls
        service_url = (vispector_url or "").strip()
        if service_url:
            parsed_service_url = urlsplit(service_url)
            if (
                parsed_service_url.scheme != "https"
                or not parsed_service_url.netloc
                or parsed_service_url.username is not None
                or parsed_service_url.password is not None
            ):
                raise ValueError("FEEDNOW_VISPECTOR_URL must be an absolute HTTPS URL")
        # Schema tables include login-state and session data. Names are
        # ``<resource_prefix><table-name>`` so the runtime ``table_prefix``
        # resolves every adapter access through these physical names.
        # Billing is on-demand everywhere; data lives on in prod, is retained
        # nowhere else; PITR guards prod only.
        removal_policy = (
            cdk.RemovalPolicy.RETAIN if resolved.name == "prod" else cdk.RemovalPolicy.DESTROY
        )
        self.tables: dict[str, Table] = {}
        for spec in _SCHEMA:
            table = Table(
                self,
                f"{spec.name}Table",
                table_name=f"{self.table_prefix}{spec.name}",
                partition_key=Attribute(name=spec.partition_key, type=AttributeType.STRING),
                sort_key=(
                    Attribute(name=spec.sort_key, type=AttributeType.STRING)
                    if spec.sort_key is not None
                    else None
                ),
                billing_mode=BillingMode.PAY_PER_REQUEST,
                removal_policy=removal_policy,
                # The session tables expire items on the
                # numeric ``expires_at_epoch`` attribute the task-7 adapter
                # writes (None elsewhere -> no TTL on core tables).
                time_to_live_attribute=spec.ttl_attribute,
                # PITR guards prod only (task 2); the bool shorthand is
                # deprecated in favour of the explicit specification.
                point_in_time_recovery_specification=(
                    PointInTimeRecoverySpecification(point_in_time_recovery_enabled=True)
                    if resolved.name == "prod"
                    else None
                ),
            )
            for index in spec.indexes:
                table.add_global_secondary_index(
                    index_name=index.name,
                    partition_key=Attribute(name=index.partition_key, type=AttributeType.STRING),
                    sort_key=Attribute(name=index.sort_key, type=AttributeType.STRING),
                    projection_type=ProjectionType.ALL,
                )
            self.tables[spec.name] = table

        # Cognito lifecycle and configuration are user-managed. Import only;
        # never create, replace, or mutate a pool/client as part of deployment.
        if not existing_user_pool_id or not existing_client_id:
            raise ValueError(
                "A user-provisioned Cognito pool and client are required for every environment"
            )
        self.user_pool = UserPool.from_user_pool_id(
            self, "ExistingCognitoUserPool", existing_user_pool_id
        )
        self.user_pool_client = UserPoolClient.from_user_pool_client_id(
            self, "ExistingCognitoClient", existing_client_id
        )
        self.cognito_trigger_function = None
        self.user_pool_domain = None
        configured_cognito_domain = (cognito_domain or "").strip().rstrip("/")
        if configured_cognito_domain:
            parsed_cognito_domain = urlsplit(configured_cognito_domain)
            if (
                parsed_cognito_domain.scheme != "https"
                or not parsed_cognito_domain.netloc
                or parsed_cognito_domain.path
                or parsed_cognito_domain.query
                or parsed_cognito_domain.fragment
                or parsed_cognito_domain.username is not None
                or parsed_cognito_domain.password is not None
            ):
                raise ValueError("FEEDNOW_COGNITO_DOMAIN must be an HTTPS origin")
            cognito_domain = configured_cognito_domain
        else:
            cognito_domain = cdk.Fn.join(
                "",
                [
                    f"https://{resolved.cognito_domain_prefix}.auth.",
                    self.region,
                    ".amazoncognito.com",
                ],
            )

        # Issuer for the runtime ``FEEDNOW_COGNITO_ISSUERS`` wiring (task 6):
        # the pool id is an unresolved token, so the URL is assembled with
        # Fn::Sub rather than Python string interpolation.
        self.cognito_issuer_url = cdk.Fn.sub(
            "https://cognito-idp.${region}.amazonaws.com/${pool_id}",
            {"region": self.region, "pool_id": self.user_pool.user_pool_id},
        )

        cdk.CfnOutput(self, "CognitoUserPoolId", value=self.user_pool.user_pool_id)
        cdk.CfnOutput(self, "CognitoIssuerUrl", value=self.cognito_issuer_url)
        cdk.CfnOutput(self, "CognitoClientId", value=self.user_pool_client.user_pool_client_id)

        # The operator encrypts the pepper with this key and supplies only the
        # ciphertext to Lambda configuration. Plaintext never enters CDK,
        # CloudFormation, SSM, or deployment files.
        self.pepper_kms_key = Key(
            self,
            "PepperKmsKey",
            alias=resolved.pepper_kms_alias,
            description=f"KMS key for the {resolved.name} API-key pepper",
            enable_key_rotation=True,
            key_spec=KeySpec.SYMMETRIC_DEFAULT,
            key_usage=KeyUsage.ENCRYPT_DECRYPT,
            removal_policy=removal_policy,
        )
        cdk.CfnOutput(self, "PepperKmsKeyArn", value=self.pepper_kms_key.key_arn)

        # The runtime execution role. No managed policies at all -- even
        # AWSLambdaBasicExecutionRole would wildcard the log group -- and
        # no table-admin actions: CloudFormation owns the tables, the
        # runtime only reads/writes items per the matrix.
        self.lambda_role = Role(
            self,
            "LambdaExecutionRole",
            role_name=resolved.lambda_role_name,
            # jsii's generated ServicePrincipal does not structurally
            # satisfy the IPrincipal Protocol for basedpyright (the jsii
            # interface wiring is dynamic); the double cast via object is
            # the documented workaround for the CDK Python interface types.
            assumed_by=cast(IPrincipal, cast(object, ServicePrincipal("lambda.amazonaws.com"))),
            description="Least-privilege runtime role for the feednow-auth Lambda.",
        )
        for statement in _runtime_policy_statements(
            tables=self.tables,
            pepper_kms_key_arn=self.pepper_kms_key.key_arn,
            environment=resolved.name,
            log_group_arn=self.format_arn(
                service="logs",
                resource="log-group",
                resource_name=f"/aws/lambda/{resolved.lambda_function_name}:*",
                # CloudFormation log-group ARNs join the resource and the
                # group name with ":", not the default "/".
                arn_format=cdk.ArnFormat.COLON_RESOURCE_NAME,
            ),
        ):
            self.lambda_role.add_to_policy(statement)

        # The runtime Lambda receives only the KMS ciphertext; plaintext is
        # decrypted under its environment-specific context on cold start.
        self.runtime_function = Function(
            self,
            "RuntimeFunction",
            function_name=resolved.lambda_function_name,
            runtime=Runtime.PYTHON_3_13,
            architecture=Architecture.X86_64,
            memory_size=512,
            timeout=cdk.Duration.seconds(30),
            handler="handler.handler",
            code=_runtime_lambda_code(),
            # Same jsii interface workaround as the ServicePrincipal cast
            # above: the concrete Role does not structurally satisfy IRole
            # for basedpyright.
            role=cast(IRole, cast(object, self.lambda_role)),
            environment={
                LAMBDA_REGION_ENV: self.region,
                LAMBDA_ENVIRONMENT_ENV: resolved.name,
                LAMBDA_TABLE_PREFIX_ENV: self.table_prefix,
                LAMBDA_ISSUERS_ENV: self.cognito_issuer_url,
                LAMBDA_CLIENT_IDS_ENV: self.user_pool_client.user_pool_client_id,
                LAMBDA_PEPPER_CIPHERTEXT_ENV: os.getenv(LAMBDA_PEPPER_CIPHERTEXT_ENV, ""),
                LAMBDA_COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV: os.getenv(
                    LAMBDA_COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV, ""
                ),
                "FEEDNOW_COGNITO_AUTHORIZE_URL": f"{cognito_domain}/oauth2/authorize",
                "FEEDNOW_COGNITO_TOKEN_ENDPOINT": f"{cognito_domain}/oauth2/token",
                "FEEDNOW_COGNITO_USERINFO_URL": f"{cognito_domain}/oauth2/userInfo",
                "FEEDNOW_OAUTH_REDIRECT_URL": callback_urls[0],
                "FEEDNOW_ALLOWED_RETURN_ORIGINS": origin,
                "FEEDNOW_SESSION_TTL_SECONDS": "1800",
                "FEEDNOW_COOKIE_SECURE": "true",
                **({"FEEDNOW_VISPECTOR_URL": service_url} if service_url else {}),
            },
        )

        # The public HTTP API (v2) on the $default stage. Both
        # routes proxy to the function with payload format 2.0 (what Mangum
        # reads); HttpLambdaIntegration attaches the API-to-Lambda invoke
        # permission per route, scoped to the function ARN and this API's
        # execute-api source ARN -- never a wildcard.
        self.http_api = HttpApi(
            self,
            "HttpApi",
            api_name=resolved.http_api_name,
            create_default_stage=True,
        )
        runtime_integration = HttpLambdaIntegration(
            "RuntimeLambdaIntegration",
            # ... and Function vs IFunction.
            cast(IFunction, cast(object, self.runtime_function)),
        )
        self.http_api.add_routes(
            path="/",
            methods=[HttpMethod.ANY],
            integration=runtime_integration,
        )
        self.http_api.add_routes(
            path="/{proxy+}",
            methods=[HttpMethod.ANY],
            integration=runtime_integration,
        )
        cdk.CfnOutput(self, "ApiEndpoint", value=self.http_api.api_endpoint)

        # Redaction-safe access logs: only the five tokens in
        # API_ACCESS_LOG_FORMAT are emitted -- no $context.requestHeader.*
        # (Authorization bearer tokens) and no $context.requestQueryString
        # ever reach CloudWatch.
        self.api_access_logs = LogGroup(
            self,
            "ApiAccessLogs",
            retention=RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.DESTROY,
        )
        default_stage = self.http_api.default_stage
        if default_stage is None:
            msg = "the HTTP API default stage was not created"
            raise RuntimeError(msg)
        stage_resource = default_stage.node.default_child
        if not isinstance(stage_resource, CfnStage):
            msg = "the HTTP API default stage is not a CloudFormation stage"
            raise RuntimeError(msg)
        stage_resource.access_log_settings = CfnStage.AccessLogSettingsProperty(
            destination_arn=self.api_access_logs.log_group_arn,
            format=API_ACCESS_LOG_FORMAT,
        )
