"""FeedNowAuth CDK stack module.

Exposes the :class:`FeedNowAuthEnv` value object that validates the
``FEEDNOW_ENV`` deployment input and derives every environment-bound name
from it, plus the :class:`FeedNowAuthStack` class. Phase 07 task 2 adds the
seven DynamoDB tables (transcribed verbatim from ``SCHEMA`` in
``src/app/storage/dynamodb.py``); task 3 adds the Cognito user pool, the
public PKCE app client, and the hosted domain; task 4 adds the generated
API-key pepper secret and the least-privilege Lambda execution role (the
consolidated IAM matrix from docs/phases/06-dynamodb.md); task 6 adds the
runtime Lambda (Docker-free local bundling of ``deploy/aws/runtime`` +
``src/app`` + the payload requirements), the HTTP API on the ``$default``
stage, and the redaction-safe access logs. The remaining resources are
added by the later Phase 07 tasks; naming is fixed here so every task
synthesizes against the same environment contract.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

import aws_cdk as cdk
import jsii
from aws_cdk import BundlingOptions, ILocalBundling
from aws_cdk.aws_apigatewayv2 import CfnStage, HttpApi, HttpMethod
from aws_cdk.aws_apigatewayv2_integrations import HttpLambdaIntegration
from aws_cdk.aws_cognito import (
    AccountRecovery,
    AuthFlow,
    CognitoDomainOptions,
    OAuthFlows,
    OAuthScope,
    OAuthSettings,
    SignInAliases,
    UserPool,
    UserPoolClient,
    UserPoolDomain,
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
from aws_cdk.aws_lambda import Architecture, Code, Function, IFunction, Runtime
from aws_cdk.aws_logs import LogGroup, RetentionDays
from aws_cdk.aws_secretsmanager import Secret, SecretStringGenerator
from constructs import Construct

VALID_ENVIRONMENTS = ("dev", "staging", "prod")

#: OAuth scopes the public PKCE client asks Cognito for. ``openid`` is what
#: makes the issued token a JWT the runtime can verify against the pool JWKS;
#: ``email``/``profile`` are the only claims identity resolution reads.
COGNITO_OAUTH_SCOPES: Final[tuple[OAuthScope, ...]] = (
    OAuthScope.OPENID,
    OAuthScope.EMAIL,
    OAuthScope.PROFILE,
)

#: The five runtime configuration keys injected into the task-6 Lambda
#: (the Phase 07 task 5 boot contract). Duplicated rather than imported:
#: the synth path (``requirements.txt``) carries no fastapi/boto3, so the
#: CDK app must not import ``deploy/aws/runtime/handler.py``.
#: ``test_cdk_lambda_api.py`` pins these against the handler's
#: ``REQUIRED_ENV_KEYS`` so the two can never drift.
LAMBDA_REGION_ENV: Final = "FEEDNOW_DYNAMODB_REGION"
LAMBDA_TABLE_PREFIX_ENV: Final = "FEEDNOW_TABLE_PREFIX"
LAMBDA_ISSUERS_ENV: Final = "FEEDNOW_COGNITO_ISSUERS"
LAMBDA_CLIENT_IDS_ENV: Final = "FEEDNOW_COGNITO_CLIENT_IDS"
LAMBDA_PEPPER_SECRET_ID_ENV: Final = "FEEDNOW_PEPPER_SECRET_ID"

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
    """Normalize the ``COGNITO_CALLBACK_URLS`` input into an ordered URL tuple.

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
    """One table's name suffix and key schema (Phase 06 decision 2's layout)."""

    name: str
    partition_key: str
    sort_key: str | None = None
    indexes: tuple[_IndexSpec, ...] = ()


#: The seven-table schema, transcribed verbatim from ``SCHEMA`` in
#: ``src/app/storage/dynamodb.py`` (docs/phases/06-dynamodb.md "Table and
#: index schema"). Duplicated rather than imported on purpose: the synth path
#: (``requirements.txt``) carries no boto3, so the CDK app must not import the
#: runtime adapter module. ``test_cdk_dynamodb.py`` pins this copy against the
#: runtime ``SCHEMA`` so the two can never drift.
_SCHEMA: Final[tuple[_TableSpec, ...]] = (
    _TableSpec(name="users", partition_key="pk"),
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
)

#: The actions the Phase 06 adapter performs *only* inside
#: ``TransactWriteItems`` (docs/phases/06-dynamodb.md hardening note), so
#: their grants are pinned with the ``dynamodb:EnclosingOperation``
#: condition and the role can never write outside a transaction.
#: ``UpdateItem``/``DeleteItem`` are deliberately absent: the CAS revoke and
#: the membership delete are standalone conditional single-item writes.
_TRANSACTIONAL_ACTIONS: Final[frozenset[str]] = frozenset({"PutItem", "ConditionCheckItem"})

#: Consolidated per-resource least-privilege matrix, transcribed verbatim
#: from the "Least-privilege IAM matrix" table in docs/phases/06-dynamodb.md
#: (Phase 07 CDK input, AC 5). GSI ARNs are not rows here: they get
#: ``dynamodb:Query`` only, and a GSI ``Query`` also needs ``Query`` on the
#: base table ARN (already covered by the table rows below). No ``Scan``,
#: no table-admin actions (``CreateTable``/``DeleteTable``/``DescribeTable``
#: belong to the CloudFormation deploy path, never the runtime role).
_DYNAMODB_GRANTS: Final[Mapping[str, frozenset[str]]] = {
    "users": frozenset({"GetItem", "PutItem", "ConditionCheckItem"}),
    "organizations": frozenset({"GetItem", "PutItem", "BatchGetItem", "ConditionCheckItem"}),
    "external_identities": frozenset({"PutItem"}),
    "audit_events": frozenset({"PutItem"}),
    "api_keys": frozenset({"GetItem", "PutItem", "UpdateItem", "Query"}),
    "memberships": frozenset({"GetItem", "PutItem", "DeleteItem", "Query"}),
    "unique_constraints": frozenset({"GetItem", "PutItem"}),
}


def _runtime_policy_statements(
    *,
    tables: Mapping[str, Table],
    pepper_secret_arn: str,
    log_group_arn: str,
) -> list[PolicyStatement]:
    """One statement per matrix row for the Lambda execution role (task 4).

    Each table gets a non-transactional statement (point reads, the CAS
    ``UpdateItem``, the conditional ``DeleteItem``, base-table ``Query``)
    and, when the matrix lists them, a ``PutItem``/``ConditionCheckItem``
    statement pinned to ``TransactWriteItems``. Each GSI gets ``Query``
    only. The pepper grant is ``GetSecretValue`` on the secret ARN; the
    log grant is ``CreateLogStream``/``PutLogEvents`` on the function's
    log group ARN pattern -- nothing else, no wildcards anywhere.
    """
    statements: list[PolicyStatement] = []
    for spec in _SCHEMA:
        table_arn = tables[spec.name].table_arn
        granted = _DYNAMODB_GRANTS[spec.name]
        plain_actions = sorted(f"dynamodb:{action}" for action in granted - _TRANSACTIONAL_ACTIONS)
        if plain_actions:
            statements.append(PolicyStatement(actions=plain_actions, resources=[table_arn]))
        transaction_actions = sorted(
            f"dynamodb:{action}" for action in granted & _TRANSACTIONAL_ACTIONS
        )
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
            actions=["secretsmanager:GetSecretValue"],
            resources=[pepper_secret_arn],
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
    """The task-6 asset bundle: runtime modules + ``app/`` + payload wheels.

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

        Matches the runtime ``table_prefix`` contract from Phase 06: table
        names are ``<resource_prefix><table-name>``.
        """
        return f"feednow-auth-{self.name}-"

    @property
    def cognito_domain_prefix(self) -> str:
        """Cognito user pool domain prefix, e.g. ``feednow-auth-dev``."""
        return f"feednow-auth-{self.name}"

    @property
    def cognito_client_name(self) -> str:
        """Cognito app client name, e.g. ``feednow-auth-dev`` (task 3)."""
        return f"feednow-auth-{self.name}"

    @property
    def pepper_secret_name(self) -> str:
        """Secrets Manager name of the generated API-key pepper (task 4),
        e.g. ``feednow-auth/dev/api-pepper``. A name, never secret material.
        """
        return f"feednow-auth/{self.name}/api-pepper"

    @property
    def lambda_function_name(self) -> str:
        """Runtime Lambda function name, e.g. ``feednow-auth-dev`` (task 6).

        Fixed here because the task-4 log grant is scoped to this
        function's log group ARN pattern.
        """
        return f"feednow-auth-{self.name}"

    @property
    def lambda_role_name(self) -> str:
        """Least-privilege Lambda execution role name (task 4), e.g.
        ``feednow-auth-dev-lambda``."""
        return f"feednow-auth-{self.name}-lambda"

    @property
    def http_api_name(self) -> str:
        """HTTP API name (task 6), e.g. ``feednow-auth-dev``."""
        return f"feednow-auth-{self.name}"


class FeedNowAuthStack(cdk.Stack):
    """Environment-bound stack; DynamoDB tables (task 2), Cognito (task 3), the
    pepper secret + least-privilege Lambda role (task 4), and the runtime
    Lambda + HTTP API with redaction-safe access logs (task 6) live here."""

    def __init__(
        self,
        scope: Construct,
        id: str,
        *,
        feednow_env: FeedNowAuthEnv | str,
        cognito_callback_urls: Sequence[str] | str | None = None,
        **kwargs: object,
    ) -> None:
        resolved = (
            feednow_env if isinstance(feednow_env, FeedNowAuthEnv) else FeedNowAuthEnv(feednow_env)
        )
        super().__init__(scope, id, **kwargs)
        self.feednow_env = resolved
        # Resolved prefix for runtime wiring (Phase 07 task 6).
        self.table_prefix = resolved.resource_prefix
        # Required non-secret deployment input (Phase 07 task 3). CDK validates
        # OAuth redirect URIs at synth time, so an empty value cannot be
        # deferred to deploy: fail here with the input name the operator set.
        callback_urls = parse_cognito_callback_urls(cognito_callback_urls)
        if not callback_urls:
            msg = (
                "COGNITO_CALLBACK_URLS is required and must contain at least one HTTPS "
                "redirect URI (comma-separated); see deploy/aws/cdk/.env.example."
            )
            raise ValueError(msg)
        self.cognito_callback_urls = callback_urls

        # Phase 07 task 2: the seven Phase 06 schema tables. Names are
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

        # Phase 07 task 3: Cognito user pool + public PKCE app client + hosted
        # domain. Email is the only sign-in identity (no usernames, no phone
        # numbers) and self-service sign-up is on so first-login provisioning
        # (Phase 03) has an identity to resolve. Password reset goes through
        # the verified-email recovery mechanism with Cognito's default email
        # templates -- no custom sender, so no SES grant anywhere.
        self.user_pool = UserPool(
            self,
            "CognitoUserPool",
            sign_in_aliases=SignInAliases(email=True),
            self_sign_up_enabled=True,
            account_recovery=AccountRecovery.EMAIL_ONLY,
            removal_policy=removal_policy,
        )

        # Public (no-secret) client: PKCE is the only safe authorization-code
        # flow for a browser SPA. ALLOW_USER_PASSWORD_AUTH is the explicit flow
        # the task-7 non-prod smoke path needs; CDK pairs every explicit auth
        # flow with ALLOW_REFRESH_TOKEN_AUTH, which is what the runtime
        # refresh path relies on. Callback/logout URIs come from the required
        # COGNITO_CALLBACK_URLS input, never from a hardcoded literal.
        self.user_pool_client = UserPoolClient(
            self,
            "CognitoApiClient",
            user_pool=self.user_pool,
            user_pool_client_name=resolved.cognito_client_name,
            generate_secret=False,
            auth_flows=AuthFlow(user_password=True),
            o_auth=OAuthSettings(
                callback_urls=list(callback_urls),
                logout_urls=list(callback_urls),
                scopes=list(COGNITO_OAUTH_SCOPES),
                flows=OAuthFlows(authorization_code_grant=True),
            ),
        )

        # Hosted UI domain: ``<prefix>.auth.<region>.amazoncognito.com``. The
        # prefix is global-unique, hence the environment suffix.
        self.user_pool_domain = UserPoolDomain(
            self,
            "CognitoDomain",
            user_pool=self.user_pool,
            cognito_domain=CognitoDomainOptions(domain_prefix=resolved.cognito_domain_prefix),
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

        # Phase 07 task 4: the API-key pepper, generated by Secrets Manager
        # itself (GenerateSecretString) under the JSON field the runtime
        # pepper source parses. 48 bytes clears the 32-byte floor from
        # src/app/auth/pepper.py with margin. No plaintext pepper ever
        # exists in source, .env, stack outputs, or this template; prod
        # retains the secret because losing it invalidates every stored
        # credential digest.
        self.pepper_secret = Secret(
            self,
            "ApiPepperSecret",
            secret_name=resolved.pepper_secret_name,
            generate_secret_string=SecretStringGenerator(
                generate_string_key="pepper",
                # CDK requires the template alongside the key; the generated
                # value is merged into it at create time, so the template
                # itself carries no secret material -- just the field name.
                secret_string_template=json.dumps({}),
                # CDK's password_length is the CloudFormation ByteLength.
                password_length=48,
                exclude_punctuation=True,
            ),
            removal_policy=removal_policy,
        )

        # Phase 07 task 4: the least-privilege execution role the task-6
        # Lambda runs as. No managed policies at all -- even
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
            pepper_secret_arn=self.pepper_secret.secret_arn,
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

        # Phase 07 task 6: the runtime Lambda. The code asset is produced by
        # _LocalBundling (no Docker); the handler is the task-5 composition
        # root; the role is the task-4 least-privilege role verbatim, so no
        # grant beyond the IAM matrix exists anywhere. The five FEEDNOW_*
        # values are all stack-derived: the deployment region, the task-2
        # table prefix, the task-3 issuer/client references, and the task-4
        # secret *name* (a name, never material; boto3 resolves names
        # account-internally).
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
                LAMBDA_TABLE_PREFIX_ENV: self.table_prefix,
                LAMBDA_ISSUERS_ENV: self.cognito_issuer_url,
                LAMBDA_CLIENT_IDS_ENV: self.user_pool_client.user_pool_client_id,
                LAMBDA_PEPPER_SECRET_ID_ENV: self.pepper_secret.secret_name,
            },
        )

        # Phase 07 task 6: the public HTTP API (v2) on the $default stage --
        # the same stage the task-5 handler documents via API_STAGE. Both
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
