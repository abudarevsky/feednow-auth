"""CDK overlay for safely enabling Google verification on an existing pool."""

from __future__ import annotations

from pathlib import Path

import aws_cdk as cdk
from aws_cdk import Stack
from aws_cdk.aws_cognito import UserPool
from aws_cdk.aws_iam import PolicyStatement, Role, ServicePrincipal
from aws_cdk.aws_lambda import CfnPermission, Code, Function, Runtime
from aws_cdk.aws_logs import LogGroup, RetentionDays
from aws_cdk.custom_resources import Provider
from constructs import Construct
from feednow_auth_stack import _runtime_lambda_code


class GoogleFederationFixStack(Stack):
    """Attach the verification trigger to an existing manually managed pool.

    This avoids creating/replacing the existing dev pool, app client, or domain.
    The custom resource preserves the pool/client settings returned by Cognito
    and makes only the dedicated evidence mapping, required client grant, and
    trigger changes.
    """

    def __init__(
        self,
        scope: Construct,
        construct_id: str,
        *,
        user_pool_id: str,
        client_id: str,
        implementation_version: str = "google-email-proof-v1",
        **kwargs: object,
    ) -> None:
        super().__init__(scope, construct_id, **kwargs)
        if not user_pool_id.startswith(f"{self.region}_"):
            raise ValueError("GOOGLE_FIX_USER_POOL_ID must belong to AWS_REGION")
        if not client_id:
            raise ValueError("GOOGLE_FIX_CLIENT_ID is required")

        pool = UserPool.from_user_pool_id(self, "ExistingCognitoPool", user_pool_id)
        pool_arn = pool.user_pool_arn

        trigger_logs = LogGroup(
            self,
            "GoogleTriggerLogs",
            log_group_name=(
                f"/aws/lambda/feednow-auth-{user_pool_id.rsplit('_', 1)[-1]}-google-trigger-v3"
            ),
            retention=RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        trigger_role = Role(
            self,
            "GoogleTriggerRole",
            assumed_by=ServicePrincipal("lambda.amazonaws.com"),
            description="Cognito trigger for trusted Google registration verification.",
        )
        trigger_role.add_to_policy(
            PolicyStatement(
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"{trigger_logs.log_group_arn}:*"],
            )
        )
        trigger = Function(
            self,
            "GoogleCognitoTrigger",
            function_name=f"feednow-auth-{user_pool_id.rsplit('_', 1)[-1]}-google-trigger-v3",
            runtime=Runtime.PYTHON_3_13,
            handler="cognito_trigger_lambda.handler",
            code=_runtime_lambda_code(),
            role=trigger_role,
            timeout=cdk.Duration.seconds(10),
            memory_size=128,
            log_group=trigger_logs,
        )
        CfnPermission(
            self,
            "CognitoMayInvokeGoogleTrigger",
            action="lambda:InvokeFunction",
            function_name=trigger.function_arn,
            principal="cognito-idp.amazonaws.com",
            source_account=self.account,
            source_arn=pool_arn,
        )

        provider_logs = LogGroup(
            self,
            "FederationProviderLogs",
            log_group_name=(
                f"/aws/lambda/feednow-auth-{user_pool_id.rsplit('_', 1)[-1]}-google-fix-provider-v3"
            ),
            retention=RetentionDays.ONE_WEEK,
            removal_policy=cdk.RemovalPolicy.RETAIN,
        )
        provider_role = Role(
            self,
            "FederationProviderRole",
            assumed_by=ServicePrincipal("lambda.amazonaws.com"),
            description=(
                "CDK custom resource for preserving and updating one Cognito pool's "
                "federation config."
            ),
        )
        provider_role.add_to_policy(
            PolicyStatement(
                actions=["logs:CreateLogStream", "logs:PutLogEvents"],
                resources=[f"{provider_logs.log_group_arn}:*"],
            )
        )
        provider_role.add_to_policy(
            PolicyStatement(
                actions=[
                    "cognito-idp:AddCustomAttributes",
                    "cognito-idp:DescribeUserPool",
                    "cognito-idp:UpdateUserPool",
                    "cognito-idp:DescribeUserPoolClient",
                    "cognito-idp:UpdateUserPoolClient",
                    "cognito-idp:UpdateIdentityProvider",
                ],
                resources=[pool_arn],
            )
        )
        on_event = Function(
            self,
            "FederationFixProviderFunction",
            function_name=f"feednow-auth-{user_pool_id.rsplit('_', 1)[-1]}-google-fix-provider-v3",
            runtime=Runtime.PYTHON_3_13,
            handler="handler.handler",
            code=Code.from_asset(
                str(Path(__file__).resolve().parent / "google_federation_fix_provider")
            ),
            role=provider_role,
            timeout=cdk.Duration.seconds(60),
            memory_size=256,
            log_group=provider_logs,
        )
        provider = Provider(
            self,
            "FederationFixProvider",
            on_event_handler=on_event,
            log_group=provider_logs,
        )
        provider_resource = cdk.CustomResource(
            self,
            "ConfigureGoogleFederation",
            service_token=provider.service_token,
            properties={
                "PoolId": user_pool_id,
                "ClientId": client_id,
                "TriggerArn": trigger.function_arn,
                "ImplementationVersion": implementation_version,
            },
        )
        provider_resource.node.add_dependency(trigger)
        provider_resource.node.add_dependency(provider_logs)

        cdk.CfnOutput(self, "GoogleFederationPoolId", value=user_pool_id)
        cdk.CfnOutput(self, "GoogleFederationClientId", value=client_id)
        cdk.CfnOutput(self, "GoogleVerificationTriggerArn", value=trigger.function_arn)
