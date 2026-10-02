# Cognito integration

Cognito is the current external identity provider. It establishes the external
identity; `feednow-auth` owns internal users, organizations, memberships,
authorization context, API credentials, and audit events.

## Access-token validation

`CognitoAccessTokenVerifier` accepts access tokens signed with exact `RS256`,
an issuer in the configured allowlist, an allowed `client_id`, and
`token_use="access"`. Issuer-bound JWKS lookup prevents resolving a key from a
different configured issuer. Validation failures use fixed safe reasons and
do not write to storage. JWKS outages map to service-unavailable behavior.

On first login, the service requires a user-info profile whose `sub` matches
the validated token and whose email is explicitly verified. The verified
profile is the source of the stored email; token claims alone do not create a
placeholder address.

## Provider configuration

The AWS runtime takes issuer and client-ID allowlists from its environment and
decrypts the KMS-encrypted API-key pepper supplied in Lambda configuration. Browser session endpoints
also require the authorize URL, token endpoint, user-info endpoint, callback
URL, allowed return origins, session lifetime, and cookie security setting.
The session settings form one all-or-nothing gate. The local Docker runtime
uses the configured Cognito endpoints and a local SQLite database.

Do not place Cognito secrets, tokens, or API-key pepper material in source
control or logs. See [operations.md](operations.md) for the environment
reference, local startup, and live-provider verification procedure.

## User-pool and app-client requirements

Cognito pools and app clients are provisioned and owned by the operator. The
AWS application stack imports their IDs from each environment file and never
creates, replaces, or updates those resources. Pool domain, app-client callback
URLs, OAuth scopes, provider configuration, and required attributes are
configured on the existing pool/client. The operator adds the selected
environment's callback and logout URLs to the existing app client, preserving
its current URL entries. It also adds the authorization-code flow and the
required `openid`, `email`, and `profile` scopes while preserving other app
client flows and scopes. Callback defaults to
`<ACCOUNT_BASE_URL>/api/oauth/callback`; set
`FEEDNOW_COGNITO_CALLBACK_URLS` only when additional callback URLs are needed.
The deployment defaults to the `feednow-auth-<environment>` domain prefix.
When an existing pool uses another Cognito domain, set
`FEEDNOW_COGNITO_DOMAIN` in that environment's `deploy/aws/cdk/.env.<environment>`
to its HTTPS origin, without a path. The same value configures runtime login
and token endpoints and the Google Console `/oauth2/idpresponse` URI.

Google is configured as an identity provider on a user pool, so all app clients
in that pool share its Google client ID and secret. `ensure-google` targets the
pool and app client selected by `--env`; if two environments point to the same
pool, they share the provider registration while each app client retains its
own callback and sign-out URLs. If the environments use separate pools, each
pool needs its own provider registration, though Google Console can authorize
the `/oauth2/idpresponse` redirect URI for each pool domain on one Google OAuth
client.

The app client must allow authorization-code grant with `openid`, `email`, and
`profile` scopes. Register the exact callback and sign-out URLs used by the
environment. The app client may be public or confidential because all code
exchange occurs in the backend; the browser never receives its secret. For a
confidential existing client, deployment retrieves the secret from Cognito,
encrypts it with the environment KMS key, and supplies only the ciphertext to
Lambda. The runtime decrypts it in memory for token exchange. The Google
provider secret is entered only through the secure backend operator prompt. The issuer has the
form `https://cognito-idp.<region>.amazonaws.com/<user-pool-id>`.

For local account development, register
`http://localhost:8000/oauth/callback` and `http://localhost:8000/logout`;
the UI is normally served at `http://localhost:3000`. The backend performs
the code exchange, token validation, verified-profile lookup, and session
issuance. Do not put Cognito tokens in browser storage.

Native Cognito email registration uses its email verification flow. For
federated Google users, first-login provisioning requires explicit verified
email proof. The development pool maps Google's `email_verified` claim to
`custom:g_verified`; the backend accepts only the exact verified proof and
does not merge identities based on matching email addresses. Existing legacy
federated profiles need an operator-reviewed repair; never infer verification
from an email match.

## Google verification trigger with local Docker

The local Docker application connects to a real Cognito user pool; it does not
run Cognito triggers in the app container. Cognito invokes the trigger as an
AWS Lambda function. The repository's overlay deploys that function and
updates the selected existing pool's Google verification mapping and trigger
configuration without replacing the pool, app client, or domain.

To check and set up the trigger for the development pool configured in
`deploy/docker/.env`, use AWS credentials for that pool's account and run:

```bash
./deploy/docker/run-dev.sh --ensure-google-trigger
```

The command confirms the user pool is named as a development pool, checks the
expected Lambda and both Cognito trigger attachments, and exits without a
deployment when they are already present. If either attachment is missing, it
deploys the dedicated CDK overlay. It stops if the pool already has a different
pre-sign-up or pre-authentication Lambda, so that trigger must be reviewed
before proceeding. AWS CLI, CDK, Python 3, and credentials with the overlay's
deployment permissions are required. To deploy manually, provide the pool ID
and app-client ID:

```bash
cd deploy/aws/cdk
export CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
export AWS_REGION=eu-north-1
export GOOGLE_FIX_USER_POOL_ID="eu-north-1_<user-pool-suffix>"
export GOOGLE_FIX_CLIENT_ID="<app-client-id>"
cdk --app "python3 google_federation_fix.py" deploy FeedNowAuthGoogleFederationFix-dev
```

Then configure `deploy/docker/.env` to use that same pool's issuer, client ID,
domain, and user-info endpoint, and start the local account stack with
`./deploy/docker/run-dev.sh --cognito --ui`. The Docker backend performs the
OAuth flow against Cognito; Cognito invokes the separately deployed Lambda
during Google registration. Native Cognito email registration does not depend
on this Google-specific trigger. The standard AWS Cognito pool is required;
the local Docker composition does not provide a Cognito or Lambda emulator.

## Troubleshooting checks

- An invalid signature or unknown signing key usually indicates a token from
  a different pool, stale issuer configuration, or an unavailable JWKS
  endpoint. Confirm the token issuer and configured allowlist.
- An audience/client mismatch means the access token's `client_id` is not in
  the configured client allowlist. Confirm the app client that issued it.
- First-login rejection means user-info is missing, its `sub` does not match
  the access token, or the returned email lacks accepted verified proof.
- Cognito's login page may be unavailable when the app client lacks the
  required provider or the domain has incomplete branding configuration.
- JWKS network failures return service-unavailable behavior; retry after
  provider connectivity recovers rather than treating the token as valid.
