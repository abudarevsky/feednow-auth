"""Cognito access-token verification (identity).

Implements the token contract and the reviewer-pinned check order (B1/B2 and
the step-0 revision in the identity design notes).
:class:`CognitoAccessTokenVerifier.verify` runs exactly these stages
(0—7), in this order — each later stage may assume the earlier ones passed,
and every failure path raises :class:`TokenValidationError` (or propagates
the source's :class:`UnknownKeyIdError` /
:class:`TokenProviderUnavailableError`) with a **fixed, safe reason string**
that never interpolates token, key, or claim material:

1. **Structure** — the token is split and its header/payload are decoded
   *unverified* (manual base64url + JSON, deliberately not
   ``jwt.decode(verify_signature=False)``, which would also run the time
   checks and break the pinned order).
0. **Header (step 0, runs immediately after stage 1)** — the unverified JOSE
   header is inspected **before any claim extraction**: (a) ``alg`` must be
   the exact case-sensitive string ``"RS256"`` (missing/non-string/other →
   ``"token algorithm is not allowed"``; RFC 7515 algs are case-sensitive, so
   no ``.upper()`` normalization), then (b) ``kid`` must be a non-empty string
   (``"token header is missing the key id"``, moved here from stage 3).
   Strictly better fail-fast: ``none``/HS256 forgeries reject before issuer
   membership and any network fetch, and this establishes no trust (stage 1
   already parsed the same unverified bytes).
2. **Issuer** — ``iss`` is read from the unverified payload and checked with
   the app's own exact set-membership against ``allowed_issuers`` — **not**
   PyJWT's ``issuer=`` option (defense in depth: an ``iss`` that merely has an
   allowlisted entry as a strict prefix — the classic Cognito issuer-spoof —
   is rejected here, before any network activity).
3. **Key fetch** — the signing key is resolved via
   ``jwks_source.signing_key(iss, kid)``, bound to the already-verified
   issuer only; a ``kid`` missing under that issuer is unambiguously an
   :class:`UnknownKeyIdError` (a ``TokenValidationError``). No cross-issuer
   scanning is possible through this interface.
4. **Decode** — ``jwt.decode`` with ``algorithms=["RS256"]`` (step 0 already
   rejects non-RS256 headers, so the ``InvalidAlgorithmError`` mapping below
   stays as unreachable-in-practice fail-closed redundancy),
   ``options={"verify_aud": False}`` (``aud`` is an ID-token claim; Cognito
   binds access tokens via ``client_id`` instead), and a fixed
   ``leeway_seconds`` applied by PyJWT to ``exp`` and to ``iat``/``nbf`` when
   present. PyJWT exceptions are mapped one-by-one to fixed reasons; an
   unexpected library error fails closed as ``"token failed validation"``.
5. **token_use** — must equal ``"access"`` (ID and refresh tokens rejected).
6. **client_id** — exact set-membership against ``allowed_client_ids``.
7. **Claim shape** — ``sub`` (non-empty, ≤255, the :data:`ProviderSubject`
    bound), optional ``email`` (≤320 when present; absent/null yields
    ``None`` — the access-token email is advisory and provisioning reads the
    verified user-info profile instead), ``username``
   (optional; absent/null/empty all normalize to ``None`` so the service can
   fall back to ``sub`` for the display name; ≤255, the ``DisplayText``
   bound), ``iss``/``client_id``/``exp`` re-checked, then a frozen
   :class:`CognitoClaims` is built.

The length caps mirror the *model* bounds (``app.models.ids``,
``app.models.user``) as plain integers on purpose: the verifier must not
import domain types (design notes design choice 4), so a token can never smuggle a
value that the later ``User``/``ExternalIdentity`` construction would reject
with a 500 instead of a clean 401.

:class:`AccessTokenVerifier` is the **published handoff interface** (implementation):
API-key implementation API-key path and future providers feed the same verification
seam. This module knows nothing about storage or users — resolution and
provisioning (implementation) consume :class:`CognitoClaims`.

session (profile and session boundary) extends this module with the
**verified-profile seam** used by first-login provisioning:

- :class:`CognitoProfile` — the frozen profile value object (subject, email,
  email-verification flag, display name) that the identity service consumes
  instead of trusting access-token claims for the user's email.
- :func:`require_provisioning_profile` — the provisioning-profile gate: the
  single place that decides whether a fetched profile may create a user
  (subject must equal the verified token's, email present and bounded,
  ``email_verified`` exactly ``True``, display name bounded or ``None``).
  Every rejection is a :class:`TokenValidationError` with a fixed safe
  reason; the gate uses plain integer bounds and imports no ``app.models``
  types (the same decision-4 rule as the verifier and the client).
- :class:`ProfileSource` — the published fetch interface, mirroring
  :class:`AccessTokenVerifier`'s handoff role.
- :class:`CognitoUserInfoClient` — the narrow Cognito ``/oauth2/userInfo``
  HTTP client. The endpoint is fixed approved configuration validated to be
  absolute HTTPS at construction (no per-call URL selection, so a verified
  token can never steer a fetch); redirects are rejected rather than
  followed; the response body is size-capped and fail-closed parsed. Field
  shape failures raise :class:`TokenValidationError` (401-mapped) with fixed
  safe reasons, and transport/non-JSON failures raise
  :class:`TokenProviderUnavailableError` (503-mapped) — the same vocabulary
  and reason-hygiene rules as the verifier: no token, email, subject, or
  payload material is ever interpolated into exception text or logged (this
  module imports no logging).

Current behavior and invariants: ``docs/authentication.md``."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable
from urllib.parse import urlparse

import jwt
from jwt import PyJWK
from jwt.exceptions import (
    DecodeError,
    ExpiredSignatureError,
    ImmatureSignatureError,
    InvalidAlgorithmError,
    InvalidSignatureError,
    InvalidSubjectError,
    PyJWTError,
)
from jwt.utils import base64url_decode

from app.auth.errors import TokenProviderUnavailableError, TokenValidationError
from app.auth.jwks import JwksSource

#: The single allowed JOSE algorithm: exact, case-sensitive header match
#: (step 0) and the only entry in the decode-time ``algorithms`` allowlist.
_ALLOWED_ALG: Final = "RS256"

#: ``sub`` bound mirroring ``app.models.ids.ProviderSubject`` (max_length=255).
_SUB_MAX_LENGTH: Final = 255

#: ``email`` bound mirroring ``app.models.user.Email`` (max_length=320).
_EMAIL_MAX_LENGTH: Final = 320

#: ``username`` bound mirroring ``app.models.user.DisplayText`` (max_length=255).
_USERNAME_MAX_LENGTH: Final = 255

#: Generic bound for the ``iss``/``client_id`` string claims.
_ID_CLAIM_MAX_LENGTH: Final = 255

#: Hard cap on the user-info response body. A Cognito profile is roughly a
#: kilobyte; anything larger is a hostile or misconfigured endpoint and is
#: rejected fail-closed instead of being buffered without limit.
_MAX_PROFILE_BODY_BYTES: Final = 65_536


@dataclass(frozen=True)
class CognitoClaims:
    """Verified access-token claims — the verifier's only output shape.

    Immutable value object; field names match the Cognito claim names so the
    implementation mapping to ``ExternalIdentity``/``User`` stays mechanical. No raw
    token material is retained. ``email`` is ``None`` when the token carries
    no email claim: Cognito access tokens routinely omit it, and the
    authoritative email for provisioning comes from the verified
    :class:`CognitoProfile` (session), never from a synthesized stand-in.
    """

    sub: str
    email: str | None
    username: str | None
    client_id: str
    iss: str
    exp: int


@runtime_checkable
class AccessTokenVerifier(Protocol):
    """The published handoff verification interface (identity docs).

    Implementations accept or reject a bearer token *without side effects*:
    a rejection must never mutate storage state (acceptance criterion 1) and
    must raise :class:`TokenValidationError` (401-mapped in implementation) or
    :class:`TokenProviderUnavailableError` (503-mapped in implementation).
    """

    def verify(self, token: str) -> CognitoClaims: ...


class CognitoAccessTokenVerifier:
    """Verifies Cognito access tokens against an issuer-bound JWKS source.

    The issuer and client allowlists are stored as independent frozenset
    copies (exact-match membership only, never prefix matching); the
    :class:`~app.auth.jwks.JwksSource` is injected so tests can bind the
    loopback JWKS fixture and AWS can wire real Cognito domains without
    changing this class.
    """

    def __init__(
        self,
        jwks_source: JwksSource,
        allowed_issuers: Iterable[str],
        allowed_client_ids: Iterable[str],
        leeway_seconds: int = 60,
    ) -> None:
        issuers = frozenset(allowed_issuers)
        if not issuers:
            raise ValueError("allowed_issuers must contain at least one issuer")
        clients = frozenset(allowed_client_ids)
        if not clients:
            raise ValueError("allowed_client_ids must contain at least one client id")
        if leeway_seconds < 0:
            raise ValueError("leeway_seconds must be non-negative")
        self._jwks_source = jwks_source
        self._allowed_issuers: Final = issuers
        self._allowed_client_ids: Final = clients
        self._leeway_seconds = leeway_seconds

    @property
    def allowed_issuers(self) -> frozenset[str]:
        """The configured exact-match issuer allowlist."""
        return self._allowed_issuers

    @property
    def allowed_client_ids(self) -> frozenset[str]:
        """The configured exact-match app-client allowlist."""
        return self._allowed_client_ids

    def verify(self, token: str) -> CognitoClaims:
        """Verify ``token`` and return its claims.

        :raises TokenValidationError: malformed/forged/expired token,
            disallowed algorithm, issuer, or client, wrong ``token_use``, or
            invalid claim shape (fixed safe reason; see the module docstring
            order).
        :raises UnknownKeyIdError: no key under the verified issuer matches
            the token's ``kid`` (subclass of ``TokenValidationError``).
        :raises TokenProviderUnavailableError: the issuer's JWKS endpoint
            could not be fetched (not a bad-token failure).
        """
        header, payload = self._unpack_unverified(token)  # 1
        kid = self._check_header(header)  # 0
        issuer = self._check_issuer(payload)  # 2
        key = self._fetch_signing_key(issuer, kid)  # 3
        verified = self._decode(token, key)  # 4
        self._check_token_use(verified)  # 5
        self._check_client_id(verified)  # 6
        return self._build_claims(verified)  # 7

    # -- stage 1: unverified structure -----------------------------------------

    @staticmethod
    def _unpack_unverified(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
        """Decode header and payload **without any verification** (step 0 and
        order stages 2—3 need them before the signature is checked).

        Manual base64url + JSON is deliberate: ``jwt.decode(verify_signature=False)``
        would also enforce ``exp``/``iat``/``nbf`` here, letting a time failure
        mask (and mis-order) the issuer check.
        """
        if not isinstance(token, str):
            raise TokenValidationError("token must be a string")
        malformed = TokenValidationError("token is not a well-formed JWT")
        segments = token.split(".")
        if len(segments) != 3:
            raise malformed
        try:
            header = json.loads(base64url_decode(segments[0]))
            payload = json.loads(base64url_decode(segments[1]))
        except (ValueError, TypeError):  # binascii.Error subclasses ValueError
            raise malformed from None
        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise malformed
        return header, payload

    # -- step 0: unverified-header inspection (before any claim extraction) -------

    @staticmethod
    def _check_header(header: Mapping[str, Any]) -> str:
        """Inspect the JOSE header before touching payload claims.

        ``alg`` is checked **first** and compared exactly (case-sensitive, no
        normalization): a ``none``/HS256 forgery rejects with a deterministic
        reason independent of claim content and before any network fetch.
        ``kid`` (checked second) must be a non-empty string. Returns the
        validated ``kid`` for the stage-3 lookup; establishes no trust —
        stage 1 already parsed these same unverified bytes.
        """
        alg = header.get("alg")
        if not isinstance(alg, str) or alg != _ALLOWED_ALG:
            raise TokenValidationError("token algorithm is not allowed")
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise TokenValidationError("token header is missing the key id")
        return kid

    # -- stage 2: own exact-match issuer check -----------------------------------

    def _check_issuer(self, payload: Mapping[str, Any]) -> str:
        """Return ``iss`` after exact allowlist membership (never PyJWT ``issuer=``).

        Set membership kills the prefix-spoof class (``allowed-iss + attacker
        suffix``) independently of the pinned library version.
        """
        if "iss" not in payload or payload["iss"] is None:
            raise TokenValidationError("token is missing the issuer claim")
        issuer = payload["iss"]
        if not isinstance(issuer, str) or not issuer:
            raise TokenValidationError("token issuer claim is invalid")
        if issuer not in self._allowed_issuers:
            raise TokenValidationError("token issuer is not in the allowlist")
        return issuer

    # -- stage 3: issuer-bound key resolution -------------------------------------

    def _fetch_signing_key(self, issuer: str, kid: str) -> PyJWK:
        """Resolve the step-0-validated ``kid`` **only** from the verified issuer's set.

        An unknown ``kid`` under a correct issuer is unambiguously
        :class:`~app.auth.errors.UnknownKeyIdError` — raised by the source,
        propagated unchanged.
        """
        return self._jwks_source.signing_key(issuer, kid)

    # -- stage 4: signature + time validation via PyJWT -----------------------------

    def _decode(self, token: str, key: PyJWK) -> Mapping[str, Any]:
        """``jwt.decode`` with the pinned options; every library failure becomes
        a :class:`TokenValidationError` with a fixed reason (library messages,
        which can echo claim fragments, are chained as ``__cause__`` only).
        """
        try:
            verified: Mapping[str, Any] = jwt.decode(
                token,
                key.key,
                algorithms=[_ALLOWED_ALG],
                options={"verify_aud": False},
                leeway=self._leeway_seconds,
            )
        except ExpiredSignatureError as exc:
            raise TokenValidationError("token has expired") from exc
        except ImmatureSignatureError as exc:
            raise TokenValidationError("token is not yet valid") from exc
        except InvalidSignatureError as exc:  # subclass of DecodeError: order matters
            raise TokenValidationError("token signature is invalid") from exc
        except InvalidAlgorithmError as exc:  # fail-closed redundancy of step 0
            raise TokenValidationError("token algorithm is not allowed") from exc
        except InvalidSubjectError as exc:
            raise TokenValidationError("token sub claim is invalid") from exc
        except DecodeError as exc:
            raise TokenValidationError("token is not a well-formed JWT") from exc
        except PyJWTError as exc:
            raise TokenValidationError("token failed validation") from exc
        except Exception as exc:  # unexpected library behavior fails closed
            raise TokenValidationError("token failed validation") from exc
        return verified

    # -- stages 5—6: token_use and client binding -------------------------------------

    @staticmethod
    def _check_token_use(payload: Mapping[str, Any]) -> None:
        """Access tokens only: ID and refresh tokens must not authenticate."""
        if payload.get("token_use") != "access":
            raise TokenValidationError("token is not an access token")

    def _check_client_id(self, payload: Mapping[str, Any]) -> None:
        """Cognito binds the app client in access tokens via ``client_id``."""
        if "client_id" not in payload or payload["client_id"] is None:
            raise TokenValidationError("token is missing the client_id claim")
        client_id = payload["client_id"]
        if not isinstance(client_id, str) or not client_id:
            raise TokenValidationError("token client_id claim is invalid")
        if client_id not in self._allowed_client_ids:
            raise TokenValidationError("token client_id is not in the allowlist")

    # -- stage 7: claim-shape validation and claims construction ------------------------

    def _build_claims(self, payload: Mapping[str, Any]) -> CognitoClaims:
        """Validate shapes and build the frozen claims.

        ``username`` is the one optional member: absent, JSON null, and empty
        string all normalize to ``None`` so the implementation display-name rule
        ("username when non-empty, else sub") can never see an empty string.
        """
        sub = self._require_str_claim(
            payload,
            "sub",
            max_length=_SUB_MAX_LENGTH,
            missing_reason="token is missing the sub claim",
            invalid_reason="token sub claim is invalid",
        )
        # Cognito's standard access-token payload does not include email even
        # when the authorize request contains the ``email`` scope. Absent or
        # null yields ``None`` (Phase 11 task 5): the claims email is
        # advisory only, and first-login provisioning must go through the
        # verified user-info profile instead. A present-but-malformed claim
        # remains a rejection.
        raw_email = payload.get("email")
        if raw_email is None:
            email = None
        elif not isinstance(raw_email, str) or not raw_email or len(raw_email) > _EMAIL_MAX_LENGTH:
            raise TokenValidationError("token email claim is invalid")
        else:
            email = raw_email
        client_id = self._require_str_claim(
            payload,
            "client_id",
            max_length=_ID_CLAIM_MAX_LENGTH,
            missing_reason="token is missing the client_id claim",
            invalid_reason="token client_id claim is invalid",
        )
        issuer = self._require_str_claim(
            payload,
            "iss",
            max_length=_ID_CLAIM_MAX_LENGTH,
            missing_reason="token is missing the issuer claim",
            invalid_reason="token issuer claim is invalid",
        )

        raw_username = payload.get("username")
        username: str | None
        if raw_username is None:
            username = None
        elif not isinstance(raw_username, str) or len(raw_username) > _USERNAME_MAX_LENGTH:
            raise TokenValidationError("token username claim is invalid")
        else:
            username = raw_username or None

        if "exp" not in payload or payload["exp"] is None:
            raise TokenValidationError("token is missing the exp claim")
        exp = payload["exp"]
        if isinstance(exp, bool) or not isinstance(exp, int):
            raise TokenValidationError("token exp claim is invalid")

        return CognitoClaims(
            sub=sub,
            email=email,
            username=username,
            client_id=client_id,
            iss=issuer,
            exp=exp,
        )

    @staticmethod
    def _require_str_claim(
        payload: Mapping[str, Any],
        name: str,
        *,
        max_length: int,
        missing_reason: str,
        invalid_reason: str,
    ) -> str:
        """Return a non-empty, length-bounded string claim or raise a fixed reason."""
        if name not in payload or payload[name] is None:
            raise TokenValidationError(missing_reason)
        value = payload[name]
        if not isinstance(value, str) or not value or len(value) > max_length:
            raise TokenValidationError(invalid_reason)
        return value


# -- Phase 11: verified-profile seam ------------------------------------------


@dataclass(frozen=True)
class CognitoProfile:
    """Verified identity-provider profile — the user-info fetch's only output.

    Immutable value object mirroring :class:`CognitoClaims`'s hygiene rules:
    no raw token, HTTP response, or provider payload material is retained,
    and the field bounds are enforced by the producing client (plain
    integers, no ``app.models`` imports — the same design notes design choice 4 that
    keeps the verifier free of domain types). ``email`` and ``display_name``
    are optional at the *transport* layer; the provisioning-profile gate
    (:func:`require_provisioning_profile`) decides which absences are
    acceptable before any user is created.
    """

    sub: str
    email: str | None
    email_verified: bool
    display_name: str | None


def require_provisioning_profile(profile: CognitoProfile, *, token_sub: str) -> CognitoProfile:
    """Gate a fetched profile against the verified token before provisioning.

    The transport layer tolerates absent ``email``/``name``; account creation
    must not. This is the single decision point: ``sub`` must be a valid,
    bounded subject **equal to** the already-verified token's ``sub`` (a
    profile for anyone else is a provider contract violation, never a
    provisioning input), ``email`` must be present, non-empty, and within
    the model bound, ``email_verified`` must be exactly ``True``, and
    ``display_name`` must be ``None`` or a bounded non-empty string.

    Returns ``profile`` unchanged on success (callers chain it into the
    provisioning batch). Every failure raises
    :class:`~app.auth.errors.TokenValidationError` (401-mapped) with a fixed
    safe reason — no email, subject, or profile value is ever interpolated
    into the message.
    """
    if not isinstance(profile.sub, str) or not profile.sub or len(profile.sub) > _SUB_MAX_LENGTH:
        raise TokenValidationError("profile sub claim is invalid")
    if profile.sub != token_sub:
        raise TokenValidationError("profile subject does not match the token")

    if profile.email is None:
        raise TokenValidationError("profile is missing the email claim")
    if (
        not isinstance(profile.email, str)
        or not profile.email
        or len(profile.email) > _EMAIL_MAX_LENGTH
    ):
        raise TokenValidationError("profile email claim is invalid")

    if not isinstance(profile.email_verified, bool):
        raise TokenValidationError("profile email_verified claim is invalid")
    if profile.email_verified is not True:
        raise TokenValidationError("profile email is not verified")

    if profile.display_name is not None and (
        not isinstance(profile.display_name, str)
        or not profile.display_name
        or len(profile.display_name) > _USERNAME_MAX_LENGTH
    ):
        raise TokenValidationError("profile display name is invalid")

    return profile


@runtime_checkable
class ProfileSource(Protocol):
    """The published profile-fetch interface (session design notes implementation).

    Implementations exchange a **verified** bearer access token for the
    provider's authoritative profile, side-effect-free from the caller's
    point of view. ``expected_sub`` is the subject of the already-verified
    token: a profile for any other subject is a provider contract violation
    and must be rejected, never adopted.

    :raises TokenValidationError: profile shape/subject failure (401-mapped).
    :raises TokenProviderUnavailableError: the provider could not deliver a
        parseable profile (503-mapped).
    """

    def fetch(self, access_token: str, expected_sub: str) -> CognitoProfile: ...


class _RejectRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Turn every 3xx into an ``HTTPError`` instead of a second request.

    Overriding ``redirect_request`` to return ``None`` is the documented
    urllib way to decline a redirect: the opener then raises ``HTTPError``
    for the 3xx status. Following redirects from a fixed approved endpoint
    would let a compromised or misconfigured server move the bearer token to
    another origin, so no redirect target is ever fetched.
    """

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


class CognitoUserInfoClient:
    """Fetches Cognito user-info profiles over HTTPS for verified tokens.

    The URL is constructor-pinned approved configuration (absolute HTTPS,
    no query/fragment), never derived from token claims or per-call input,
    so this client adds no SSRF surface: the only caller-controlled data on
    the wire is the bearer token itself, sent over a single fixed GET. The
    opener is built once with :class:`_RejectRedirectHandler` and reused
    (urllib openers are thread-safe for independent requests); timeouts are
    enforced per request.
    """

    def __init__(self, userinfo_url: str, timeout_seconds: float = 5.0) -> None:
        self._userinfo_url = self._validate_userinfo_url(userinfo_url)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self._timeout_seconds = timeout_seconds
        self._opener = urllib.request.build_opener(_RejectRedirectHandler())

    @property
    def userinfo_url(self) -> str:
        """The fixed HTTPS user-info endpoint this client will call."""
        return self._userinfo_url

    def fetch(self, access_token: str, expected_sub: str) -> CognitoProfile:
        """GET the profile bound to ``access_token`` and validate its shape.

        :raises TokenValidationError: missing/empty access token, a profile
            whose ``sub`` is malformed or differs from ``expected_sub``, or
            an invalid ``email``/``email_verified``/``name`` member (fixed
            safe reasons; see the helpers below).
        :raises TokenProviderUnavailableError: transport failure, timeout,
            any non-2xx (redirects included), an over-cap body, or a body
            that is not a JSON object.
        """
        if not isinstance(access_token, str) or not access_token:
            raise TokenValidationError("profile request requires an access token")
        request = urllib.request.Request(
            self._userinfo_url,
            method="GET",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
        # HTTPError is a URLError subclass and URLError an OSError subclass:
        # the order below keeps "endpoint answered badly" distinct from
        # "endpoint unreachable" (which covers DNS, TLS, and read timeouts).
        try:
            with self._opener.open(request, timeout=self._timeout_seconds) as response:
                body: bytes = response.read(_MAX_PROFILE_BODY_BYTES + 1)
        except urllib.error.HTTPError as exc:
            raise TokenProviderUnavailableError(
                "profile endpoint returned an error response"
            ) from exc
        except OSError as exc:
            raise TokenProviderUnavailableError("profile endpoint could not be reached") from exc
        if len(body) > _MAX_PROFILE_BODY_BYTES:
            raise TokenProviderUnavailableError("profile response is too large")
        return self._build_profile(self._parse_json_object(body), expected_sub)

    @staticmethod
    def _validate_userinfo_url(userinfo_url: str) -> str:
        """Pin approved configuration: absolute HTTPS, no query or fragment.

        A per-request URL selection point or an http:// endpoint would let
        the bearer token travel in cleartext or to an unapproved host; a
        query/fragment would smuggle parameters into the fixed request.
        """
        parsed = urlparse(userinfo_url)
        if parsed.scheme.lower() != "https" or not parsed.netloc:
            raise ValueError("userinfo_url must be an absolute HTTPS URL")
        if parsed.query or parsed.fragment:
            raise ValueError("userinfo_url must not contain a query or fragment")
        return userinfo_url

    @staticmethod
    def _parse_json_object(body: bytes) -> Mapping[str, Any]:
        """Decode the response body fail-closed; parse failures are provider faults."""
        try:
            payload = json.loads(body)
        except ValueError as exc:  # json.JSONDecodeError subclasses ValueError
            raise TokenProviderUnavailableError(
                "profile response is not a valid JSON document"
            ) from exc
        if not isinstance(payload, dict):
            raise TokenProviderUnavailableError("profile response is not a JSON object")
        return payload

    @staticmethod
    def _build_profile(payload: Mapping[str, Any], expected_sub: str) -> CognitoProfile:
        """Validate the four profile members and build the frozen value object.

        ``email`` absent/null maps to ``None`` (the provisioning gate, not
        this client, decides whether a profile without email may create a
        user); ``name`` absent, null, and empty all map to ``None`` exactly
        like the verifier's ``username`` normalization. A present-but-
        malformed member is always a rejection, never a silent default.
        """
        sub = _require_profile_str(
            payload,
            "sub",
            max_length=_SUB_MAX_LENGTH,
            invalid_reason="profile sub claim is invalid",
        )
        if sub != expected_sub:
            raise TokenValidationError("profile subject does not match the token")

        raw_email = payload.get("email")
        if raw_email is None:
            email = None
        elif not isinstance(raw_email, str) or not raw_email or len(raw_email) > _EMAIL_MAX_LENGTH:
            raise TokenValidationError("profile email claim is invalid")
        else:
            email = raw_email

        if "email_verified" not in payload or payload["email_verified"] is None:
            raise TokenValidationError("profile is missing the email_verified claim")
        raw_email_verified = payload["email_verified"]
        # OIDC defines email_verified as a JSON boolean, but Cognito's
        # /oauth2/userInfo endpoint serializes it as the lowercase string
        # "true" or "false". Accept those exact wire values and normalize
        # them; arbitrary strings and numeric values still fail closed.
        if isinstance(raw_email_verified, bool):
            email_verified = raw_email_verified
        elif raw_email_verified == "true":
            email_verified = True
        elif raw_email_verified == "false":
            # Cognito can leave the standard attribute false for a freshly
            # federated Google profile even when Google's verified-email
            # claim was mapped into our dedicated proof attribute. The
            # custom claim is returned by /oauth2/userInfo under `profile`
            # scope and is populated only by the configured Google mapping.
            # Keep this exact, source-specific proof as a narrow fallback;
            # missing/false/malformed claims still fail closed.
            email_verified = payload.get("custom:g_verified") == "true"
        else:
            raise TokenValidationError("profile email_verified claim is invalid")

        raw_name = payload.get("name")
        if raw_name is None:
            display_name = None
        elif not isinstance(raw_name, str) or len(raw_name) > _USERNAME_MAX_LENGTH:
            raise TokenValidationError("profile name claim is invalid")
        else:
            display_name = raw_name or None

        return CognitoProfile(
            sub=sub,
            email=email,
            email_verified=email_verified,
            display_name=display_name,
        )


def _require_profile_str(
    payload: Mapping[str, Any],
    name: str,
    *,
    max_length: int,
    invalid_reason: str,
) -> str:
    """Return a non-empty, length-bounded profile member or raise a fixed reason."""
    if name not in payload or payload[name] is None:
        raise TokenValidationError(f"profile is missing the {name} claim")
    value = payload[name]
    if not isinstance(value, str) or not value or len(value) > max_length:
        raise TokenValidationError(invalid_reason)
    return value


__all__ = [
    "AccessTokenVerifier",
    "CognitoAccessTokenVerifier",
    "CognitoClaims",
    "CognitoProfile",
    "CognitoUserInfoClient",
    "ProfileSource",
    "require_provisioning_profile",
]
