"""Cognito access-token verification (Phase 03 task 3).

Implements the token contract and the reviewer-pinned check order (B1/B2 and
the step-0 revision in the Phase 03 breakdown).
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
   bound), ``email`` (required, ≤320, the ``User.Email`` bound), ``username``
   (optional; absent/null/empty all normalize to ``None`` so the service can
   fall back to ``sub`` for the display name; ≤255, the ``DisplayText``
   bound), ``iss``/``client_id``/``exp`` re-checked, then a frozen
   :class:`CognitoClaims` is built.

The length caps mirror the *model* bounds (``app.models.ids``,
``app.models.user``) as plain integers on purpose: the verifier must not
import domain types (breakdown decision 4), so a token can never smuggle a
value that the later ``User``/``ExternalIdentity`` construction would reject
with a 500 instead of a clean 401.

:class:`AccessTokenVerifier` is the **published handoff interface** (task 7):
Phase 05's API-key path and future providers feed the same verification
seam. This module knows nothing about storage or users — resolution and
provisioning (task 4) consume :class:`CognitoClaims`.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final, Protocol, runtime_checkable

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

from app.auth.errors import TokenValidationError
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


@dataclass(frozen=True)
class CognitoClaims:
    """Verified access-token claims — the verifier's only output shape.

    Immutable value object; field names match the Cognito claim names so the
    task-4 mapping to ``ExternalIdentity``/``User`` stays mechanical. No raw
    token material is retained.
    """

    sub: str
    email: str
    username: str | None
    client_id: str
    iss: str
    exp: int


@runtime_checkable
class AccessTokenVerifier(Protocol):
    """The published handoff verification interface (Phase 03 task 7 docs).

    Implementations accept or reject a bearer token *without side effects*:
    a rejection must never mutate storage state (acceptance criterion 1) and
    must raise :class:`TokenValidationError` (401-mapped in task 5) or
    :class:`TokenProviderUnavailableError` (503-mapped in task 5).
    """

    def verify(self, token: str) -> CognitoClaims: ...


class CognitoAccessTokenVerifier:
    """Verifies Cognito access tokens against an issuer-bound JWKS source.

    The issuer and client allowlists are stored as independent frozenset
    copies (exact-match membership only, never prefix matching); the
    :class:`~app.auth.jwks.JwksSource` is injected so tests can bind the
    loopback JWKS fixture and Phase 07 can wire real Cognito domains without
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
        string all normalize to ``None`` so the task-4 display-name rule
        ("username when non-empty, else sub") can never see an empty string.
        """
        sub = self._require_str_claim(
            payload,
            "sub",
            max_length=_SUB_MAX_LENGTH,
            missing_reason="token is missing the sub claim",
            invalid_reason="token sub claim is invalid",
        )
        email = self._require_str_claim(
            payload,
            "email",
            max_length=_EMAIL_MAX_LENGTH,
            missing_reason="token is missing the email claim",
            invalid_reason="token email claim is invalid",
        )
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


__all__ = ["AccessTokenVerifier", "CognitoAccessTokenVerifier", "CognitoClaims"]
