"""Decrypt the Cognito app-client secret supplied as Lambda configuration."""

from __future__ import annotations

import base64
import os
from collections.abc import Mapping
from typing import Any, Final

import boto3

COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV: Final = "FEEDNOW_COGNITO_CLIENT_SECRET_CIPHERTEXT_B64"
ENVIRONMENT_ENV: Final = "FEEDNOW_ENV"


class KmsEncryptedCognitoClientSecret:
    """Decrypt the existing app-client secret in memory for OAuth code exchange."""

    def __init__(
        self,
        ciphertext_b64: str | None = None,
        environment: str | None = None,
        *,
        client: Any | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        env = os.environ if environ is None else environ
        self._ciphertext_b64 = (
            ciphertext_b64 or env.get(COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV) or ""
        ).strip()
        self._environment = (environment or env.get(ENVIRONMENT_ENV) or "").strip()
        if not self._ciphertext_b64:
            raise ValueError(f"{COGNITO_CLIENT_SECRET_CIPHERTEXT_ENV} is required")
        if self._environment not in {"dev", "staging", "prod"}:
            raise ValueError(f"{ENVIRONMENT_ENV} must be dev, staging, or prod")
        self._client = client

    def current(self) -> str:
        """Decrypt once for the caller; never include plaintext in errors or repr."""
        try:
            ciphertext = base64.b64decode(self._ciphertext_b64, validate=True)
            response = self._kms_client().decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext={"environment": self._environment},
            )
            plaintext = response["Plaintext"]
            secret = plaintext.decode("utf-8") if isinstance(plaintext, bytes) else ""
        except Exception:
            raise ValueError(
                "KMS-encrypted Cognito app-client secret could not be decrypted"
            ) from None
        if not secret:
            raise ValueError("KMS-encrypted Cognito app-client secret is malformed")
        return secret

    def _kms_client(self) -> Any:
        if self._client is None:
            self._client = boto3.client("kms")
        return self._client

    def __repr__(self) -> str:
        return "KmsEncryptedCognitoClientSecret(<redacted>)"

    __str__ = __repr__
