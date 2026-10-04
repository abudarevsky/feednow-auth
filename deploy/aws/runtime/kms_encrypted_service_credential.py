"""Decrypt the registered Vispector service credential at Lambda cold start."""

from __future__ import annotations

import base64
from collections.abc import Mapping
from typing import Any, Final

import boto3

SERVICE_CREDENTIAL_CIPHERTEXT_ENV: Final = "FEEDNOW_VISPECTOR_SERVICE_CREDENTIAL_CIPHERTEXT_B64"


class KmsEncryptedServiceCredential:
    """Decrypt a ciphertext-only Lambda setting into a short-lived local value."""

    def __init__(
        self,
        ciphertext_b64: str | None = None,
        environment: str = "",
        *,
        client: Any | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        import os

        env = os.environ if environ is None else environ
        self._ciphertext_b64 = (
            ciphertext_b64 or env.get(SERVICE_CREDENTIAL_CIPHERTEXT_ENV) or ""
        ).strip()
        self._environment = (environment or env.get("FEEDNOW_ENV") or "").strip()
        self._client = client

    def current(self) -> str:
        """Decrypt with the deployment environment context; redact all failures."""
        failed = False
        try:
            ciphertext = base64.b64decode(self._ciphertext_b64, validate=True)
            response = self._kms_client().decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext={"environment": self._environment},
            )
            plaintext = response["Plaintext"]
            secret = plaintext.decode("utf-8") if isinstance(plaintext, bytes) else ""
        except Exception:
            failed = True
            secret = ""
        if failed:
            raise ValueError("KMS-encrypted service credential could not be decrypted") from None
        if not secret:
            raise ValueError("KMS-encrypted service credential is malformed")
        return secret

    def _kms_client(self) -> Any:
        if self._client is None:
            self._client = boto3.client("kms")
        return self._client

    def __repr__(self) -> str:
        return "KmsEncryptedServiceCredential(<redacted>)"

    __str__ = __repr__
