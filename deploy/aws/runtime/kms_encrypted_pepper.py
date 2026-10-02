"""Decrypt the KMS-encrypted API-key pepper supplied in Lambda configuration."""

from __future__ import annotations

import base64
import os
import threading
from collections.abc import Mapping
from typing import Any, Final

import boto3

from app.auth.pepper import StaticPepper

PEPPER_CIPHERTEXT_ENV: Final = "FEEDNOW_PEPPER_CIPHERTEXT_B64"
ENVIRONMENT_ENV: Final = "FEEDNOW_ENV"


class KmsEncryptedPepper:
    """Decrypt once per Lambda container; only ciphertext is in Lambda config."""

    def __init__(
        self,
        ciphertext_b64: str | None = None,
        environment: str | None = None,
        *,
        client: Any | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        env = os.environ if environ is None else environ
        self._ciphertext_b64 = (ciphertext_b64 or env.get(PEPPER_CIPHERTEXT_ENV) or "").strip()
        self._environment = (environment or env.get(ENVIRONMENT_ENV) or "").strip()
        if not self._ciphertext_b64:
            raise ValueError(f"{PEPPER_CIPHERTEXT_ENV} is required")
        if self._environment not in {"dev", "staging", "prod"}:
            raise ValueError(f"{ENVIRONMENT_ENV} must be dev, staging, or prod")
        self._client = client
        self._static: StaticPepper | None = None
        self._lock = threading.Lock()

    def current(self) -> bytes:
        """Decrypt and validate the pepper once, caching only in process memory."""
        with self._lock:
            if self._static is None:
                self._static = StaticPepper(self._decrypt())
            return self._static.current()

    def _decrypt(self) -> bytes:
        try:
            ciphertext = base64.b64decode(self._ciphertext_b64, validate=True)
            response = self._kms_client().decrypt(
                CiphertextBlob=ciphertext,
                EncryptionContext={"environment": self._environment},
            )
            plaintext = response["Plaintext"]
        except Exception:
            raise ValueError("KMS-encrypted API-key pepper could not be decrypted") from None
        if not isinstance(plaintext, bytes) or not plaintext:
            raise ValueError("KMS-encrypted API-key pepper is malformed")
        return plaintext

    def _kms_client(self) -> Any:
        if self._client is None:
            self._client = boto3.client("kms")
        return self._client

    def __repr__(self) -> str:
        return "KmsEncryptedPepper(<redacted>)"

    __str__ = __repr__
