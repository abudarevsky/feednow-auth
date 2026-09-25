"""AWS Lambda adapter for the Cognito user-pool trigger."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app.auth.cognito_triggers import cognito_trigger_handler


def handler(event: Mapping[str, Any], context: object = None) -> dict[str, Any]:
    """Dispatch the plain-data Cognito event without external API calls."""
    return cognito_trigger_handler(event, context)
