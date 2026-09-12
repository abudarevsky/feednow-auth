"""HTTP exception handlers mapping exceptions to the frozen ``Error`` envelope.

This module is the single place where HTTP status codes and
:class:`~app.models.errors.ErrorCode` values are joined (``errors.py``
deliberately encodes no status; see its module docstring). Every error
response the service produces serializes through
:class:`app.models.errors.Error`, so consumers parse exactly one shape.

Mapping rules (Phase 01 contract):

- ``RequestValidationError`` (malformed body/query/path against a Pydantic
  schema) → 422 with ``validation_error`` and one
  :class:`~app.models.errors.FieldError` per problem.
- Raised ``HTTPException`` (Starlette or FastAPI — both are registered so
  the envelope never degrades to the default ``{"detail": ...}`` shape) →
  its own status with the code from :data:`HTTP_STATUS_TO_ERROR_CODE`;
  unmapped statuses below 500 fall back to ``validation_error`` and 5xx to
  ``internal_error`` (adding a dedicated stable code is a spec-revision,
  additive-only change).
- Any other unhandled exception → 500 ``internal_error`` with a fixed
  message. Exception text is **never** echoed: it may contain credentials
  or internals (AGENTS.md no-secrets rule).

Field-level messages echo only the structural complaint (``msg``), never
the submitted value (``input``) — mirrors why ``FieldError`` has no
``input`` field. Exception: dotted paths of ``extra="forbid"`` failures
include submitted *key names* (e.g. ``body.<some_key>``); raise sites must
not use caller-controlled key names as secret carriers. The ``request_id``
is taken from the ``X-Request-ID`` header when the caller supplies one;
nothing here generates IDs.
"""

from __future__ import annotations

from typing import Final

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.models.errors import Error, ErrorCode, FieldError

#: Header carrying the caller's correlation id into ``Error.request_id``.
REQUEST_ID_HEADER: Final = "X-Request-ID"

#: Fixed envelope messages owned by the handlers (stable per contract).
VALIDATION_MESSAGE: Final = "Request validation failed"
INTERNAL_MESSAGE: Final = "Internal server error"

#: Stable HTTP status → machine code mapping for raised HTTPExceptions.
#: Statuses absent here fall back to ``validation_error`` below 500 and
#: ``internal_error`` at 500+; 401/403 producers arrive with Phases 04/05
#: authorization work and already land on the right codes.
HTTP_STATUS_TO_ERROR_CODE: Final[dict[int, ErrorCode]] = {
    400: ErrorCode.VALIDATION_ERROR,
    401: ErrorCode.UNAUTHENTICATED,
    403: ErrorCode.FORBIDDEN,
    404: ErrorCode.NOT_FOUND,
    409: ErrorCode.CONFLICT,
    422: ErrorCode.VALIDATION_ERROR,
}


def _request_id(request: Request) -> str | None:
    """Correlation id from the caller, or None. Never secret material."""
    return request.headers.get(REQUEST_ID_HEADER)


def _error_response(status_code: int, error: Error) -> JSONResponse:
    """Serialize the frozen envelope; ``mode="json"`` keeps it JSON-safe."""
    return JSONResponse(status_code=status_code, content=error.model_dump(mode="json"))


def _error_code_for_status(status_code: int) -> ErrorCode:
    """Map an HTTP status onto the closest stable code (documented fallback)."""
    mapped = HTTP_STATUS_TO_ERROR_CODE.get(status_code)
    if mapped is not None:
        return mapped
    if status_code >= 500:
        return ErrorCode.INTERNAL_ERROR
    return ErrorCode.VALIDATION_ERROR


async def request_validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Map Pydantic request-schema failures onto the ``Error`` envelope."""
    field_errors = [
        FieldError(
            field=".".join(str(part) for part in error["loc"]) or "body",
            message=str(error["msg"]),
        )
        for error in exc.errors()
    ]
    error = Error(
        code=ErrorCode.VALIDATION_ERROR,
        message=VALIDATION_MESSAGE,
        field_errors=field_errors,
        request_id=_request_id(request),
    )
    return _error_response(422, error)


async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Map raised HTTPExceptions onto the envelope at their own status.

    ``exc.detail`` is echoed as the human-readable message; raising code is
    responsible for keeping secrets out of it (review rule — the envelope
    itself never adds submitted values).
    """
    error = Error(
        code=_error_code_for_status(exc.status_code),
        message=str(exc.detail),
        request_id=_request_id(request),
    )
    return _error_response(exc.status_code, error)


async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Last-resort 500 mapping: fixed message, exception text never leaks."""
    error = Error(
        code=ErrorCode.INTERNAL_ERROR,
        message=INTERNAL_MESSAGE,
        request_id=_request_id(request),
    )
    return _error_response(500, error)


def register_exception_handlers(application: FastAPI) -> None:
    """Install the envelope handlers on ``application`` (called by create_app).

    Both ``HTTPException`` keys are registered defensively: FastAPI's
    built-in default is keyed on the subclass, so overriding only the
    Starlette class happens to work on the pinned versions but relies on
    MRO-walk details that have shifted across releases.
    """
    application.add_exception_handler(RequestValidationError, request_validation_exception_handler)
    application.add_exception_handler(StarletteHTTPException, http_exception_handler)
    application.add_exception_handler(HTTPException, http_exception_handler)
    application.add_exception_handler(Exception, unhandled_exception_handler)


__all__ = [
    "HTTP_STATUS_TO_ERROR_CODE",
    "INTERNAL_MESSAGE",
    "REQUEST_ID_HEADER",
    "VALIDATION_MESSAGE",
    "http_exception_handler",
    "register_exception_handlers",
    "request_validation_exception_handler",
    "unhandled_exception_handler",
]
