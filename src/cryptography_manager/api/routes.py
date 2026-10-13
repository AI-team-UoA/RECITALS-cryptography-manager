"""
HTTP routes.

The request body is read and validated inside the handler rather than through
a typed signature. That is deliberate: the framework would otherwise consume
and parse the body before the handler runs, which would bypass the audit trail,
answer an unauthenticated caller with a schema complaint instead of a refusal,
and buffer an arbitrarily large payload before anyone had a chance to object.
Authorization is decided first, the body is then read under a size ceiling, and
every rejection still produces an audit record.
"""

from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Header, Request
from fastapi.responses import JSONResponse
from pydantic import ValidationError

from ..api.models import CryptographyRequest, CryptographyResponse
from ..core.status import WorkflowStatus, http_status_for
from .auth import extract_bearer

router = APIRouter()


@router.get("/health", tags=["service"])
async def health(request: Request) -> dict[str, Any]:
    """Report service liveness and which capabilities are available."""
    state = request.app.state
    return {
        "status": "ok",
        "auth_mode": state.settings.auth_mode,
        "operations": {
            "differential_privacy": "available",
            "encryption": "available",
            "key_management": "available",
            "homomorphic_encryption": "not_implemented",
            "smpc": "not_implemented",
        },
    }


@router.post(
    "/cryptography",
    tags=["cryptography"],
    summary="Execute a cryptographic operation",
    response_model=CryptographyResponse,
    responses={
        200: {"description": "Operation completed successfully"},
        400: {"description": "Configuration or parameter validation failed"},
        401: {"description": "Authorization token missing or invalid"},
        403: {"description": "Token lacks the permission for this action"},
        429: {"description": "Privacy budget exhausted"},
        500: {"description": "Unexpected execution error"},
        413: {"description": "Request body exceeds the configured limit"},
        501: {"description": "Operation recognised but not implemented"},
    },
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "application/json": {
                    "schema": CryptographyRequest.model_json_schema()
                }
            },
        }
    },
)
async def cryptography(
    request: Request,
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Execute one cryptographic operation.

    Args:
        request: The incoming request, carrying application state.
        authorization: Bearer token issued by the identity provider.

    Returns:
        The response envelope, with a status code reflecting the outcome.
    """
    state = request.app.state
    workflow = state.workflow

    auth = state.verifier.verify(extract_bearer(authorization))
    if not auth.ok:
        outcome = workflow.run(None, None, auth.error)
        return _respond(outcome.status, outcome.response)

    def reject(status: WorkflowStatus, error: str) -> JSONResponse:
        outcome = workflow.reject(
            status,
            auth.user_id,
            error,
            client_id=auth.client_id,
            token_issuer=auth.issuer,
        )
        return _respond(outcome.status, outcome.response)

    limit = state.settings.max_request_bytes
    body, oversized = await _read_capped(request, limit)
    if oversized:
        return reject(
            WorkflowStatus.PAYLOAD_TOO_LARGE,
            f"Request body exceeds the {limit} byte limit",
        )

    try:
        payload = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError as exc:
        return reject(
            WorkflowStatus.VALIDATION_ERROR,
            f"Request body is not valid JSON: {exc}",
        )

    if not isinstance(payload, dict):
        return reject(
            WorkflowStatus.VALIDATION_ERROR,
            "Request body must be a JSON object",
        )

    try:
        parsed = CryptographyRequest.model_validate(payload)
    except ValidationError as exc:
        return reject(WorkflowStatus.VALIDATION_ERROR, _render(exc))

    outcome = workflow.run(
        parsed,
        auth.user_id,
        permissions=auth.permissions,
        client_id=auth.client_id,
        token_issuer=auth.issuer,
    )
    return _respond(outcome.status, outcome.response)


async def _read_capped(
    request: Request, limit: int
) -> tuple[bytes, bool]:
    """Read a request body, refusing to buffer more than ``limit`` bytes.

    A declared Content-Length is checked first, which rejects an honest
    oversized client without reading anything. The stream is then counted as
    it arrives, because a client can omit the header or send a chunked body
    and the declared length cannot be trusted either way.

    Args:
        request: The incoming request.
        limit: Largest body to accept, in bytes.

    Returns:
        The body, and whether the limit was exceeded. When it was, the body
        is empty: it is deliberately not retained.
    """
    declared = request.headers.get("content-length")
    if declared is not None:
        try:
            if int(declared) > limit:
                return b"", True
        except ValueError:
            pass

    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > limit:
            return b"", True
        chunks.append(chunk)
    return b"".join(chunks), False


def _respond(
    status: WorkflowStatus, response: CryptographyResponse
) -> JSONResponse:
    """Render a workflow outcome as an HTTP response."""
    headers = (
        {"WWW-Authenticate": "Bearer"}
        if status is WorkflowStatus.UNAUTHORIZED
        else None
    )
    return JSONResponse(
        status_code=http_status_for(status),
        content=response.model_dump(mode="json"),
        headers=headers,
    )


def _render(exc: ValidationError) -> str:
    """Summarise validation failures as a single readable message."""
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(p) for p in error.get("loc", ()))
        message = error.get("msg", "invalid value")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts) or "Request validation failed"
