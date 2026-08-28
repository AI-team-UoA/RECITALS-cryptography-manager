"""
HTTP routes.

The request body is accepted as a raw mapping and validated inside the handler
rather than through a typed signature. That is deliberate: the framework would
otherwise reject a malformed body before the handler runs, which would both
bypass the audit trail and answer an unauthenticated caller with a schema
complaint instead of a refusal. Authorization is therefore always decided
first, and every rejection still produces an audit record.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Header, Request
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
        403: {"description": "Authorization token missing or invalid"},
        429: {"description": "Privacy budget exhausted"},
        500: {"description": "Unexpected execution error"},
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
    payload: dict[str, Any] = Body(default_factory=dict),
    authorization: str | None = Header(default=None),
) -> JSONResponse:
    """Execute one cryptographic operation.

    Args:
        request: The incoming request, carrying application state.
        payload: The request envelope.
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

    try:
        parsed = CryptographyRequest.model_validate(payload)
    except ValidationError as exc:
        # Validation failures are run back through the workflow so that a
        # malformed request is audited exactly like any other outcome.
        outcome = workflow.run(None, auth.user_id, None)
        outcome.response.status = WorkflowStatus.VALIDATION_ERROR.value
        outcome.response.errors = _render(exc)
        return _respond(WorkflowStatus.VALIDATION_ERROR, outcome.response)

    outcome = workflow.run(parsed, auth.user_id)
    return _respond(outcome.status, outcome.response)


def _respond(
    status: WorkflowStatus, response: CryptographyResponse
) -> JSONResponse:
    """Render a workflow outcome as an HTTP response."""
    return JSONResponse(
        status_code=http_status_for(status),
        content=response.model_dump(mode="json"),
    )


def _render(exc: ValidationError) -> str:
    """Summarise validation failures as a single readable message."""
    parts = []
    for error in exc.errors()[:5]:
        location = ".".join(str(p) for p in error.get("loc", ()))
        message = error.get("msg", "invalid value")
        parts.append(f"{location}: {message}" if location else message)
    return "; ".join(parts) or "Request validation failed"
