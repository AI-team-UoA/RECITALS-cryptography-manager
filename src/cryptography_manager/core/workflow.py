"""
Request workflow: validate, pre-check, execute, audit, respond.

This is where the pieces are sequenced. Every path through it -- including
every rejection -- ends in exactly one audit record, so a request that was
refused is as traceable as one that succeeded.

The ordering deviates from the obvious "check the budget first" in one place:
a differential privacy request's budget cost lives in its parameters, so those
parameters have to be validated before the budget can be checked against them.
Validating first also means a malformed request never touches budget state.
"""

from __future__ import annotations

import time
from typing import Any, final

from loguru import logger
from pydantic import ValidationError

from ..api.models import (
    CryptographyRequest,
    CryptographyResponse,
    DPParameters,
    Operation,
)
from ..exceptions import (
    CryptographyManagerError,
    DifferentialPrivacyError,
    OperationNotImplementedError,
)
from .audit import AuditLogger
from .budget import BudgetStore
from .manager import CryptographyManager
from .status import WorkflowStatus

#: Sub-operations understood per operation, used to reject a bad action before
#: an adapter is constructed.
VALID_ACTIONS: dict[Operation, frozenset[str]] = {
    Operation.DIFFERENTIAL_PRIVACY: frozenset({"query"}),
    Operation.ENCRYPTION: frozenset({"encrypt", "decrypt"}),
    Operation.KEY_MANAGEMENT: frozenset(
        {"generate_key", "rotate_key", "key_info"}
    ),
}


@final
class WorkflowOutcome:
    """The result of running a workflow, ready to be turned into a response."""

    def __init__(
        self,
        status: WorkflowStatus,
        response: CryptographyResponse,
    ) -> None:
        self.status = status
        self.response = response


@final
class CryptographyWorkflow:
    """Sequences a single cryptographic request end to end."""

    def __init__(
        self,
        manager: CryptographyManager,
        audit: AuditLogger,
        budget_store: BudgetStore,
    ) -> None:
        """Initialise the workflow.

        Args:
            manager: Dispatches requests to backend adapters.
            audit: Records every outcome.
            budget_store: Per-user privacy budget accounting.
        """
        self.manager = manager
        self.audit = audit
        self.budget_store = budget_store

    def run(
        self,
        request: CryptographyRequest | None,
        user_id: str | None,
        auth_error: str | None = None,
    ) -> WorkflowOutcome:
        """Execute one request and produce its response.

        Args:
            request: The parsed request, or ``None`` if authorization failed
                before the body was considered.
            user_id: Authenticated user, or ``None`` if unauthenticated.
            auth_error: Why authorization failed, if it did.

        Returns:
            The workflow outcome, carrying both status and response body.
        """
        started = time.perf_counter()
        operation = request.operation.value if request else None
        backend = request.backend.value if request else None
        parameters = dict(request.parameters) if request else {}

        def finish(
            status: WorkflowStatus,
            result: Any = None,
            metadata: dict[str, Any] | None = None,
            error: str | None = None,
        ) -> WorkflowOutcome:
            elapsed = time.perf_counter() - started
            record = self.audit.record(
                status=status.value,
                user_id=user_id,
                operation=operation,
                backend=backend,
                execution_time=elapsed,
                parameters=parameters,
                error_message=error,
            )
            return WorkflowOutcome(
                status,
                CryptographyResponse(
                    status=status.value,
                    result=result,
                    metadata=metadata or {},
                    execution_time=round(elapsed, 6),
                    audit_id=record.audit_id,
                    errors=error,
                ),
            )

        # 1. Authorization.
        if user_id is None or request is None:
            return finish(
                WorkflowStatus.UNAUTHORIZED,
                error=auth_error or "Missing or invalid authorization token",
            )

        # 2. Envelope validation: is this backend able to do this operation?
        incompatible = request.check_backend_compatible()
        if incompatible:
            return finish(WorkflowStatus.VALIDATION_ERROR, error=incompatible)

        action = str(
            request.parameters.get("action", "")
        ) or _default_action(request.operation)
        allowed = VALID_ACTIONS.get(request.operation)
        if allowed is not None and action not in allowed:
            return finish(
                WorkflowStatus.VALIDATION_ERROR,
                error=(
                    f"Unsupported action '{action}' for operation "
                    f"'{request.operation.value}'; supported: "
                    f"{', '.join(sorted(allowed))}"
                ),
            )

        # 3. Operation-specific validation and pre-checks.
        epsilon_cost: float | None = None
        if request.operation is Operation.DIFFERENTIAL_PRIVACY:
            try:
                dp_params = DPParameters(
                    **{
                        k: v
                        for k, v in request.parameters.items()
                        if k != "action"
                    }
                )
            except ValidationError as exc:
                return finish(
                    WorkflowStatus.VALIDATION_ERROR,
                    error=_first_error(exc),
                )
            epsilon_cost = dp_params.epsilon_cost

            remaining = self.budget_store.remaining(user_id)
            if self.budget_store.is_exhausted(user_id):
                return finish(
                    WorkflowStatus.BUDGET_EXHAUSTED,
                    metadata=self.budget_store.info(user_id),
                    error=(
                        f"Privacy budget exhausted for user '{user_id}'"
                    ),
                )
            if epsilon_cost > remaining:
                return finish(
                    WorkflowStatus.INSUFFICIENT_BUDGET,
                    metadata=self.budget_store.info(user_id),
                    error=(
                        f"Requested cost e={epsilon_cost} exceeds remaining "
                        f"budget e={remaining}"
                    ),
                )

        # 4. Execution.
        try:
            result, metadata = self.manager.execute(request)
        except OperationNotImplementedError as exc:
            return finish(WorkflowStatus.NOT_IMPLEMENTED, error=str(exc))
        except (CryptographyManagerError, ValueError) as exc:
            # A backend refusing malformed input is the caller's problem, so
            # this is reported as a validation failure rather than a fault.
            return finish(WorkflowStatus.VALIDATION_ERROR, error=str(exc))
        except Exception as exc:  # pragma: no cover - unexpected fault
            logger.exception("Unexpected failure during execution")
            return finish(
                WorkflowStatus.FAILED, error=f"Execution failed: {exc}"
            )

        # 5. Budget is debited only after the query actually ran, so a failed
        # query does not cost the user any privacy.
        if epsilon_cost is not None:
            try:
                self.budget_store.spend(user_id, epsilon_cost)
            except DifferentialPrivacyError as exc:
                # Reachable only if a concurrent request drained the budget
                # between the check above and here.
                return finish(
                    WorkflowStatus.INSUFFICIENT_BUDGET,
                    metadata=self.budget_store.info(user_id),
                    error=str(exc),
                )
            metadata = {**metadata, **self.budget_store.info(user_id)}

        return finish(WorkflowStatus.SUCCESS, result=result, metadata=metadata)


def _default_action(operation: Operation) -> str:
    """Return the sub-operation assumed when a caller names none."""
    from .manager import DEFAULT_ACTIONS

    return DEFAULT_ACTIONS.get(operation, "")


def _first_error(exc: ValidationError) -> str:
    """Render the first validation problem as a single readable sentence."""
    errors = exc.errors()
    if not errors:
        return "Parameter validation failed"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    message = first.get("msg", "invalid value")
    return f"{location}: {message}" if location else message
