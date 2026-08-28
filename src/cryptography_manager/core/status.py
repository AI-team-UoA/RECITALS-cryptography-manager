"""
Workflow status codes and their HTTP mapping.

The CrM distinguishes between the *workflow status* -- the outcome of the
internal auth -> pre-check -> validate -> execute -> audit pipeline -- and the
*HTTP status* eventually returned to the caller. Keeping them separate matters
because every workflow outcome, including the rejected ones, still produces an
audit record.
"""

from enum import Enum
from typing import final


@final
class WorkflowStatus(str, Enum):
    """Outcome of a cryptographic workflow.

    ``NOT_IMPLEMENTED`` covers operations that are accepted by the schema but
    have no adapter yet, so a caller can tell "you asked for something that
    does not exist" apart from "you asked for something not built yet".
    """

    SUCCESS = "SUCCESS"
    UNAUTHORIZED = "UNAUTHORIZED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    INSUFFICIENT_BUDGET = "INSUFFICIENT_BUDGET"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    FAILED = "FAILED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"

    @property
    def is_success(self) -> bool:
        """Whether this status represents a completed operation."""
        return self is WorkflowStatus.SUCCESS


# Workflow status to HTTP response code.
#
# BUDGET_EXHAUSTED maps to 429 rather than 400: a client that distinguishes the
# two can implement backoff correctly, and an exhausted budget really is a
# rate-limit-shaped condition -- the request was well-formed, the caller has
# simply used up what they were allotted.
_HTTP_STATUS: dict[WorkflowStatus, int] = {
    WorkflowStatus.SUCCESS: 200,
    WorkflowStatus.VALIDATION_ERROR: 400,
    WorkflowStatus.INSUFFICIENT_BUDGET: 400,
    WorkflowStatus.UNAUTHORIZED: 403,
    WorkflowStatus.BUDGET_EXHAUSTED: 429,
    WorkflowStatus.NOT_IMPLEMENTED: 501,
    # A FAILED status means the backend raised during execution, after
    # validation had already passed -- so the request itself was well-formed
    # and the fault is ours, not the caller's. 500 is the honest default.
    WorkflowStatus.FAILED: 500,
}


def http_status_for(status: WorkflowStatus) -> int:
    """Map a workflow status onto its HTTP response code.

    Args:
        status: The workflow outcome to translate.

    Returns:
        The HTTP status code to return to the caller.
    """
    return _HTTP_STATUS[status]
