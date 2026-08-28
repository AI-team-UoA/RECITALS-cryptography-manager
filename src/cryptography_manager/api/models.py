"""
Pydantic data models for the Cryptography Manager API.

These models are the single source of truth for the request envelope, the
response envelope and the audit record. They deliberately avoid importing any
cryptographic backend so that the schema stays importable even when optional
extras such as PyDP, Pyfhel or MPyC are not installed.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, final

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _normalise(value: Any) -> Any:
    """Fold prose spellings onto enum values.

    Callers write operations in prose ("differential privacy", "SMPC") while
    the wire format uses snake_case. Accepting both keeps the API forgiving
    without widening the set of operations actually accepted.
    """
    if isinstance(value, str):
        return value.strip().lower().replace(" ", "_").replace("-", "_")
    return value


@final
class Operation(str, Enum):
    """Cryptographic operation requested by the caller."""

    DIFFERENTIAL_PRIVACY = "differential_privacy"
    ENCRYPTION = "encryption"
    KEY_MANAGEMENT = "key_management"
    HOMOMORPHIC_ENCRYPTION = "homomorphic_encryption"
    SMPC = "smpc"


@final
class Backend(str, Enum):
    """Cryptographic library used to service an operation."""

    PYDP = "pydp"
    TINK = "tink"
    PYFHEL = "pyfhel"
    MPYC = "mpyc"


@final
class OutputFormat(str, Enum):
    """Desired response encoding.

    JSON-LD is a plausible future addition, but its vocabulary would have to
    align with the Compliance Manager's DPV graphs, which are not pinned down
    yet. Only JSON is accepted for now; requesting anything else is a
    validation error rather than a silently ignored field.
    """

    JSON = "json"


@final
class DPQueryType(str, Enum):
    """Aggregate queries supported by the differential privacy adapter.

    Mirrors the PyDP Laplacian algorithms wired up in the DP adapter. Declared
    here rather than imported from the adapter so that importing the schema
    never requires PyDP to be installed.
    """

    COUNT = "Count"
    MAX = "Max"
    MIN = "Min"
    MEDIAN = "Median"
    BOUNDED_MEAN = "BoundedMean"
    BOUNDED_SUM = "BoundedSum"
    BOUNDED_STDDEV = "BoundedStandardDeviation"
    BOUNDED_VARIANCE = "BoundedVariance"


# Which backends can legitimately service which operation. Checked before any
# adapter is instantiated so that an impossible pairing is a clean 400 rather
# than an import error or an obscure failure deeper in the stack.
COMPATIBLE_BACKENDS: dict[Operation, frozenset[Backend]] = {
    Operation.DIFFERENTIAL_PRIVACY: frozenset({Backend.PYDP}),
    Operation.ENCRYPTION: frozenset({Backend.TINK}),
    Operation.KEY_MANAGEMENT: frozenset({Backend.TINK}),
    Operation.HOMOMORPHIC_ENCRYPTION: frozenset({Backend.PYFHEL}),
    Operation.SMPC: frozenset({Backend.MPYC}),
}


@final
class CryptographyRequest(BaseModel):
    """Request envelope for ``POST /cryptography``.

    The ``Authorization`` header is not modelled here; it is handled by the
    auth dependency before the body is ever parsed.
    """

    model_config = ConfigDict(extra="forbid", use_enum_values=False)

    operation: Operation = Field(
        description="Cryptographic operation to execute.",
    )
    backend: Backend = Field(
        description="Cryptographic library used.",
    )
    input_data: dict[str, Any] = Field(
        description="Data to be processed.",
    )
    parameters: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Operation-specific configuration (DP: query_type, epsilon_cost; "
            "HE: scheme, context; SMPC: participants, protocol)."
        ),
    )
    key_config: dict[str, Any] | None = Field(
        default=None,
        description="Key generation or key loading configuration.",
    )
    output_format: OutputFormat = Field(
        default=OutputFormat.JSON,
        description="Desired output format.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional execution metadata.",
    )

    @field_validator("operation", "backend", "output_format", mode="before")
    @classmethod
    def _fold_spelling(cls, value: Any) -> Any:
        return _normalise(value)

    def check_backend_compatible(self) -> str | None:
        """Verify the requested backend can service the operation.

        Returns:
            An error message if the pairing is invalid, otherwise ``None``.
        """
        allowed = COMPATIBLE_BACKENDS[self.operation]
        if self.backend in allowed:
            return None
        names = ", ".join(sorted(b.value for b in allowed))
        return (
            f"Backend '{self.backend.value}' cannot service operation "
            f"'{self.operation.value}'; supported: {names}"
        )


@final
class DPParameters(BaseModel):
    """Differential privacy parameters carried in ``parameters``.

    Validated separately from the envelope because the required fields depend
    on the operation. ``epsilon_cost`` is the privacy price of the query and is
    checked against the caller's remaining budget before execution.
    """

    model_config = ConfigDict(extra="forbid")

    query_type: DPQueryType
    epsilon_cost: float = Field(
        gt=0.0,
        description="Privacy budget consumed by this query.",
    )
    delta: float | None = Field(default=None, ge=0.0, lt=1.0)
    lower_bound: float | None = None
    upper_bound: float | None = None

    @field_validator("upper_bound")
    @classmethod
    def _bounds_ordered(
        cls, upper: float | None, info: Any
    ) -> float | None:
        lower = info.data.get("lower_bound")
        if lower is not None and upper is not None and upper <= lower:
            raise ValueError(
                f"upper_bound ({upper}) must exceed lower_bound ({lower})"
            )
        return upper


@final
class CryptographyResponse(BaseModel):
    """Response envelope for ``POST /cryptography``."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(description="Execution status.")
    result: Any = Field(
        default=None,
        description="Output of the cryptographic operation.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Operation-specific metadata, e.g. remaining_budget.",
    )
    execution_time: float = Field(
        description="Duration of execution, in seconds.",
    )
    audit_id: str = Field(
        description="Identifier of the generated audit record.",
    )
    errors: dict[str, Any] | str | None = Field(
        default=None,
        description="Populated only if status indicates failure.",
    )


@final
class AuditRecord(BaseModel):
    """Structured audit entry produced for every request.

    Sensitive material -- secret and private keys, plaintext values, secret
    shares and intermediate cryptographic state -- must never reach this model.
    Sanitisation happens in ``core.audit`` before construction.
    """

    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
    )
    user_id: str | None = None
    operation: str | None = None
    backend: str | None = None
    status: str = ""
    execution_time: float = 0.0
    parameters: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
