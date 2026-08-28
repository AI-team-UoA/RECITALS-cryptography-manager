"""
Unified entry point for every cryptographic operation.

The manager owns adapter lifecycles and translates the request envelope into an
adapter call. Adapters are built lazily and cached: constructing one can be
expensive, and a backend that is absent from the environment should only break
the operation that needs it rather than preventing the service from starting.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, final

from loguru import logger

from ..api.models import Backend, CryptographyRequest, Operation
from ..config import Config
from ..exceptions import (
    ConfigurationError,
    CryptographyManagerError,
    OperationNotImplementedError,
)

if TYPE_CHECKING:
    from ..adapters import (
        CryptographicAdapter,
        DifferentialPrivacyAdapter,
        EncryptionAdapter,
    )

#: Operations that are part of the interface but have no adapter yet. Listing
#: them explicitly means a caller gets "not implemented" rather than "unknown
#: operation", which are genuinely different answers.
PENDING_OPERATIONS: frozenset[Operation] = frozenset(
    {Operation.HOMOMORPHIC_ENCRYPTION, Operation.SMPC}
)

#: Default sub-operation per operation, used when the caller does not name one.
DEFAULT_ACTIONS: dict[Operation, str] = {
    Operation.DIFFERENTIAL_PRIVACY: "query",
    Operation.ENCRYPTION: "encrypt",
    Operation.KEY_MANAGEMENT: "generate_key",
}


@final
class CryptographyManager:
    """Routes cryptographic requests to the appropriate backend adapter."""

    def __init__(
        self,
        config: Config | None = None,
        config_file: str | None = None,
    ) -> None:
        """Initialize the Cryptography Manager.

        Args:
            config: Optional configuration object.
            config_file: Optional path to a configuration file.

        Raises:
            ConfigurationError: If the configuration file cannot be loaded.
            CryptographyManagerError: If initialization otherwise fails.
        """
        try:
            if config is not None:
                self.config = config
            else:
                self.config = Config()
                if config_file:
                    self.config.load_from_file(config_file)
        except ConfigurationError:
            raise
        except Exception as exc:
            raise CryptographyManagerError(
                f"Failed to initialize Cryptography Manager: {exc}"
            )

        self._instances: dict[str, Any] = {}
        logger.info("Cryptography Manager initialized successfully")

    # ---------------- adapter access ----------------

    def differential_privacy(self) -> "DifferentialPrivacyAdapter":
        """Return the DP adapter, building it on first use."""
        if "differential_privacy" not in self._instances:
            from ..adapters import DifferentialPrivacyAdapter

            self._instances["differential_privacy"] = (
                DifferentialPrivacyAdapter(self.config)
            )
        return self._instances["differential_privacy"]

    def encryption(self) -> "EncryptionAdapter":
        """Return the encryption adapter, building it on first use."""
        if "encryption" not in self._instances:
            from ..adapters import EncryptionAdapter

            self._instances["encryption"] = EncryptionAdapter()
        return self._instances["encryption"]

    def adapter_for(self, operation: Operation) -> "CryptographicAdapter":
        """Return the adapter servicing an operation.

        Args:
            operation: The requested operation.

        Returns:
            The adapter instance.

        Raises:
            OperationNotImplementedError: If the operation is recognised but
                has no adapter yet.
        """
        if operation in PENDING_OPERATIONS:
            raise OperationNotImplementedError(
                f"Operation '{operation.value}' is not implemented yet",
                operation=operation.value,
            )
        if operation is Operation.DIFFERENTIAL_PRIVACY:
            return self.differential_privacy()
        if operation in (Operation.ENCRYPTION, Operation.KEY_MANAGEMENT):
            return self.encryption()
        raise OperationNotImplementedError(
            f"No adapter registered for operation '{operation.value}'",
            operation=operation.value,
        )

    def backend_for(self, operation: Operation) -> Backend:
        """Return the backend library servicing an operation."""
        if operation is Operation.DIFFERENTIAL_PRIVACY:
            return Backend.PYDP
        if operation in (Operation.ENCRYPTION, Operation.KEY_MANAGEMENT):
            return Backend.TINK
        if operation is Operation.HOMOMORPHIC_ENCRYPTION:
            return Backend.PYFHEL
        return Backend.MPYC

    # ---------------- dispatch ----------------

    def execute(
        self, request: CryptographyRequest
    ) -> tuple[Any, dict[str, Any]]:
        """Run a request against its backend.

        Budget accounting and auditing are handled by the workflow layer, not
        here, so that this method stays usable directly from library code.

        Args:
            request: The validated request envelope.

        Returns:
            A ``(result, metadata)`` pair.

        Raises:
            OperationNotImplementedError: If the operation has no adapter.
            AdapterError: If the backend fails.
        """
        adapter = self.adapter_for(request.operation)
        action = str(
            request.parameters.get(
                "action", DEFAULT_ACTIONS.get(request.operation, "")
            )
        )
        return adapter.execute(
            action=action,
            input_data=request.input_data,
            parameters=request.parameters,
            key_config=request.key_config,
        )
