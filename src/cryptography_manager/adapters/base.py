"""
Common interface shared by all cryptographic adapters.

Adapters deliberately speak plain Python types rather than the API's Pydantic
models. Translation between the request envelope and an adapter call happens in
``core.manager``. Keeping that boundary means an adapter can be imported and
unit-tested without the web stack installed, and a backend that is missing from
the environment only breaks its own operation.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

# An adapter returns the operation result plus operation-specific metadata,
# which is surfaced in the response envelope's ``metadata`` field.
AdapterResult = tuple[Any, dict[str, Any]]


class CryptographicAdapter(ABC):
    """Base class for every cryptographic backend adapter."""

    #: Operation this adapter services, e.g. ``"differential_privacy"``.
    operation: ClassVar[str] = ""
    #: Library backing the adapter, e.g. ``"pydp"``.
    backend: ClassVar[str] = ""

    @abstractmethod
    def execute(
        self,
        *,
        action: str,
        input_data: dict[str, Any],
        parameters: dict[str, Any],
        key_config: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Run one operation against the backend.

        Args:
            action: Sub-operation to perform, e.g. ``"encrypt"``.
            input_data: Data to be processed.
            parameters: Operation-specific configuration.
            key_config: Key generation or key loading configuration.

        Returns:
            A ``(result, metadata)`` pair.

        Raises:
            AdapterError: If the operation cannot be completed.
        """
        raise NotImplementedError
