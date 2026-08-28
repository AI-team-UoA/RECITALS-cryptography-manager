"""
Custom exceptions for the Cryptography Manager.

This module defines all custom exceptions used throughout the library,
providing clear error handling and debugging information.
"""


class ImportError(Exception):
    """Base exception for all import errors."""

    pass


class CryptographyManagerError(Exception):
    """Base exception for all Cryptography Manager errors."""

    def __init__(self, message: str, error_code: str | None = None) -> None:
        """Initialize the base exception.

        Args:
            message: Human-readable error message
            error_code: Optional error code for programmatic handling
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code


class OperationNotImplementedError(CryptographyManagerError):
    """Raised for a recognised operation that has no adapter yet.

    Distinct from an unknown operation: the request was well-formed and names
    something the component intends to support, so the caller should be told
    "not yet" rather than "no such thing".
    """

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize the not-implemented error.

        Args:
            message: Human-readable error message
            operation: The operation that is not yet available
            error_code: Optional error code for programmatic handling
        """
        super().__init__(message, error_code)
        self.operation = operation


class ConfigurationError(CryptographyManagerError):
    """Raised when there are configuration-related errors."""

    def __init__(
        self,
        message: str,
        config_key: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize configuration error.

        Args:
            message: Human-readable error message
            config_key: The configuration key that caused the error
            error_code: Optional error code for programmatic handling
        """
        super().__init__(message, error_code)
        self.config_key = config_key


class AdapterError(CryptographyManagerError):
    """Raised when there are adapter-related errors."""

    def __init__(
        self,
        message: str,
        adapter_name: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize adapter error.

        Args:
            message: Human-readable error message
            adapter_name: Name of the adapter that caused the error
            operation: The operation that failed
            error_code: Optional error code for programmatic handling
        """
        super().__init__(message, error_code)
        self.adapter_name = adapter_name
        self.operation = operation


class KeyManagementError(CryptographyManagerError):
    """Raised when there are key management-related errors."""

    def __init__(
        self,
        message: str,
        key_id: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize key management error.

        Args:
            message: Human-readable error message
            key_id: ID of the key that caused the error
            operation: The key operation that failed
            error_code: Optional error code for programmatic handling
        """
        super().__init__(message, error_code)
        self.key_id = key_id
        self.operation = operation


class AuditError(CryptographyManagerError):
    """Raised when there are audit logging-related errors."""

    def __init__(
        self,
        message: str,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize audit error.

        Args:
            message: Human-readable error message
            operation: The operation that failed to be audited
            error_code: Optional error code for programmatic handling
        """
        super().__init__(message, error_code)
        self.operation = operation


class HomomorphicEncryptionError(AdapterError):
    """Raised when there are homomorphic encryption-related errors."""

    def __init__(
        self,
        message: str,
        scheme: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize homomorphic encryption error.

        Args:
            message: Human-readable error message
            scheme: The HE scheme that caused the error
            operation: The HE operation that failed
            error_code: Optional error code for programmatic handling
        """
        super().__init__(
            message, "homomorphic_encryption", operation, error_code
        )
        self.scheme = scheme


class SecureMultiPartyComputationError(AdapterError):
    """Raised when there are secure multi-party computation-related errors."""

    def __init__(
        self,
        message: str,
        protocol: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize SMPC error.

        Args:
            message: Human-readable error message
            protocol: The SMPC protocol that caused the error
            operation: The SMPC operation that failed
            error_code: Optional error code for programmatic handling
        """
        super().__init__(
            message, "secure_multiparty_computation", operation, error_code
        )
        self.protocol = protocol


class DifferentialPrivacyError(AdapterError):
    """Raised when there are differential privacy-related errors."""

    def __init__(
        self,
        message: str,
        mechanism: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize differential privacy error.

        Args:
            message: Human-readable error message
            mechanism: The DP mechanism that caused the error
            operation: The DP operation that failed
            error_code: Optional error code for programmatic handling
        """
        super().__init__(
            message, "differential_privacy", operation, error_code
        )
        self.mechanism = mechanism


class StandardCryptographyError(AdapterError):
    """Raised when there are standard cryptography-related errors."""

    def __init__(
        self,
        message: str,
        algorithm: str | None = None,
        operation: str | None = None,
        error_code: str | None = None,
    ) -> None:
        """Initialize standard cryptography error.

        Args:
            message: Human-readable error message
            algorithm: The cryptographic algorithm that caused the error
            operation: The crypto operation that failed
            error_code: Optional error code for programmatic handling
        """
        super().__init__(
            message, "standard_cryptography", operation, error_code
        )
        self.algorithm = algorithm
