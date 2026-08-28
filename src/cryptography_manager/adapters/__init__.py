"""Cryptographic backend adapters.

Homomorphic encryption and secure multi-party computation are recognised
operations but have no adapter yet; the manager reports them as not
implemented rather than pretending they are unknown.
"""

from .base import AdapterResult, CryptographicAdapter
from .differential_privacy import DifferentialPrivacyAdapter
from .encryption import EncryptionAdapter

__all__ = [
    "AdapterResult",
    "CryptographicAdapter",
    "DifferentialPrivacyAdapter",
    "EncryptionAdapter",
]
