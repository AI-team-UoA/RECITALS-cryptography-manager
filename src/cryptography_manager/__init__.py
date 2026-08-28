"""
RECITALS Cryptography Manager.

A unified interface over differential privacy, encryption and key management,
usable either as a Python library or as a REST service.
"""

from . import adapters
from .config import Config
from .core.manager import CryptographyManager

__all__ = ["Config", "CryptographyManager", "adapters", "main"]


def main() -> None:
    """Console script entry point: serve the REST API."""
    from .main import main as _serve

    _serve()
