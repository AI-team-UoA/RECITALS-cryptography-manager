"""
Default configuration values for the Cryptography Manager.

This module defines all default configuration values used throughout
the library, organized by component and feature area.
"""

from typing import Any

# Default configuration structure
DEFAULT_CONFIG: dict[str, Any] = {
    # General settings
    "general": {
        "debug": False,
    },
    # Differential Privacy settings
    "differential_privacy": {
        "default_mechanism": "laplace",
        "default_epsilon": 1.0,
        "default_delta": 1e-5,
        "max_epsilon": 10.0,
        "min_epsilon": 0.1,
        "privacy_budget_limit": 100.0,
        "noise_scale_factor": 1.0,
    },
}

# Configuration validation rules
VALIDATION_RULES: dict[str, dict[str, Any]] = {
    "differential_privacy.default_epsilon": {
        "type": float,
        "min": 0.1,
        "max": 10.0,
    },
    "differential_privacy.default_delta": {
        "type": float,
        "min": 1e-10,
        "max": 1.0,
    },
}
