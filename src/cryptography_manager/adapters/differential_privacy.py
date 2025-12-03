"""
Differential Privacy adapter using PyDP.

This module provides the adapter for differential privacy operations
using the PyDP library.
"""

from dataclasses import dataclass
from typing import Any, final

import numpy as np
import pandas as pd
from loguru import logger

from ..config import DEFAULT_CONFIG, Config
from ..exceptions import (
    ConfigurationError,
    DifferentialPrivacyError,
    ImportError,
)


@dataclass
class PrivacyParameters:
    epsilon: float
    delta: float | None
    mechanism: str


@final
class DifferentialPrivacyAdapter:
    """Class implementation for CM's differential privacy adapter.

    TODO: Extended description
    """

    def __init__(
        self,
        config: Config,
        epsilon: float,
        delta: float | None = None,
        mechanism: str | None = None,
    ):
        """Differential privacy adapter constructor.

        Args:
            config (Config): A Config instance to get the DP-specific configuration.
        """

        defaults: dict[str, Any] = DEFAULT_CONFIG["differential_privacy"]

        # Setup configuration
        try:
            self.config: dict[str, Any] = config.get_submodule_config(
                "differential_privacy"
            )

            # Setup privacy parameters
            if not mechanism:
                mechanism: str = self.config["default_mechanism"]

            # Check epsilon
            min_epsilon = self.config.get(
                "min_epsilon", defaults["min_epsilon"]
            )
            max_epsilon = self.config.get(
                "max_epsilon", defaults["max_epsilon"]
            )
            if epsilon < min_epsilon or epsilon > max_epsilon:
                raise DifferentialPrivacyError(
                    f"Epsilon must be between {min_epsilon} and {max_epsilon}, \
                    got {epsilon}",
                    mechanism=mechanism,
                )

            if not delta:
                delta = self.config["default_delta"]

            self.params = PrivacyParameters(epsilon, delta, mechanism)

            logger.info("DP adapter configured successfully")

        except Exception as e:
            raise ConfigurationError(
                f"Failed initialization based on config: {e}"
            )

        # PyDP initialization
        try:
            import pydp as dp

            logger.info("PyDP backend initialized successfully")

        except Exception as e:
            raise ImportError(f"Failed to initialize PyDP backend: {e}")
