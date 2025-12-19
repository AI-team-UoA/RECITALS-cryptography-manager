"""
Differential Privacy adapter using PyDP.

This module provides the adapter for differential privacy operations
using the PyDP library.
"""

import sys
from dataclasses import dataclass, field
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

logger.remove()  # Remove the default handler.
logger.add(sys.stderr, level="INFO")  # Only print logs of INFO level and above


@dataclass
class PrivacyBudget:
    total_epsilon: float
    delta: float | None
    mechanism: str

    remaining_epsilon: float = field(init=False, repr=False, default=0.0)

    def __post_init__(self):
        if self.total_epsilon <= 0:
            raise DifferentialPrivacyError(
                "Total privacy budget epsilon must be > 0",
                mechanism=self.mechanism,
            )
        self.remaining_epsilon: float = self.total_epsilon

    def spend(self, epsilon: float) -> None:
        """Consume epsilon from the remaining privacy budget."""
        if epsilon <= 0:
            raise DifferentialPrivacyError(
                "Spent epsilon must be > 0",
                mechanism=self.mechanism,
            )

        if epsilon > self.remaining_epsilon:
            raise DifferentialPrivacyError(
                f"Privacy budget exceeded: Requested ε={epsilon}, remaining ε={self.remaining_epsilon}",
                mechanism=self.mechanism,
            )

        self.remaining_epsilon -= epsilon

    def reset(self) -> None:
        """Reset budget (ONLY for new datasets)."""
        self.remaining_epsilon = self.total_epsilon

    def info(self) -> dict[str, float | None]:
        """Return current accounting state."""
        return {
            "total_epsilon": self.total_epsilon,
            "remaining_epsilon": self.remaining_epsilon,
            "delta": self.delta,
        }


@final
class DifferentialPrivacyAdapter:
    """Class implementation for CM's differential privacy adapter."""

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

            self.budget = PrivacyBudget(epsilon, delta, mechanism)

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

    def _consume_budget(self, epsilon: float) -> float:
        self.budget.spend(epsilon)
        logger.debug(
            f"Spent ε={epsilon}, remaining ε={self.budget.remaining_epsilon}"
        )
        return epsilon

    ########################## Statistics functions ###########################

    def Count(self, data: np.ndarray, epsilon: float) -> int | float:
        """Compute dp count.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP count
        """
        from pydp.algorithms.laplacian import Count

        eps = self._consume_budget(epsilon)
        return Count(eps).quick_result(data.tolist())

    def Max(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp max.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP max
        """
        from pydp.algorithms.laplacian import Max

        eps = self._consume_budget(epsilon)
        return Max(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())

    def Min(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp min.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP min
        """
        from pydp.algorithms.laplacian import Min

        eps = self._consume_budget(epsilon)
        return Min(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())

    def Median(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp median value.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP median
        """
        from pydp.algorithms.laplacian import Median

        eps = self._consume_budget(epsilon)
        return Median(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())

    def BoundedMean(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp average of values.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP mean
        """
        from pydp.algorithms.laplacian import BoundedMean

        eps = self._consume_budget(epsilon)
        return BoundedMean(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())

    def BoundedSum(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp sum.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP sum
        """
        from pydp.algorithms.laplacian import BoundedSum

        eps = self._consume_budget(epsilon)
        return BoundedSum(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())

    def BoundedStandardDeviation(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp standard deviation of the dataset values.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP standard deviation
        """
        from pydp.algorithms.laplacian import BoundedStandardDeviation

        eps = self._consume_budget(epsilon)
        return BoundedStandardDeviation(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())

    def BoundedVariance(
        self,
        data: np.ndarray,
        epsilon: float,
        lower_bound: int | float,
        upper_bound: int | float,
    ) -> int | float:
        """Compute dp variance of the dataset values.

        Args:
            data (np.ndarray): A numpy array of the data to count

        Returns:
            int | float: DP variance
        """
        from pydp.algorithms.laplacian import BoundedVariance

        eps = self._consume_budget(epsilon)
        return BoundedVariance(
            epsilon=eps,
            lower_bound=lower_bound,
            upper_bound=upper_bound,
        ).quick_result(data.tolist())
