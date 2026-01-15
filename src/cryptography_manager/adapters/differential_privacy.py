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
from pydp.algorithms.laplacian import (
    BoundedMean,
    BoundedStandardDeviation,
    BoundedSum,
    BoundedVariance,
    Count,
    Max,
    Median,
    Min,
)

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

    _QUERY_MAP = {
        "Count": Count,
        "Max": Max,
        "Min": Min,
        "Median": Median,
        "BoundedMean": BoundedMean,
        "BoundedSum": BoundedSum,
        "BoundedStandardDeviation": BoundedStandardDeviation,
        "BoundedVariance": BoundedVariance,
    }

    def __init__(self, config: Config):
        try:
            self.config = config.get_submodule_config("differential_privacy")

            self.mechanism = self.config["default_mechanism"]
            self.delta = self.config.get("default_delta")

            # ---- GLOBAL BUDGET ----
            self.global_budget = self.config["privacy_budget_limit"]

            # ---- QUERY PLAN ----
            self.queries = self.config.get("queries", [])
            if not self.queries:
                raise ConfigurationError("No DP queries configured")

            requested_epsilon = sum(q["epsilon"] for q in self.queries)
            if requested_epsilon > self.global_budget:
                raise DifferentialPrivacyError(
                    f"Total query epsilon {requested_epsilon} exceeds "
                    f"global budget {self.global_budget}",
                    mechanism=self.mechanism,
                )

            self.budget = PrivacyBudget(
                total_epsilon=self.global_budget,
                delta=self.delta,
                mechanism=self.mechanism,
            )

            # ---- DATA BOUNDS ----
            data_cfg = self.config["data"]
            self.lower_bound = data_cfg["lower_bound"]
            self.upper_bound = data_cfg["upper_bound"]

            logger.info(
                f"DP adapter initialized: "
                f"ε_total={self.global_budget}, "
                f"ε_planned={requested_epsilon}"
            )

        except Exception as e:
            raise ConfigurationError(f"DP adapter init failed: {e}")

        try:
            import pydp

            logger.info("PyDP backend initialized")
        except Exception as e:
            raise ImportError(f"Failed to initialize PyDP backend: {e}")

    def execute_all(self, data: np.ndarray) -> dict[str, int | float]:
        """
        Execute all configured DP queries in order.
        """
        results = {}

        for query in self.queries:
            result = self._execute_single_query(
                qtype=query["type"],
                epsilon=query["epsilon"],
                data=data,
            )
            results[query["name"]] = result

        return results

    def _execute_single_query(
        self,
        qtype: str,
        epsilon: float,
        data: np.ndarray,
    ) -> int | float:
        """
        Execute a single DP query using the registry.
        """

        if qtype not in self._QUERY_MAP:
            raise DifferentialPrivacyError(
                f"Unsupported DP query type: {qtype}",
                mechanism=self.mechanism,
            )

        # Spend budget first
        self.budget.spend(epsilon)

        algo_cls = self._QUERY_MAP[qtype]

        if qtype == "Count":
            return algo_cls(epsilon).quick_result(data.tolist())

        return algo_cls(
            epsilon=epsilon,
            lower_bound=self.lower_bound,
            upper_bound=self.upper_bound,
        ).quick_result(data.tolist())
