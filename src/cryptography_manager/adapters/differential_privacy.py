"""
Differential privacy adapter backed by PyDP.

PyDP wraps Google's differential privacy library, so the noise calibration and
sensitivity analysis are inherited from a well-reviewed implementation rather
than reimplemented here. This adapter's job is to translate a configuration or
request into a correctly-parameterised PyDP algorithm and to keep epsilon
accounting honest.

Two execution paths are offered. ``execute_all`` runs a configured plan of
queries in one go and debits the adapter's own budget; it exists for library
and scripted use. ``execute_query`` runs a single query and leaves budget
accounting to the caller, which is what the service layer needs because there
the budget belongs to a user rather than to an adapter instance.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, ClassVar, final

import numpy.typing as npt

import numpy as np
from loguru import logger


from ..config import Config
from ..core.budget import PrivacyBudget
from ..exceptions import (
    BackendImportError,
    ConfigurationError,
    DifferentialPrivacyError,
)
from .base import AdapterResult, CryptographicAdapter

try:
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
except Exception as exc:  # pragma: no cover - environment problem
    raise BackendImportError(f"Failed to initialise PyDP backend: {exc}")


@final
class DifferentialPrivacyAdapter(CryptographicAdapter):
    """Differentially private aggregate queries over numeric data."""

    operation: ClassVar[str] = "differential_privacy"
    backend: ClassVar[str] = "pydp"

    _QUERY_MAP: ClassVar[dict[str, type]] = {
        "Count": Count,
        "Max": Max,
        "Min": Min,
        "Median": Median,
        "BoundedMean": BoundedMean,
        "BoundedSum": BoundedSum,
        "BoundedStandardDeviation": BoundedStandardDeviation,
        "BoundedVariance": BoundedVariance,
    }

    # Every query except Count is sensitivity-bounded and needs an explicit
    # value range. PyDP can infer bounds itself, but inference both consumes
    # privacy budget it was never told about and fails outright on small or
    # awkward datasets, so bounds are required here instead.
    _REQUIRES_BOUNDS: ClassVar[frozenset[str]] = frozenset(
        {
            "Max",
            "Min",
            "Median",
            "BoundedMean",
            "BoundedSum",
            "BoundedStandardDeviation",
            "BoundedVariance",
        }
    )

    def __init__(self, config: Config):
        """Initialise the adapter from configuration.

        The query plan and data bounds are optional: a service handling
        per-request queries supplies them with each request, while a script
        driving a configured plan supplies them up front.

        Args:
            config: Loaded configuration object.

        Raises:
            ConfigurationError: If the differential privacy section is absent
                or malformed.
            DifferentialPrivacyError: If the configured plan cannot fit inside
                the configured budget.
        """
        try:
            section = config.get_submodule_config("differential_privacy")
            if not section:
                raise ConfigurationError(
                    "Missing 'differential_privacy' configuration section",
                    config_key="differential_privacy",
                )

            self.config: dict[str, Any] = section
            self.mechanism: str = section.get("default_mechanism", "laplace")
            self.delta: float | None = section.get("default_delta")
            self.global_budget: float = float(
                section.get("privacy_budget_limit", 1.0)
            )

            self.queries: list[dict[str, Any]] = list(
                section.get("queries") or []
            )

            data_cfg = section.get("data") or {}
            self.lower_bound: float | int | None = data_cfg.get("lower_bound")
            self.upper_bound: float | int | None = data_cfg.get("upper_bound")
        except ConfigurationError:
            raise
        except Exception as exc:
            # Only genuine configuration lookup failures are translated here.
            # Wrapping everything would disguise a budget or validation error
            # as a configuration problem and mislead whoever debugs it.
            raise ConfigurationError(f"DP adapter init failed: {exc}")

        planned = sum(float(q.get("epsilon", 0.0)) for q in self.queries)
        if planned > self.global_budget:
            raise DifferentialPrivacyError(
                f"Configured queries require e={planned}, which exceeds the "
                f"budget limit e={self.global_budget}",
                mechanism=self.mechanism,
            )

        self.budget = PrivacyBudget(
            total_epsilon=self.global_budget,
            delta=self.delta,
            mechanism=self.mechanism,
        )

        logger.info(
            f"DP adapter initialised: budget e={self.global_budget}, "
            f"{len(self.queries)} configured quer"
            f"{'y' if len(self.queries) == 1 else 'ies'} "
            f"planning e={planned}"
        )

    # ---------------- helpers ----------------

    @staticmethod
    def _prepare(
        data: Sequence[Any] | npt.NDArray[Any],
    ) -> tuple[list[Any], str]:
        """Convert input data to a PyDP-compatible list and dtype.

        PyDP binds to a C++ implementation whose ``dtype`` must match the
        element type it is handed; a mismatch surfaces as an opaque
        ``TypeError`` from the binding layer, so the type is settled here.

        Args:
            data: Numeric values to aggregate.

        Returns:
            The values as a plain list, and either ``"int"`` or ``"float"``.

        Raises:
            DifferentialPrivacyError: If the data is empty or non-numeric.
        """
        values = (
            data.tolist() if isinstance(data, np.ndarray) else list(data)
        )
        if not values:
            raise DifferentialPrivacyError(
                "Cannot run a differentially private query over empty data"
            )

        try:
            if all(
                isinstance(v, (int, np.integer))
                and not isinstance(v, bool)
                for v in values
            ):
                return [int(v) for v in values], "int"
            return [float(v) for v in values], "float"
        except (TypeError, ValueError) as exc:
            raise DifferentialPrivacyError(
                f"Data must be numeric: {exc}"
            )

    @staticmethod
    def _match_dtype(value: float | int, dtype: str) -> float | int:
        """Coerce a bound to the dtype PyDP was configured with."""
        return int(value) if dtype == "int" else float(value)

    # ---------------- execution ----------------

    def execute_query(
        self,
        query_type: str,
        epsilon: float,
        data: Sequence[Any] | npt.NDArray[Any],
        lower_bound: float | int | None = None,
        upper_bound: float | int | None = None,
        budget: PrivacyBudget | None = None,
    ) -> float | int:
        """Run a single differentially private query.

        Budget accounting is the caller's responsibility unless ``budget`` is
        supplied. The service layer debits a per-user store instead, and
        double-debiting would silently halve every user's budget.

        Args:
            query_type: Name of the aggregate to compute.
            epsilon: Privacy budget to spend on this query.
            data: Numeric values to aggregate.
            lower_bound: Lower value bound; falls back to configuration.
            upper_bound: Upper value bound; falls back to configuration.
            budget: Optional budget to debit before executing.

        Returns:
            The noisy aggregate.

        Raises:
            DifferentialPrivacyError: If the query is unsupported, bounds are
                missing or invalid, or the backend fails.
        """
        if query_type not in self._QUERY_MAP:
            supported = ", ".join(sorted(self._QUERY_MAP))
            raise DifferentialPrivacyError(
                f"Unsupported query type '{query_type}'; "
                f"supported: {supported}",
                mechanism=self.mechanism,
                operation=query_type,
            )
        if epsilon <= 0:
            raise DifferentialPrivacyError(
                f"Epsilon must be > 0, got {epsilon}",
                mechanism=self.mechanism,
                operation=query_type,
            )

        values, dtype = self._prepare(data)

        kwargs: dict[str, Any] = {"epsilon": epsilon, "dtype": dtype}
        if query_type in self._REQUIRES_BOUNDS:
            low = lower_bound if lower_bound is not None else self.lower_bound
            high = upper_bound if upper_bound is not None else self.upper_bound
            if low is None or high is None:
                raise DifferentialPrivacyError(
                    f"Query '{query_type}' requires lower_bound and "
                    f"upper_bound, either per request or in configuration",
                    mechanism=self.mechanism,
                    operation=query_type,
                )
            if high <= low:
                raise DifferentialPrivacyError(
                    f"upper_bound ({high}) must exceed lower_bound ({low})",
                    mechanism=self.mechanism,
                    operation=query_type,
                )
            kwargs["lower_bound"] = self._match_dtype(low, dtype)
            kwargs["upper_bound"] = self._match_dtype(high, dtype)

        # Debit before executing: a query that runs but fails to be accounted
        # for has already leaked privacy.
        if budget is not None:
            budget.spend(epsilon)

        try:
            algorithm = self._QUERY_MAP[query_type](**kwargs)
            return algorithm.quick_result(values)
        except DifferentialPrivacyError:
            raise
        except Exception as exc:
            raise DifferentialPrivacyError(
                f"Query '{query_type}' failed: {exc}",
                mechanism=self.mechanism,
                operation=query_type,
            )

    def execute_all(
        self, data: Sequence[Any] | npt.NDArray[Any]
    ) -> dict[str, float | int]:
        """Run every configured query in order, debiting the adapter budget.

        Args:
            data: Numeric values to aggregate.

        Returns:
            Query name mapped to its noisy result.

        Raises:
            ConfigurationError: If no queries are configured.
            DifferentialPrivacyError: If the budget is exceeded or a query
                fails.
        """
        if not self.queries:
            raise ConfigurationError(
                "No queries configured; provide a 'queries' list or call "
                "execute_query directly",
                config_key="differential_privacy.queries",
            )

        results: dict[str, float | int] = {}
        for query in self.queries:
            results[query["name"]] = self.execute_query(
                query_type=query["type"],
                epsilon=float(query["epsilon"]),
                data=data,
                lower_bound=query.get("lower_bound"),
                upper_bound=query.get("upper_bound"),
                budget=self.budget,
            )
        return results

    # ---------------- adapter entry point ----------------

    def execute(
        self,
        *,
        action: str,
        input_data: dict[str, Any],
        parameters: dict[str, Any],
        key_config: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Run one differentially private query for the service layer.

        Args:
            action: ``"query"``, or empty to default to it.
            input_data: ``{"data": [...]}``.
            parameters: ``query_type`` and ``epsilon_cost``, optionally
                ``lower_bound`` and ``upper_bound``.
            key_config: Unused.

        Returns:
            A ``(result, metadata)`` pair. Budget state is not included here;
            the service layer adds it from the per-user store.

        Raises:
            DifferentialPrivacyError: If the action is unknown or the query
                cannot be run.
        """
        if action not in ("", "query"):
            raise DifferentialPrivacyError(
                f"Unsupported differential privacy action: {action}",
                mechanism=self.mechanism,
                operation=action,
            )
        if "data" not in input_data:
            raise DifferentialPrivacyError(
                "input_data must contain 'data'", mechanism=self.mechanism
            )

        query_type = str(parameters.get("query_type", ""))
        epsilon = float(parameters.get("epsilon_cost", 0.0))
        result = self.execute_query(
            query_type=query_type,
            epsilon=epsilon,
            data=input_data["data"],
            lower_bound=parameters.get("lower_bound"),
            upper_bound=parameters.get("upper_bound"),
        )
        return (
            result,
            {
                "query_type": query_type,
                "epsilon_spent": epsilon,
                "mechanism": self.mechanism,
                "record_count": len(input_data["data"]),
            },
        )
