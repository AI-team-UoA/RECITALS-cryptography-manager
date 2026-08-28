"""Differentially private queries, dtype handling and budget accounting."""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from cryptography_manager.adapters import DifferentialPrivacyAdapter
from cryptography_manager.config import Config
from cryptography_manager.core.budget import PrivacyBudget
from cryptography_manager.exceptions import (
    ConfigurationError,
    DifferentialPrivacyError,
)

BOUNDED_QUERIES = [
    "Max",
    "Min",
    "Median",
    "BoundedMean",
    "BoundedSum",
    "BoundedStandardDeviation",
    "BoundedVariance",
]


class TestConfiguration:
    def test_builds_without_a_query_plan(self, dp):
        assert dp.queries == []

    def test_execute_all_requires_a_plan(self, dp):
        with pytest.raises(ConfigurationError, match="No queries configured"):
            dp.execute_all([1, 2, 3])

    def test_empty_override_falls_back_to_defaults(self):
        """An empty section is filled in from the packaged defaults.

        Config merges over DEFAULT_CONFIG, so the adapter always sees a
        populated section even when the caller supplies nothing.
        """
        adapter = DifferentialPrivacyAdapter(
            Config({"differential_privacy": {}})
        )
        assert adapter.global_budget > 0
        assert adapter.mechanism == "laplace"

    def test_absent_section_is_rejected(self, monkeypatch):
        """The guard against a wholly missing section still holds.

        Unreachable through Config today because the defaults always supply
        the section, but the adapter must not assume that stays true.
        """
        empty = Config()
        monkeypatch.setattr(
            empty, "get_submodule_config", lambda _: {}
        )
        with pytest.raises(ConfigurationError, match="Missing"):
            DifferentialPrivacyAdapter(empty)

    def test_plan_exceeding_the_budget_is_a_privacy_error(self):
        """The failure is about privacy, not configuration.

        Reporting this as a ConfigurationError would send whoever debugs it
        looking for a syntax problem instead of an over-committed budget.
        """
        over = Config(
            {
                "differential_privacy": {
                    "privacy_budget_limit": 0.1,
                    "queries": [
                        {"name": "c", "type": "Count", "epsilon": 0.5}
                    ],
                }
            }
        )
        with pytest.raises(DifferentialPrivacyError, match="exceeds"):
            DifferentialPrivacyAdapter(over)


class TestQueries:
    @pytest.mark.parametrize("query_type", ["Count"] + BOUNDED_QUERIES)
    def test_every_supported_query_runs(self, dp, query_type):
        result = dp.execute_query(
            query_type, 0.5, list(range(100)), lower_bound=0, upper_bound=99
        )
        assert isinstance(result, (int, float))

    def test_integer_data(self, dp):
        result = dp.execute_query("BoundedMean", 0.5, list(range(100)), 0, 99)
        assert isinstance(result, float)

    def test_float_data(self, dp):
        """Float columns must work.

        PyDP's dtype has to match the element type it is handed; passing
        floats while it assumes ints fails deep in the C++ binding.
        """
        values = [i + 0.5 for i in range(100)]
        result = dp.execute_query("BoundedMean", 0.5, values, 0.0, 99.5)
        assert isinstance(result, float)

    def test_numpy_input(self, dp):
        assert dp.execute_query("Count", 0.5, np.arange(50)) is not None

    def test_pandas_column(self, dp):
        frame = pd.DataFrame({"v": range(100)})
        result = dp.execute_query("Median", 0.5, frame["v"].to_numpy(), 0, 99)
        assert isinstance(result, (int, float))

    def test_float_bounds_with_integer_data(self, dp):
        assert dp.execute_query(
            "BoundedSum", 0.5, list(range(100)), 0.0, 99.0
        ) is not None

    def test_results_are_noisy(self, dp):
        """Two runs of the same query should differ.

        Identical results would mean no noise was added at all, which is the
        one failure mode that silently voids the privacy guarantee.
        """
        data = list(range(1000))
        results = {
            dp.execute_query("BoundedSum", 0.1, data, 0, 999)
            for _ in range(8)
        }
        assert len(results) > 1


class TestBounds:
    @pytest.mark.parametrize("query_type", BOUNDED_QUERIES)
    def test_bounded_queries_require_bounds(self, dp, query_type):
        dp.lower_bound = dp.upper_bound = None
        with pytest.raises(DifferentialPrivacyError, match="requires"):
            dp.execute_query(query_type, 0.5, list(range(100)))

    def test_count_needs_no_bounds(self, dp):
        dp.lower_bound = dp.upper_bound = None
        assert dp.execute_query("Count", 0.5, list(range(100))) is not None

    def test_configured_bounds_are_used_as_a_fallback(self, dp):
        assert dp.execute_query("Median", 0.5, list(range(100))) is not None

    def test_inverted_bounds_are_rejected(self, dp):
        with pytest.raises(DifferentialPrivacyError, match="must exceed"):
            dp.execute_query("BoundedMean", 0.5, [1, 2, 3], 99, 0)


class TestInputValidation:
    @pytest.mark.parametrize(
        "kwargs,match",
        [
            (dict(query_type="Mode", epsilon=0.1), "Unsupported query type"),
            (dict(query_type="Count", epsilon=0.0), "must be > 0"),
            (dict(query_type="Count", epsilon=-1.0), "must be > 0"),
        ],
    )
    def test_bad_parameters(self, dp, kwargs, match):
        with pytest.raises(DifferentialPrivacyError, match=match):
            dp.execute_query(data=list(range(10)), **kwargs)

    def test_empty_data_is_rejected(self, dp):
        with pytest.raises(DifferentialPrivacyError, match="empty data"):
            dp.execute_query("Count", 0.1, [])

    def test_non_numeric_data_is_rejected(self, dp):
        with pytest.raises(DifferentialPrivacyError, match="numeric"):
            dp.execute_query("Count", 0.1, ["a", "b"])


class TestBudgetInteraction:
    def test_budget_is_debited_when_supplied(self, dp):
        budget = PrivacyBudget(total_epsilon=1.0)
        dp.execute_query("Count", 0.3, list(range(10)), budget=budget)
        assert budget.remaining_epsilon == pytest.approx(0.7)

    def test_no_budget_means_no_accounting(self, dp):
        """Accounting belongs to the caller on this path.

        The service debits a per-user store; if the adapter also debited its
        own budget, every user's allowance would be silently halved.
        """
        before = dp.budget.remaining_epsilon
        dp.execute_query("Count", 0.3, list(range(10)))
        assert dp.budget.remaining_epsilon == before

    def test_overspend_is_refused(self, dp):
        budget = PrivacyBudget(total_epsilon=0.2)
        with pytest.raises(DifferentialPrivacyError, match="exceeded"):
            dp.execute_query("Count", 0.5, list(range(10)), budget=budget)

    def test_refused_query_costs_nothing(self, dp):
        budget = PrivacyBudget(total_epsilon=0.2)
        with pytest.raises(DifferentialPrivacyError):
            dp.execute_query("Count", 0.5, list(range(10)), budget=budget)
        assert budget.remaining_epsilon == pytest.approx(0.2)


class TestConfiguredPlan:
    def test_runs_the_repository_plan(self, repo_config):
        adapter = DifferentialPrivacyAdapter(repo_config)
        frame = pd.read_csv("examples/database.csv")
        results = adapter.execute_all(frame["ID"].to_numpy())
        assert set(results) == {
            "count", "max", "min", "median",
            "mean", "sum", "stddev", "variance",
        }
        assert all(isinstance(v, (int, float)) for v in results.values())

    def test_plan_debits_exactly_what_it_planned(self, repo_config):
        adapter = DifferentialPrivacyAdapter(repo_config)
        planned = sum(q["epsilon"] for q in adapter.queries)
        adapter.execute_all(list(range(100)))
        assert adapter.budget.info()["spent_epsilon"] == pytest.approx(
            planned
        )


class TestAdapterInterface:
    def test_returns_result_and_metadata(self, dp):
        result, meta = dp.execute(
            action="query",
            input_data={"data": list(range(100))},
            parameters={
                "query_type": "BoundedMean",
                "epsilon_cost": 0.2,
                "lower_bound": 0,
                "upper_bound": 99,
            },
        )
        assert isinstance(result, float)
        assert meta["record_count"] == 100
        assert meta["epsilon_spent"] == 0.2

    def test_empty_action_defaults_to_query(self, dp):
        result, _ = dp.execute(
            action="",
            input_data={"data": [1, 2, 3]},
            parameters={"query_type": "Count", "epsilon_cost": 0.1},
        )
        assert result is not None

    @pytest.mark.parametrize(
        "action,input_data,match",
        [
            ("bogus", {"data": [1]}, "Unsupported differential privacy"),
            ("query", {}, "must contain 'data'"),
        ],
    )
    def test_bad_input_is_rejected(self, dp, action, input_data, match):
        with pytest.raises(DifferentialPrivacyError, match=match):
            dp.execute(
                action=action,
                input_data=input_data,
                parameters={"query_type": "Count", "epsilon_cost": 0.1},
            )
