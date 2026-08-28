"""Privacy budget accounting and persistence."""

from __future__ import annotations

import pytest

from cryptography_manager.core.budget import (
    EPSILON_TOLERANCE,
    FileBudgetStore,
    InMemoryBudgetStore,
    PrivacyBudget,
)
from cryptography_manager.exceptions import DifferentialPrivacyError


class TestPrivacyBudget:
    def test_starts_full(self):
        assert PrivacyBudget(total_epsilon=1.0).remaining_epsilon == 1.0

    @pytest.mark.parametrize("total", [0.0, -1.0])
    def test_non_positive_total_is_rejected(self, total):
        with pytest.raises(DifferentialPrivacyError, match="must be > 0"):
            PrivacyBudget(total_epsilon=total)

    def test_spending_reduces_the_remainder(self):
        budget = PrivacyBudget(total_epsilon=1.0)
        budget.spend(0.3)
        assert budget.remaining_epsilon == pytest.approx(0.7)

    def test_overspending_is_refused_and_changes_nothing(self):
        budget = PrivacyBudget(total_epsilon=1.0)
        with pytest.raises(DifferentialPrivacyError, match="exceeded"):
            budget.spend(1.5)
        assert budget.remaining_epsilon == 1.0

    @pytest.mark.parametrize("amount", [0.0, -0.1])
    def test_non_positive_spend_is_rejected(self, amount):
        with pytest.raises(DifferentialPrivacyError, match="must be > 0"):
            PrivacyBudget(total_epsilon=1.0).spend(amount)

    def test_spending_the_exact_remainder_is_allowed(self):
        budget = PrivacyBudget(total_epsilon=1.0)
        budget.spend(1.0)
        assert budget.is_exhausted

    def test_reset_restores_the_full_budget(self):
        budget = PrivacyBudget(total_epsilon=1.0)
        budget.spend(0.8)
        budget.reset()
        assert budget.remaining_epsilon == 1.0

    def test_info_reports_the_full_picture(self):
        budget = PrivacyBudget(total_epsilon=1.0, delta=1e-5)
        budget.spend(0.25)
        info = budget.info()
        assert info["spent_epsilon"] == pytest.approx(0.25)
        assert info["remaining_epsilon"] == pytest.approx(0.75)
        assert info["delta"] == 1e-5


class TestBudgetStore:
    """Behaviour shared by every store implementation."""

    @pytest.fixture(params=["memory", "file"])
    def store(self, request, tmp_path):
        if request.param == "memory":
            return InMemoryBudgetStore(total_epsilon=1.0)
        return FileBudgetStore(
            total_epsilon=1.0, path=tmp_path / "budgets.json"
        )

    def test_new_user_starts_with_the_full_budget(self, store):
        assert store.remaining("alice") == 1.0

    def test_spending_is_tracked_per_user(self, store):
        store.spend("alice", 0.4)
        assert store.remaining("alice") == pytest.approx(0.6)
        assert store.remaining("bob") == 1.0

    def test_overspending_is_refused(self, store):
        store.spend("alice", 0.8)
        with pytest.raises(DifferentialPrivacyError, match="exceeded"):
            store.spend("alice", 0.5)
        assert store.remaining("alice") == pytest.approx(0.2)

    def test_reset_restores_one_user_only(self, store):
        store.spend("alice", 0.5)
        store.spend("bob", 0.5)
        store.reset("alice")
        assert store.remaining("alice") == 1.0
        assert store.remaining("bob") == pytest.approx(0.5)

    def test_fractional_spending_lands_exactly_on_zero(self, store):
        """Repeated fractional spends must not leave a residue.

        Floating point drift would otherwise leave something like 1e-16,
        which reads as an unusable sliver of budget rather than an exhausted
        one -- and reports the wrong status to the caller forever.
        """
        for _ in range(3):
            store.spend("alice", 0.2)
        store.spend("alice", 0.4)
        assert store.remaining("alice") == 0.0
        assert store.is_exhausted("alice")

    def test_is_exhausted_tolerates_residue(self, store):
        store.spend("alice", 1.0 - EPSILON_TOLERANCE / 2)
        assert store.is_exhausted("alice")

    def test_info_shape(self, store):
        assert set(store.info("alice")) == {
            "total_epsilon",
            "remaining_epsilon",
            "spent_epsilon",
            "delta",
        }


class TestFileBudgetStore:
    def test_state_survives_a_new_instance(self, tmp_path):
        path = tmp_path / "nested" / "budgets.json"
        FileBudgetStore(total_epsilon=1.0, path=path).spend("carol", 0.25)
        assert FileBudgetStore(
            total_epsilon=1.0, path=path
        ).remaining("carol") == pytest.approx(0.75)

    def test_parent_directory_is_created(self, tmp_path):
        path = tmp_path / "a" / "b" / "budgets.json"
        FileBudgetStore(total_epsilon=1.0, path=path)
        assert path.parent.is_dir()

    def test_corrupt_state_fails_loudly(self, tmp_path):
        """A damaged store must not silently reset budgets.

        Starting from a full budget after a read failure would hand out
        epsilon that had already been spent.
        """
        path = tmp_path / "budgets.json"
        path.write_text("{ not json")
        store = FileBudgetStore(total_epsilon=1.0, path=path)
        with pytest.raises(DifferentialPrivacyError, match="Failed to read"):
            store.remaining("alice")
