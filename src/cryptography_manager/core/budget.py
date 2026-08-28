"""
Privacy budget accounting.

Differential privacy guarantees only hold if the total epsilon spent against a
dataset is bounded. The remaining budget is retrieved per user before each
query runs, which means accounting has to outlive a single adapter instance --
hence a store keyed by user rather than a counter living on the adapter.

Two rejection states are tracked separately: a budget already exhausted
(nothing left at all) and one merely insufficient for the requested query. They
map to different HTTP responses, and the distinction is useful to a caller
deciding whether to retry with a cheaper query or give up entirely.
"""

from __future__ import annotations

import json
import os
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import final

from loguru import logger

from ..exceptions import DifferentialPrivacyError

#: Budgets are floating point; comparisons need a tolerance so that spending
#: exactly the remaining budget is not rejected by representation error.
EPSILON_TOLERANCE = 1e-9


@dataclass
class PrivacyBudget:
    """Epsilon accounting for a single dataset or session."""

    total_epsilon: float
    delta: float | None = None
    mechanism: str = "laplace"

    remaining_epsilon: float = field(init=False, repr=False, default=0.0)

    def __post_init__(self) -> None:
        if self.total_epsilon <= 0:
            raise DifferentialPrivacyError(
                "Total privacy budget epsilon must be > 0",
                mechanism=self.mechanism,
            )
        self.remaining_epsilon = self.total_epsilon

    @property
    def is_exhausted(self) -> bool:
        """Whether no budget remains at all."""
        return self.remaining_epsilon <= EPSILON_TOLERANCE

    def can_afford(self, epsilon: float) -> bool:
        """Whether ``epsilon`` can be spent without overdrawing."""
        return epsilon <= self.remaining_epsilon + EPSILON_TOLERANCE

    def spend(self, epsilon: float) -> None:
        """Consume epsilon from the remaining budget.

        Args:
            epsilon: Privacy cost of the query.

        Raises:
            DifferentialPrivacyError: If the cost is non-positive or exceeds
                the remaining budget.
        """
        if epsilon <= 0:
            raise DifferentialPrivacyError(
                "Spent epsilon must be > 0", mechanism=self.mechanism
            )
        if not self.can_afford(epsilon):
            raise DifferentialPrivacyError(
                f"Privacy budget exceeded: requested e={epsilon}, "
                f"remaining e={self.remaining_epsilon}",
                mechanism=self.mechanism,
            )
        # Clamp so repeated spending cannot drift below zero.
        self.remaining_epsilon = max(0.0, self.remaining_epsilon - epsilon)

    def reset(self) -> None:
        """Restore the full budget. Only valid for a new dataset."""
        self.remaining_epsilon = self.total_epsilon

    def info(self) -> dict[str, float | None]:
        """Return the current accounting state."""
        return {
            "total_epsilon": self.total_epsilon,
            "remaining_epsilon": self.remaining_epsilon,
            "spent_epsilon": self.total_epsilon - self.remaining_epsilon,
            "delta": self.delta,
        }


class BudgetStore(ABC):
    """Per-user privacy budget accounting."""

    total_epsilon: float
    delta: float | None
    _lock: threading.Lock

    def __init__(self, total_epsilon: float, delta: float | None = None):
        """Initialise the store.

        Args:
            total_epsilon: Budget granted to each user.
            delta: Privacy leakage probability recorded alongside the budget.
        """
        if total_epsilon <= 0:
            raise DifferentialPrivacyError(
                "Total privacy budget epsilon must be > 0"
            )
        self.total_epsilon = total_epsilon
        self.delta = delta
        self._lock = threading.Lock()

    @abstractmethod
    def _load(self) -> dict[str, float]:
        """Return the mapping of user ID to remaining epsilon."""

    @abstractmethod
    def _save(self, state: dict[str, float]) -> None:
        """Persist the mapping of user ID to remaining epsilon."""

    def remaining(self, user_id: str) -> float:
        """Return the epsilon still available to a user."""
        with self._lock:
            return self._load().get(user_id, self.total_epsilon)

    def spend(self, user_id: str, epsilon: float) -> float:
        """Deduct epsilon from a user's budget.

        Args:
            user_id: Identifier of the requesting user.
            epsilon: Privacy cost of the query.

        Returns:
            The remaining budget after the deduction.

        Raises:
            DifferentialPrivacyError: If the cost is non-positive or exceeds
                the remaining budget.
        """
        if epsilon <= 0:
            raise DifferentialPrivacyError("Spent epsilon must be > 0")
        with self._lock:
            state = self._load()
            current = state.get(user_id, self.total_epsilon)
            if epsilon > current + EPSILON_TOLERANCE:
                raise DifferentialPrivacyError(
                    f"Privacy budget exceeded: requested e={epsilon}, "
                    f"remaining e={current}"
                )
            updated = current - epsilon
            # Snap a floating-point residue to zero. Without this a budget
            # spent down in fractional steps lands on something like 1e-16
            # instead of 0.0, and reads as "insufficient" forever rather than
            # "exhausted".
            if updated <= EPSILON_TOLERANCE:
                updated = 0.0
            state[user_id] = updated
            self._save(state)
            logger.info(
                f"Budget spent: user={user_id} e={epsilon} "
                f"remaining={state[user_id]}"
            )
            return state[user_id]

    def is_exhausted(self, user_id: str) -> bool:
        """Whether a user has no usable budget left.

        Uses the same tolerance as spending, so a budget drained by
        fractional steps is reported as exhausted rather than as an
        unusable sliver.
        """
        return self.remaining(user_id) <= EPSILON_TOLERANCE

    def reset(self, user_id: str) -> None:
        """Restore a user's full budget. Only valid for a new dataset."""
        with self._lock:
            state = self._load()
            state[user_id] = self.total_epsilon
            self._save(state)

    def info(self, user_id: str) -> dict[str, float | None]:
        """Return a user's accounting state, for response metadata."""
        remaining = self.remaining(user_id)
        return {
            "total_epsilon": self.total_epsilon,
            "remaining_epsilon": remaining,
            "spent_epsilon": self.total_epsilon - remaining,
            "delta": self.delta,
        }


@final
class InMemoryBudgetStore(BudgetStore):
    """Budget store backed by a process-local dictionary.

    Budgets are lost on restart, and are not shared across workers. Suitable
    for tests, examples and single-process development only.
    """

    def __init__(self, total_epsilon: float, delta: float | None = None):
        super().__init__(total_epsilon, delta)
        self._state: dict[str, float] = {}

    def _load(self) -> dict[str, float]:
        return self._state

    def _save(self, state: dict[str, float]) -> None:
        self._state = state


@final
class FileBudgetStore(BudgetStore):
    """Budget store backed by a JSON file.

    Survives restarts, which matters because a budget that resets when the
    container restarts is not a privacy guarantee. Writes are atomic via
    ``os.replace``. This is still single-node: a multi-replica deployment
    needs a shared backend, and this class is the seam to swap it in at.
    """

    def __init__(
        self,
        total_epsilon: float,
        path: str | Path,
        delta: float | None = None,
    ):
        super().__init__(total_epsilon, delta)
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, float]:
        if not self.path.exists():
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
            return {str(k): float(v) for k, v in data.items()}
        except Exception as exc:
            # Refusing to continue is the safe failure mode: silently starting
            # from a full budget would hand out epsilon that was already spent.
            raise DifferentialPrivacyError(
                f"Failed to read budget store at {self.path}: {exc}"
            )

    def _save(self, state: dict[str, float]) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with open(tmp, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.path)
