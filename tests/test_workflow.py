"""The request workflow: validation, pre-checks, execution and auditing."""

from __future__ import annotations

import pytest

from cryptography_manager.api.models import CryptographyRequest
from cryptography_manager.core.status import WorkflowStatus, http_status_for

from .conftest import SAMPLE_BOUNDS, SAMPLE_DATA


def dp_request(**parameters) -> CryptographyRequest:
    """A differential privacy request with overridable parameters."""
    merged = {
        "query_type": "BoundedMean",
        "epsilon_cost": 0.2,
        **SAMPLE_BOUNDS,
    }
    merged.update(parameters)
    return CryptographyRequest(
        operation="differential_privacy",
        backend="pydp",
        input_data={"data": SAMPLE_DATA},
        parameters=merged,
    )


class TestStatusMapping:
    @pytest.mark.parametrize(
        "status,code",
        [
            (WorkflowStatus.SUCCESS, 200),
            (WorkflowStatus.VALIDATION_ERROR, 400),
            (WorkflowStatus.INSUFFICIENT_BUDGET, 400),
            (WorkflowStatus.UNAUTHORIZED, 403),
            (WorkflowStatus.BUDGET_EXHAUSTED, 429),
            (WorkflowStatus.FAILED, 500),
            (WorkflowStatus.NOT_IMPLEMENTED, 501),
        ],
    )
    def test_each_status_maps_to_its_code(self, status, code):
        assert http_status_for(status) == code

    def test_every_status_is_mapped(self):
        for status in WorkflowStatus:
            assert http_status_for(status) > 0


class TestSuccess:
    def test_differential_privacy_query(self, workflow):
        outcome = workflow.run(dp_request(), "alice")
        assert outcome.status is WorkflowStatus.SUCCESS
        assert isinstance(outcome.response.result, float)
        assert outcome.response.errors is None
        assert outcome.response.execution_time > 0

    def test_remaining_budget_is_reported(self, workflow):
        outcome = workflow.run(dp_request(), "alice")
        assert outcome.response.metadata["remaining_epsilon"] == (
            pytest.approx(0.8)
        )

    def test_budget_decrements_across_calls(self, workflow, budget_store):
        for _ in range(3):
            workflow.run(dp_request(), "alice")
        assert budget_store.remaining("alice") == pytest.approx(0.4)

    def test_budgets_are_isolated_per_user(self, workflow, budget_store):
        workflow.run(dp_request(), "alice")
        assert budget_store.remaining("bob") == 1.0


class TestAuthorization:
    def test_no_user_is_unauthorized(self, workflow):
        outcome = workflow.run(dp_request(), None, "token expired")
        assert outcome.status is WorkflowStatus.UNAUTHORIZED
        assert outcome.response.errors == "token expired"

    def test_absent_request_is_unauthorized(self, workflow):
        outcome = workflow.run(None, None, "no token")
        assert outcome.status is WorkflowStatus.UNAUTHORIZED


class TestBudgetPreChecks:
    def test_cost_above_the_remainder_is_insufficient(self, workflow):
        outcome = workflow.run(dp_request(epsilon_cost=5.0), "alice")
        assert outcome.status is WorkflowStatus.INSUFFICIENT_BUDGET

    def test_a_refused_request_costs_nothing(self, workflow, budget_store):
        workflow.run(dp_request(epsilon_cost=5.0), "alice")
        assert budget_store.remaining("alice") == 1.0

    def test_a_drained_budget_is_exhausted_not_insufficient(
        self, workflow, budget_store
    ):
        """The two rejections are genuinely different answers.

        'Exhausted' means stop asking; 'insufficient' means this particular
        query was too expensive. A caller can act on the distinction.
        """
        budget_store.spend("alice", 1.0)
        outcome = workflow.run(dp_request(epsilon_cost=0.1), "alice")
        assert outcome.status is WorkflowStatus.BUDGET_EXHAUSTED

    def test_budget_is_debited_only_after_a_successful_query(
        self, workflow, budget_store
    ):
        workflow.run(dp_request(query_type="Nonsense"), "alice")
        assert budget_store.remaining("alice") == 1.0


class TestValidation:
    @pytest.mark.parametrize(
        "request_factory,reason",
        [
            (
                lambda: CryptographyRequest(
                    operation="differential_privacy",
                    backend="tink",
                    input_data={"data": [1]},
                ),
                "backend cannot service the operation",
            ),
            (
                lambda: dp_request(epsilon_cost=-1),
                "negative epsilon",
            ),
            (
                lambda: CryptographyRequest(
                    operation="encryption",
                    backend="tink",
                    input_data={"plaintext": "x"},
                    parameters={"action": "melt"},
                ),
                "unknown action",
            ),
        ],
    )
    def test_invalid_requests_are_rejected(
        self, workflow, request_factory, reason
    ):
        outcome = workflow.run(request_factory(), "alice")
        assert outcome.status is WorkflowStatus.VALIDATION_ERROR, reason
        assert outcome.response.errors


class TestNotImplemented:
    @pytest.mark.parametrize(
        "operation,backend",
        [("homomorphic_encryption", "pyfhel"), ("smpc", "mpyc")],
    )
    def test_pending_operations_report_not_implemented(
        self, workflow, operation, backend
    ):
        outcome = workflow.run(
            CryptographyRequest(
                operation=operation, backend=backend, input_data={"x": 1}
            ),
            "alice",
        )
        assert outcome.status is WorkflowStatus.NOT_IMPLEMENTED


class TestEncryptionThroughTheWorkflow:
    def test_generate_encrypt_decrypt(self, workflow):
        outcome = workflow.run(
            CryptographyRequest(
                operation="key_management",
                backend="tink",
                input_data={},
                parameters={"action": "generate_key"},
            ),
            "alice",
        )
        keyset = outcome.response.result["keyset"]

        outcome = workflow.run(
            CryptographyRequest(
                operation="encryption",
                backend="tink",
                input_data={"plaintext": "top secret"},
                parameters={"action": "encrypt", "associated_data": "ctx"},
                key_config={"keyset": keyset},
            ),
            "alice",
        )
        ciphertext = outcome.response.result["ciphertext"]

        outcome = workflow.run(
            CryptographyRequest(
                operation="encryption",
                backend="tink",
                input_data={"ciphertext": ciphertext},
                parameters={"action": "decrypt", "associated_data": "ctx"},
                key_config={"keyset": keyset},
            ),
            "alice",
        )
        assert outcome.response.result["plaintext"] == "top secret"

    def test_encryption_does_not_touch_the_privacy_budget(
        self, workflow, budget_store
    ):
        workflow.run(
            CryptographyRequest(
                operation="key_management",
                backend="tink",
                input_data={},
                parameters={"action": "generate_key"},
            ),
            "alice",
        )
        assert budget_store.remaining("alice") == 1.0


class TestAuditing:
    def test_every_outcome_is_audited(
        self, workflow, budget_store, audit_records
    ):
        """Including the rejections.

        A refused request that leaves no trace is exactly the one an
        investigator will later want to find.
        """
        workflow.run(dp_request(), "alice")
        workflow.run(dp_request(), None, "no token")
        workflow.run(dp_request(epsilon_cost=5.0), "alice")
        workflow.run(dp_request(query_type="Nope"), "alice")
        workflow.run(
            CryptographyRequest(
                operation="smpc", backend="mpyc", input_data={}
            ),
            "alice",
        )
        budget_store.spend("alice", budget_store.remaining("alice"))
        workflow.run(dp_request(epsilon_cost=0.1), "alice")

        statuses = {record["status"] for record in audit_records()}
        assert statuses == {
            "SUCCESS",
            "UNAUTHORIZED",
            "INSUFFICIENT_BUDGET",
            "VALIDATION_ERROR",
            "NOT_IMPLEMENTED",
            "BUDGET_EXHAUSTED",
        }

    def test_the_response_audit_id_matches_the_written_record(
        self, workflow, audit_records
    ):
        outcome = workflow.run(dp_request(), "alice")
        assert audit_records()[0]["audit_id"] == outcome.response.audit_id

    def test_dataset_never_reaches_the_audit_trail(
        self, workflow, audit_path
    ):
        workflow.run(dp_request(), "alice")
        assert "[0, 1, 2" not in audit_path.read_text()
