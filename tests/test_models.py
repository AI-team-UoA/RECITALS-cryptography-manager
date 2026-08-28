"""The request, response and audit envelopes."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from cryptography_manager.api.models import (
    AuditRecord,
    Backend,
    CryptographyRequest,
    DPParameters,
    Operation,
    OutputFormat,
)


class TestRequestParsing:
    @pytest.mark.parametrize(
        "written,expected",
        [
            ("differential_privacy", Operation.DIFFERENTIAL_PRIVACY),
            ("Differential Privacy", Operation.DIFFERENTIAL_PRIVACY),
            ("differential-privacy", Operation.DIFFERENTIAL_PRIVACY),
            ("SMPC", Operation.SMPC),
            ("Key Management", Operation.KEY_MANAGEMENT),
        ],
    )
    def test_prose_spellings_are_accepted(self, written, expected):
        request = CryptographyRequest(
            operation=written, backend="pydp", input_data={}
        )
        assert request.operation is expected

    def test_backend_spellings_are_folded(self):
        request = CryptographyRequest(
            operation="differential_privacy", backend="PyDP", input_data={}
        )
        assert request.backend is Backend.PYDP

    def test_defaults_are_applied(self):
        request = CryptographyRequest(
            operation="encryption", backend="tink", input_data={}
        )
        assert request.output_format is OutputFormat.JSON
        assert request.parameters == {}
        assert request.metadata == {}
        assert request.key_config is None

    def test_unknown_fields_are_rejected(self):
        """A typo must fail loudly rather than change what runs."""
        with pytest.raises(ValidationError, match="Extra inputs"):
            CryptographyRequest(
                operation="encryption",
                backend="tink",
                input_data={},
                epsilon=0.5,
            )

    @pytest.mark.parametrize("missing", ["operation", "backend", "input_data"])
    def test_required_fields(self, missing):
        payload = {
            "operation": "encryption",
            "backend": "tink",
            "input_data": {},
        }
        del payload[missing]
        with pytest.raises(ValidationError, match="Field required"):
            CryptographyRequest(**payload)

    def test_unsupported_output_format_is_rejected(self):
        """Rejected rather than silently ignored.

        Answering a JSON-LD request with plain JSON while reporting success
        would be worse than refusing it.
        """
        with pytest.raises(ValidationError):
            CryptographyRequest(
                operation="encryption",
                backend="tink",
                input_data={},
                output_format="json-ld",
            )


class TestBackendCompatibility:
    @pytest.mark.parametrize(
        "operation,backend",
        [
            ("differential_privacy", "pydp"),
            ("encryption", "tink"),
            ("key_management", "tink"),
            ("homomorphic_encryption", "pyfhel"),
            ("smpc", "mpyc"),
        ],
    )
    def test_valid_pairings(self, operation, backend):
        request = CryptographyRequest(
            operation=operation, backend=backend, input_data={}
        )
        assert request.check_backend_compatible() is None

    @pytest.mark.parametrize(
        "operation,backend",
        [
            ("differential_privacy", "tink"),
            ("encryption", "pydp"),
            ("smpc", "pyfhel"),
        ],
    )
    def test_invalid_pairings_explain_themselves(self, operation, backend):
        request = CryptographyRequest(
            operation=operation, backend=backend, input_data={}
        )
        message = request.check_backend_compatible()
        assert message is not None
        assert backend in message
        assert "supported:" in message


class TestDPParameters:
    def test_valid_parameters(self):
        params = DPParameters(
            query_type="BoundedMean",
            epsilon_cost=0.1,
            lower_bound=0,
            upper_bound=100,
        )
        assert params.epsilon_cost == 0.1

    @pytest.mark.parametrize("cost", [0, -0.5])
    def test_non_positive_cost_is_rejected(self, cost):
        with pytest.raises(ValidationError, match="greater than 0"):
            DPParameters(query_type="Count", epsilon_cost=cost)

    def test_unknown_query_type_is_rejected(self):
        with pytest.raises(ValidationError):
            DPParameters(query_type="Mode", epsilon_cost=0.1)

    def test_inverted_bounds_are_rejected(self):
        with pytest.raises(ValidationError, match="must exceed"):
            DPParameters(
                query_type="BoundedMean",
                epsilon_cost=0.1,
                lower_bound=100,
                upper_bound=0,
            )

    def test_equal_bounds_are_rejected(self):
        with pytest.raises(ValidationError, match="must exceed"):
            DPParameters(
                query_type="BoundedMean",
                epsilon_cost=0.1,
                lower_bound=5,
                upper_bound=5,
            )

    @pytest.mark.parametrize("delta", [-0.1, 1.0, 2.0])
    def test_delta_must_be_a_probability(self, delta):
        with pytest.raises(ValidationError):
            DPParameters(
                query_type="Count", epsilon_cost=0.1, delta=delta
            )


class TestAuditRecord:
    def test_identifier_and_timestamp_are_generated(self):
        record = AuditRecord(status="SUCCESS")
        assert len(record.audit_id) == 36
        assert record.timestamp.tzinfo is not None

    def test_records_carry_the_expected_fields(self):
        assert set(AuditRecord(status="SUCCESS").model_dump()) == {
            "audit_id",
            "timestamp",
            "user_id",
            "operation",
            "backend",
            "status",
            "execution_time",
            "parameters",
            "error_message",
        }
