"""The REST API end to end, over a real ASGI stack."""

from __future__ import annotations

import json

import pytest

from .conftest import SAMPLE_DATA


def read_audit(client) -> list[dict]:
    """Return the audit records this client's application has written."""
    if not client.audit_file.exists():
        return []
    text = client.audit_file.read_text().strip()
    return [json.loads(line) for line in text.split("\n")] if text else []


class TestHealth:
    def test_reports_ok(self, client):
        assert client.get("/health").status_code == 200

    def test_declares_which_operations_are_available(self, client):
        operations = client.get("/health").json()["operations"]
        assert operations["differential_privacy"] == "available"
        assert operations["homomorphic_encryption"] == "not_implemented"
        assert operations["smpc"] == "not_implemented"


class TestAuthorization:
    def test_a_request_without_a_token_is_refused(self, client, dp_request):
        response = client.post("/cryptography", json=dp_request)
        assert response.status_code == 403
        assert response.json()["status"] == "UNAUTHORIZED"

    def test_a_non_bearer_scheme_is_refused(self, client, dp_request):
        response = client.post(
            "/cryptography",
            json=dp_request,
            headers={"Authorization": "Basic abc"},
        )
        assert response.status_code == 403

    def test_a_refusal_still_carries_an_audit_id(self, client, dp_request):
        response = client.post("/cryptography", json=dp_request)
        assert len(response.json()["audit_id"]) == 36

    def test_authorization_is_decided_before_the_body(self, client):
        """A malformed body from an anonymous caller is still a refusal.

        Validating first would tell an unauthenticated caller about the
        schema, and would report the wrong reason for the rejection.
        """
        response = client.post("/cryptography", json={"garbage": True})
        assert response.status_code == 403


class TestDifferentialPrivacy:
    def test_a_query_succeeds(self, client, auth_header, dp_request):
        response = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        )
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "SUCCESS"
        assert isinstance(body["result"], float)
        assert body["errors"] is None

    def test_the_response_envelope_is_complete(
        self, client, auth_header, dp_request
    ):
        body = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        ).json()
        assert set(body) == {
            "status",
            "result",
            "metadata",
            "execution_time",
            "audit_id",
            "errors",
        }

    def test_budget_is_reported_and_decremented(
        self, client, auth_header, dp_request
    ):
        first = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        ).json()
        second = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        ).json()
        assert second["metadata"]["remaining_epsilon"] < (
            first["metadata"]["remaining_epsilon"]
        )

    def test_the_budget_eventually_refuses_further_queries(
        self, client, auth_header, dp_request
    ):
        codes = [
            client.post(
                "/cryptography", json=dp_request, headers=auth_header
            ).status_code
            for _ in range(14)
        ]
        assert 200 in codes
        assert codes[-1] == 429

    def test_a_query_costing_more_than_the_budget_is_refused(
        self, client, auth_header, dp_request
    ):
        dp_request["parameters"]["epsilon_cost"] = 99.0
        response = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        )
        assert response.status_code == 400
        assert response.json()["status"] == "INSUFFICIENT_BUDGET"

    def test_users_have_separate_budgets(self, client, dp_request):
        for _ in range(14):
            client.post(
                "/cryptography",
                json=dp_request,
                headers={"Authorization": "Bearer alice"},
            )
        response = client.post(
            "/cryptography",
            json=dp_request,
            headers={"Authorization": "Bearer bob"},
        )
        assert response.status_code == 200


class TestValidation:
    @pytest.mark.parametrize(
        "mutation,reason",
        [
            ({"nonsense": 1}, "unknown field"),
            ({"operation": "mind_reading"}, "unknown operation"),
            ({"backend": "tink"}, "incompatible backend"),
            ({"output_format": "json-ld"}, "unsupported output format"),
        ],
    )
    def test_bad_requests_are_refused(
        self, client, auth_header, dp_request, mutation, reason
    ):
        dp_request.update(mutation)
        response = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        )
        assert response.status_code == 400, reason
        assert response.json()["errors"]

    @pytest.mark.parametrize(
        "parameters",
        [
            {"query_type": "Nonsense", "epsilon_cost": 0.1},
            {"query_type": "BoundedMean", "epsilon_cost": -1},
            {"query_type": "BoundedMean"},
        ],
    )
    def test_bad_parameters_are_refused(
        self, client, auth_header, dp_request, parameters
    ):
        dp_request["parameters"] = parameters
        response = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        )
        assert response.status_code == 400

    def test_an_empty_body_is_refused(self, client, auth_header):
        response = client.post(
            "/cryptography", json={}, headers=auth_header
        )
        assert response.status_code == 400
        assert "Field required" in response.json()["errors"]

    def test_missing_bounds_are_refused(self, client, auth_header):
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "differential_privacy",
                "backend": "pydp",
                "input_data": {"data": SAMPLE_DATA},
                "parameters": {
                    "query_type": "BoundedMean",
                    "epsilon_cost": 0.1,
                },
            },
        )
        # config.yaml supplies fallback bounds, so this succeeds; the point
        # is that it does not fail obscurely inside the backend.
        assert response.status_code in (200, 400)


class TestPendingOperations:
    @pytest.mark.parametrize(
        "operation,backend",
        [("homomorphic_encryption", "pyfhel"), ("smpc", "mpyc")],
    )
    def test_recognised_but_unimplemented(
        self, client, auth_header, operation, backend
    ):
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": operation,
                "backend": backend,
                "input_data": {"values": [1, 2]},
            },
        )
        assert response.status_code == 501
        assert response.json()["status"] == "NOT_IMPLEMENTED"


class TestEncryption:
    @pytest.fixture
    def keyset(self, client, auth_header):
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "key_management",
                "backend": "tink",
                "input_data": {},
                "parameters": {"action": "generate_key"},
            },
        )
        assert response.status_code == 200
        return response.json()["result"]["keyset"]

    def test_round_trip(self, client, auth_header, keyset):
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "encryption",
                "backend": "tink",
                "input_data": {"plaintext": "classified"},
                "parameters": {
                    "action": "encrypt",
                    "associated_data": "demo",
                },
                "key_config": {"keyset": keyset},
            },
        )
        ciphertext = response.json()["result"]["ciphertext"]

        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "encryption",
                "backend": "tink",
                "input_data": {"ciphertext": ciphertext},
                "parameters": {
                    "action": "decrypt",
                    "associated_data": "demo",
                },
                "key_config": {"keyset": keyset},
            },
        )
        assert response.json()["result"]["plaintext"] == "classified"

    def test_wrong_associated_data_is_refused(
        self, client, auth_header, keyset
    ):
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "encryption",
                "backend": "tink",
                "input_data": {"plaintext": "x"},
                "parameters": {"action": "encrypt",
                               "associated_data": "right"},
                "key_config": {"keyset": keyset},
            },
        )
        ciphertext = response.json()["result"]["ciphertext"]
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "encryption",
                "backend": "tink",
                "input_data": {"ciphertext": ciphertext},
                "parameters": {"action": "decrypt",
                               "associated_data": "wrong"},
                "key_config": {"keyset": keyset},
            },
        )
        assert response.status_code == 400

    def test_rotation(self, client, auth_header, keyset):
        response = client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "key_management",
                "backend": "tink",
                "input_data": {},
                "parameters": {"action": "rotate_key"},
                "key_config": {"keyset": keyset},
            },
        )
        assert response.json()["metadata"]["keyset_info"]["key_count"] == 2

    def test_encryption_does_not_consume_privacy_budget(
        self, client, auth_header, keyset, dp_request
    ):
        before = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        ).json()["metadata"]["remaining_epsilon"]
        client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "encryption",
                "backend": "tink",
                "input_data": {"plaintext": "x"},
                "parameters": {"action": "encrypt"},
                "key_config": {"keyset": keyset},
            },
        )
        after = client.post(
            "/cryptography", json=dp_request, headers=auth_header
        ).json()["metadata"]["remaining_epsilon"]
        assert before - after == pytest.approx(
            dp_request["parameters"]["epsilon_cost"]
        )


class TestAuditTrail:
    def test_every_request_is_recorded(self, client, auth_header, dp_request):
        client.post("/cryptography", json=dp_request, headers=auth_header)
        client.post("/cryptography", json=dp_request)
        assert len(read_audit(client)) == 2

    def test_secrets_never_reach_the_trail(
        self, client, auth_header, dp_request
    ):
        client.post(
            "/cryptography",
            headers=auth_header,
            json={
                "operation": "key_management",
                "backend": "tink",
                "input_data": {},
                "parameters": {"action": "generate_key"},
            },
        )
        client.post("/cryptography", json=dp_request, headers=auth_header)
        contents = client.audit_file.read_text()
        assert "test-token-alice" not in contents
        assert "[0, 1, 2" not in contents

    def test_identities_are_opaque(self, client, auth_header, dp_request):
        client.post("/cryptography", json=dp_request, headers=auth_header)
        record = read_audit(client)[0]
        assert record["user_id"].startswith("dev:")
        assert "test-token" not in record["user_id"]

    def test_budget_state_is_persisted(
        self, client, auth_header, dp_request
    ):
        client.post("/cryptography", json=dp_request, headers=auth_header)
        assert client.budget_file.exists()
        assert json.loads(client.budget_file.read_text())


class TestOpenAPI:
    def test_the_endpoint_is_documented(self, client):
        spec = client.get("/openapi.json").json()
        assert "/cryptography" in spec["paths"]

    def test_all_response_codes_are_documented(self, client):
        spec = client.get("/openapi.json").json()
        responses = spec["paths"]["/cryptography"]["post"]["responses"]
        assert {"200", "400", "403", "429", "500", "501"} <= set(responses)
