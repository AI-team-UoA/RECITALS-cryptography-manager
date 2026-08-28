"""Audit record construction, sanitisation and delivery."""

from __future__ import annotations

import json

import numpy as np
import pytest

from cryptography_manager.core.audit import (
    REDACTED,
    AuditLogger,
    sanitize,
)

SECRET = "GiDW5jlb4Wp/B1ZUQ87I6O1K8eoC79G/WM0EDWF6NokA1w=="


class TestSanitisation:
    """Nothing sensitive may reach a record.

    These are the tests that matter most in this module: an audit trail that
    leaks key material is worse than no audit trail, because it concentrates
    secrets in a file designed to be shipped elsewhere.
    """

    @pytest.mark.parametrize(
        "key",
        [
            "keyset",
            "key",
            "secret_key",
            "privateKey",
            "password",
            "passphrase",
            "api_token",
            "credential",
            "plaintext",
            "ciphertext",
            "shares",
            "seed",
            "nonce",
        ],
    )
    def test_sensitive_keys_are_redacted(self, key):
        assert sanitize({key: SECRET})[key] == REDACTED

    def test_redaction_is_case_insensitive(self):
        assert sanitize({"SECRET_KEY": SECRET})["SECRET_KEY"] == REDACTED

    def test_nested_secrets_are_redacted(self):
        payload = {"a": {"b": {"c": {"inner_secret": SECRET}}}}
        assert SECRET not in json.dumps(sanitize(payload))

    def test_harmless_values_are_preserved(self):
        clean = sanitize(
            {"query_type": "BoundedMean", "epsilon_cost": 0.1, "n": 42}
        )
        assert clean == {
            "query_type": "BoundedMean",
            "epsilon_cost": 0.1,
            "n": 42,
        }

    def test_bulk_data_is_summarised_not_stored(self):
        clean = sanitize({"data": list(range(1000))})
        assert clean["data"] == {"type": "sequence", "length": 1000}

    def test_long_bare_sequences_are_summarised(self):
        assert sanitize({"xs": list(range(50))})["xs"]["length"] == 50

    def test_short_sequences_are_kept(self):
        assert sanitize({"bounds": [0, 99]})["bounds"] == [0, 99]

    def test_deep_nesting_is_truncated(self):
        payload: dict = {}
        cursor = payload
        for _ in range(20):
            cursor["n"] = {}
            cursor = cursor["n"]
        assert "[TRUNCATED]" in json.dumps(sanitize(payload))

    def test_unserialisable_values_degrade_to_a_type_name(self):
        assert isinstance(sanitize({"x": np.int64(5)})["x"], (int, str))
        assert sanitize({"x": object()})["x"] == "object"


class TestRecordConstruction:
    def test_record_has_the_expected_fields(self, audit):
        record = audit.build(
            status="SUCCESS",
            user_id="alice",
            operation="differential_privacy",
            backend="pydp",
            execution_time=0.0123,
        )
        assert record.user_id == "alice"
        assert record.execution_time == 0.0123
        assert record.timestamp.tzinfo is not None
        assert len(record.audit_id) == 36

    def test_parameters_are_sanitised_on_construction(self, audit):
        record = audit.build(status="SUCCESS", parameters={"keyset": SECRET})
        assert record.parameters["keyset"] == REDACTED

    def test_audit_ids_are_unique(self, audit):
        ids = {audit.build(status="SUCCESS").audit_id for _ in range(50)}
        assert len(ids) == 50


class TestDelivery:
    def test_records_are_appended_as_json_lines(self, audit, audit_records):
        audit.record(status="SUCCESS", user_id="alice")
        audit.record(status="UNAUTHORIZED", error_message="no token")
        records = audit_records()
        assert len(records) == 2
        assert records[1]["status"] == "UNAUTHORIZED"

    def test_parent_directory_is_created(self, audit, audit_path):
        audit.record(status="SUCCESS")
        assert audit_path.exists()

    def test_secrets_never_reach_the_file(
        self, audit, audit_path, audit_records
    ):
        audit.record(
            status="SUCCESS",
            parameters={"keyset": SECRET, "data": list(range(100))},
        )
        contents = audit_path.read_text()
        assert SECRET not in contents
        assert "[0, 1, 2" not in contents

    def test_a_dead_downstream_never_fails_the_request(
        self, tmp_path, audit_path
    ):
        """Forwarding is best-effort by design.

        Losing an operation's result because an audit sink was briefly
        unreachable would be a worse outcome than a delayed record.
        """
        logger = AuditLogger(
            log_path=audit_path,
            targets={
                "ledger": "http://127.0.0.1:9/dead",
                "compliance": "http://127.0.0.1:9/dead",
            },
            timeout=0.3,
        )
        logger.record(status="SUCCESS", user_id="bob")
        logger.shutdown()
        assert audit_path.exists()
        assert len(audit_path.read_text().strip().split("\n")) == 1
