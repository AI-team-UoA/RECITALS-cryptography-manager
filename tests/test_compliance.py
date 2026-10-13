"""What the compliance manager is sent, and how delivery behaves."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from rdflib import Graph, Literal, Namespace
from rdflib.namespace import RDF

from cryptography_manager.api.models import AuditRecord
from cryptography_manager.core.audit import AuditLogger
from cryptography_manager.core.compliance import (
    component_status,
    to_turtle,
    use_case_for,
)

RECITALS = Namespace("http://example.org/recitals/")
DPV = Namespace("https://w3id.org/dpv#")


def record(**fields) -> AuditRecord:
    defaults = {
        "status": "SUCCESS",
        "user_id": "alice",
        "operation": "encryption",
        "action": "encrypt",
        "backend": "tink",
        "timestamp": datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc),
    }
    return AuditRecord(**{**defaults, **fields})


def graph_of(rec: AuditRecord) -> tuple[Graph, object]:
    """Parse the rendered document the way the compliance manager does."""
    graph = Graph().parse(data=to_turtle(rec), format="turtle")
    subject = next(graph.subjects(RDF.type, RECITALS.UseCaseResource))
    return graph, subject


class TestRendering:
    def test_the_document_is_valid_turtle_with_a_linkable_root(self):
        """The root type is what gets a resource attached to its use case."""
        graph, subject = graph_of(record())
        assert str(subject).startswith(str(RECITALS))

    def test_a_completed_operation_passes(self):
        graph, subject = graph_of(record())
        assert graph.value(subject, RECITALS.componentStatus) == Literal(
            "passed"
        )
        assert graph.value(subject, DPV.hasStatus) == DPV.ActivityCompleted
        assert graph.value(subject, DPV.hasTechnicalMeasure) == DPV.Encryption

    @pytest.mark.parametrize(
        "status",
        ["FAILED", "VALIDATION_ERROR", "UNAUTHORIZED", "FORBIDDEN"],
    )
    def test_anything_else_fails(self, status):
        graph, subject = graph_of(record(status=status))
        assert graph.value(subject, RECITALS.componentStatus) == Literal(
            "failed"
        )
        assert graph.value(subject, DPV.hasStatus) == DPV.ActivityNotCompleted
        assert graph.value(subject, RECITALS.workflowStatus) == Literal(status)

    @pytest.mark.parametrize(
        "operation,measure",
        [
            ("differential_privacy", DPV.DifferentialPrivacy),
            ("key_management", DPV.CryptographicKeyManagement),
        ],
    )
    def test_each_operation_names_its_measure(self, operation, measure):
        graph, subject = graph_of(record(operation=operation))
        assert graph.value(subject, DPV.hasTechnicalMeasure) == measure

    def test_hostile_text_cannot_break_out_of_a_literal(self):
        """An error message is caller-influenced and must stay a string."""
        hostile = 'bad" ; recitals:componentStatus "passed" .\n<x> a <y> . \\'
        graph, subject = graph_of(
            record(status="FAILED", error_message=hostile)
        )
        assert graph.value(subject, RECITALS.errorMessage) == Literal(hostile)
        assert list(graph.objects(subject, RECITALS.componentStatus)) == [
            Literal("failed")
        ]

    def test_absent_fields_are_left_out(self):
        graph, subject = graph_of(
            record(operation=None, action=None, backend=None, user_id=None)
        )
        assert graph.value(subject, RECITALS.operation) is None
        assert graph.value(subject, DPV.hasTechnicalMeasure) is None

    def test_status_reduction(self):
        assert component_status(record()) == "passed"
        assert component_status(record(status="BUDGET_EXHAUSTED")) == "failed"


class TestUseCase:
    def test_the_default_applies(self):
        assert use_case_for(record(), "UC1") == "UC1"

    def test_a_request_can_name_its_own(self):
        rec = record(metadata={"use_case_id": "UC2"})
        assert use_case_for(rec, "UC1") == "UC2"

    def test_none_configured_means_none(self):
        assert use_case_for(record(), None) is None

    @pytest.mark.parametrize("bad", ["", "1UC", "UC 1", "UC/../x", 7])
    def test_a_malformed_identifier_is_not_used(self, bad):
        assert use_case_for(record(metadata={"use_case_id": bad}), None) is None


@pytest.mark.slow
class TestDelivery:
    def logger(self, audit_path, sink, **kwargs) -> AuditLogger:
        return AuditLogger(
            log_path=audit_path,
            targets={"compliance": sink.url},
            retry_backoff=0.01,
            **{"compliance_use_case_id": "UC1", **kwargs},
        )

    def test_the_upload_matches_the_input_api(self, audit_path, sink):
        logger = self.logger(audit_path, sink)
        logger.record(status="FAILED", operation="encryption", user_id="bob")
        logger.shutdown()

        assert sink.requests[0]["path"] == "/input"
        form = sink.form()
        assert form["use_case_id"]["text"] == "UC1"
        assert form["component"]["text"] == "cryptography-manager"
        assert form["component_status"]["text"] == "failed"
        assert form["file"]["content_type"] == "text/turtle"
        assert form["file"]["filename"].endswith(".ttl")
        Graph().parse(data=form["file"]["text"], format="turtle")

    def test_nothing_is_sent_without_a_use_case(self, audit_path, sink):
        logger = self.logger(audit_path, sink, compliance_use_case_id=None)
        logger.record(status="SUCCESS")
        logger.shutdown()
        assert sink.requests == []

    def test_a_request_can_choose_its_use_case(self, audit_path, sink):
        logger = self.logger(audit_path, sink)
        logger.record(status="SUCCESS", metadata={"use_case_id": "UC3"})
        logger.shutdown()
        assert sink.form()["use_case_id"]["text"] == "UC3"

    def test_a_transient_failure_is_retried(self, audit_path, sink):
        sink.statuses = [503, 503, 201]
        logger = self.logger(audit_path, sink)
        logger.record(status="SUCCESS")
        logger.shutdown()
        assert len(sink.requests) == 3

    def test_retries_are_bounded(self, audit_path, sink):
        sink.statuses = [503]
        logger = self.logger(audit_path, sink, attempts=2)
        logger.record(status="SUCCESS")
        logger.shutdown()
        assert len(sink.requests) == 2

    def test_a_refusal_is_not_retried(self, audit_path, sink):
        sink.statuses = [404]
        logger = self.logger(audit_path, sink)
        logger.record(status="SUCCESS")
        logger.shutdown()
        assert len(sink.requests) == 1

    def test_the_service_token_is_presented(self, audit_path, sink):
        logger = self.logger(audit_path, sink, token_provider=lambda: "tok")
        logger.record(status="SUCCESS")
        logger.shutdown()
        assert sink.requests[0]["headers"]["Authorization"] == "Bearer tok"

    def test_other_services_still_receive_json(self, audit_path, sink):
        logger = AuditLogger(
            log_path=audit_path, targets={"ledger": sink.url}
        )
        logger.record(status="SUCCESS", user_id="carol")
        logger.shutdown()
        assert b'"user_id":"carol"' in sink.requests[0]["body"].replace(
            b" ", b""
        )
