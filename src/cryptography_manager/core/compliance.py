"""
Rendering of audit records for the compliance manager.

The compliance manager does not take JSON. It ingests RDF, uploaded as a
Turtle file and filed under a use case, and reasons over it with the Data
Privacy Vocabulary. This module turns an audit record into that shape.

The graph is written out by hand rather than through an RDF library: it is a
single resource with a dozen literal properties, and that does not justify a
runtime dependency in a service whose image is kept deliberately small.
"""

from __future__ import annotations

import re
from typing import Any

from ..api.models import AuditRecord

#: Name this component reports itself under.
COMPONENT = "cryptography-manager"

RECITALS_NS = "http://example.org/recitals/"

_PREFIXES = f"""\
@prefix recitals: <{RECITALS_NS}> .
@prefix dpv: <https://w3id.org/dpv#> .
@prefix dct: <http://purl.org/dc/terms/> .
@prefix prov: <http://www.w3.org/ns/prov#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
"""

#: The technical measure each operation stands for in the vocabulary.
_MEASURES: dict[str, str] = {
    "differential_privacy": "dpv:DifferentialPrivacy",
    "encryption": "dpv:Encryption",
    "key_management": "dpv:CryptographicKeyManagement",
    "homomorphic_encryption": "dpv:HomomorphicEncryption",
    "smpc": "dpv:SecureMultiPartyComputation",
}

#: Identifiers the compliance manager accepts for a use case.
_USE_CASE_ID = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,79}")

_ESCAPES = str.maketrans(
    {
        "\\": "\\\\",
        '"': '\\"',
        "\n": "\\n",
        "\r": "\\r",
        "\t": "\\t",
    }
)


def _literal(value: Any) -> str:
    """Render a value as a quoted, escaped Turtle string literal."""
    return f'"{str(value).translate(_ESCAPES)}"'


def component_status(record: AuditRecord) -> str:
    """Reduce a workflow outcome to the compliance manager's two states.

    Args:
        record: The audit record.

    Returns:
        ``"passed"`` if the operation completed, otherwise ``"failed"``.
    """
    return "passed" if record.status == "SUCCESS" else "failed"


def use_case_for(record: AuditRecord, default: str | None) -> str | None:
    """Decide which use case a record is filed under.

    A request may name its own use case in its metadata; otherwise the
    deployment-wide default applies.

    Args:
        record: The audit record.
        default: The configured use case, if any.

    Returns:
        A well-formed use case identifier, or ``None`` if there is none.
    """
    candidate = record.metadata.get("use_case_id") or default
    if isinstance(candidate, str) and _USE_CASE_ID.fullmatch(candidate):
        return candidate
    return None


def to_turtle(record: AuditRecord) -> str:
    """Render an audit record as a Turtle document.

    The record becomes one resource, typed so that the compliance manager
    links it to the use case it is submitted for. Only what the audit record
    already holds is written, so nothing sensitive can appear here that
    sanitisation kept out of the record.

    Args:
        record: The audit record.

    Returns:
        The Turtle document.
    """
    passed = component_status(record) == "passed"
    timestamp = record.timestamp.isoformat()

    properties: list[str] = [
        "a recitals:UseCaseResource , recitals:ComponentExecution",
        f"dct:identifier {_literal(record.audit_id)}",
        f"prov:generatedAtTime {_literal(timestamp)}^^xsd:dateTime",
        f"recitals:component {_literal(COMPONENT)}",
        f"recitals:componentStatus {_literal(component_status(record))}",
        f"recitals:workflowStatus {_literal(record.status)}",
        "dpv:hasStatus "
        + ("dpv:ActivityCompleted" if passed else "dpv:ActivityNotCompleted"),
    ]

    measure = _MEASURES.get(record.operation or "")
    if measure:
        properties.append(f"dpv:hasTechnicalMeasure {measure}")
    for name, value in (
        ("operation", record.operation),
        ("action", record.action),
        ("backend", record.backend),
        ("requestedBy", record.user_id),
        ("callingClient", record.client_id),
        ("errorMessage", record.error_message),
    ):
        if value:
            properties.append(f"recitals:{name} {_literal(value)}")

    subject = f"<{RECITALS_NS}CryptographyExecution-{record.audit_id}>"
    body = " ;\n    ".join(properties)
    return f"{_PREFIXES}\n{subject}\n    {body} .\n"
