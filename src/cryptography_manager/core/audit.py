"""
Audit record construction, sanitisation and delivery.

Every request produces exactly one audit record, whether it succeeded, was
rejected before execution, or failed inside a backend -- a rejected request
that leaves no trace is precisely the one an investigator will want later.

Two rules shape this module. Sensitive material never enters a record: not key
material, not plaintext, not the dataset, not secret shares. And delivery never
fails a request: an unreachable downstream service is logged and the record is
still written locally, because losing the operation's result because the audit
trail was briefly unavailable would be a worse outcome than a delayed record.
"""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, final

import httpx
from loguru import logger

from ..api.models import AuditRecord
from .compliance import (
    COMPONENT,
    component_status,
    to_turtle,
    use_case_for,
)

#: Keys whose values are redacted outright. Matching is case-insensitive and
#: substring-based, so 'secret_key' and 'privateKey' are both caught.
SENSITIVE_KEY_FRAGMENTS: frozenset[str] = frozenset(
    {
        "key",
        "keyset",
        "secret",
        "password",
        "passphrase",
        "token",
        "credential",
        "plaintext",
        "ciphertext",
        "share",
        "private",
        "seed",
        "nonce",
    }
)

#: Keys holding bulk data, replaced by a size summary rather than redacted, so
#: the record still says how much was processed without saying what it was.
BULK_DATA_KEYS: frozenset[str] = frozenset({"data", "input_data", "values"})

REDACTED = "[REDACTED]"

#: Guards against an enormous nested payload turning into an enormous record.
MAX_DEPTH = 6


def _is_sensitive(key: str) -> bool:
    """Whether a key's value must be redacted."""
    lowered = key.lower()
    return any(frag in lowered for frag in SENSITIVE_KEY_FRAGMENTS)


def sanitize(value: Any, _depth: int = 0) -> Any:
    """Strip sensitive material from a parameter structure.

    Args:
        value: Arbitrary parameter data.
        _depth: Internal recursion guard.

    Returns:
        A copy safe to persist and forward.
    """
    if _depth >= MAX_DEPTH:
        return "[TRUNCATED]"

    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            name = str(key)
            if _is_sensitive(name):
                clean[name] = REDACTED
            elif name.lower() in BULK_DATA_KEYS:
                clean[name] = _summarise(item)
            else:
                clean[name] = sanitize(item, _depth + 1)
        return clean

    if isinstance(value, (list, tuple)):
        # A bare sequence of values is data; record its shape, not its
        # contents, which could be the dataset itself.
        if len(value) > 10:
            return _summarise(value)
        return [sanitize(v, _depth + 1) for v in value]

    if isinstance(value, (str, int, float, bool)) or value is None:
        return value

    return str(type(value).__name__)


def _summarise(value: Any) -> Any:
    """Describe bulk data by shape instead of content."""
    if isinstance(value, (list, tuple)):
        return {"type": "sequence", "length": len(value)}
    if isinstance(value, dict):
        return {"type": "mapping", "keys": sorted(str(k) for k in value)}
    if isinstance(value, str):
        return {"type": "string", "length": len(value)}
    return {"type": type(value).__name__}


@final
class AuditLogger:
    """Builds audit records, writes them locally and forwards them onward."""

    def __init__(
        self,
        log_path: str | Path = "./audit/crm-audit.jsonl",
        targets: dict[str, str] | None = None,
        timeout: float = 5.0,
        attempts: int = 3,
        retry_backoff: float = 0.5,
        compliance_use_case_id: str | None = None,
        token_provider: Callable[[], str | None] | None = None,
    ):
        """Initialise the logger.

        Args:
            log_path: JSON-lines file receiving every record.
            targets: Downstream services to forward to, keyed by name.
            timeout: Per-request timeout when forwarding.
            attempts: Deliveries tried per record and downstream service.
            retry_backoff: Seconds before the first retry; doubles each time.
            compliance_use_case_id: Use case the compliance manager files
                records under when a request names none.
            token_provider: Supplies this service's own access token for
                downstream calls, when it has one.
        """
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.targets = targets or {}
        self.timeout = timeout
        self.attempts = max(attempts, 1)
        self.retry_backoff = retry_backoff
        self.compliance_use_case_id = compliance_use_case_id
        self.token_provider = token_provider
        if "compliance" in self.targets and not compliance_use_case_id:
            logger.warning(
                "No compliance use case configured (CRM_CM_USE_CASE_ID): "
                "only requests naming one in metadata.use_case_id will "
                "reach the compliance manager."
            )
        self._write_lock = threading.Lock()
        # Forwarding runs off the request path so a slow downstream service
        # cannot add its latency to every caller's response.
        self._pool = ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="crm-audit"
        )

    def build(
        self,
        *,
        status: str,
        user_id: str | None = None,
        client_id: str | None = None,
        token_issuer: str | None = None,
        operation: str | None = None,
        action: str | None = None,
        backend: str | None = None,
        execution_time: float = 0.0,
        parameters: dict[str, Any] | None = None,
        metadata: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> AuditRecord:
        """Construct a sanitised audit record.

        Args:
            status: Workflow outcome.
            user_id: Identifier of the requesting user, if known.
            client_id: Client the caller's token was issued to.
            token_issuer: Issuer of the caller's token.
            operation: Requested cryptographic operation.
            action: Sub-operation that was requested.
            backend: Library used.
            execution_time: Duration of execution, in seconds.
            parameters: Raw parameters; sanitised before being stored.
            metadata: Caller-supplied context; sanitised the same way.
            error_message: Failure detail, if any.

        Returns:
            The record, ready to be emitted.
        """
        return AuditRecord(
            user_id=user_id,
            client_id=client_id,
            token_issuer=token_issuer,
            operation=operation,
            action=action or None,
            backend=backend,
            status=status,
            execution_time=round(execution_time, 6),
            parameters=sanitize(parameters or {}),
            metadata=sanitize(metadata or {}),
            error_message=error_message,
        )

    def emit(self, record: AuditRecord) -> AuditRecord:
        """Persist a record locally and schedule it for forwarding.

        Args:
            record: The record to emit.

        Returns:
            The same record, for convenience.
        """
        self._write_local(record)
        if self.targets:
            self._pool.submit(self._forward, record)
        return record

    def record(self, **kwargs: Any) -> AuditRecord:
        """Build and emit a record in one call."""
        return self.emit(self.build(**kwargs))

    def _write_local(self, record: AuditRecord) -> None:
        """Append a record to the local JSON-lines file."""
        try:
            line = record.model_dump_json()
            with self._write_lock:
                with open(self.log_path, "a", encoding="utf-8") as handle:
                    handle.write(line + "\n")
        except Exception as exc:
            # Even the local write is best-effort. A full disk should degrade
            # the audit trail, not take the service down.
            logger.error(f"Failed to write audit record locally: {exc}")

    def _forward(self, record: AuditRecord) -> None:
        """Send a record to every configured downstream service."""
        headers: dict[str, str] = {}
        token = self.token_provider() if self.token_provider else None
        if token:
            headers["Authorization"] = f"Bearer {token}"

        for name, endpoint in self.targets.items():
            if name == "compliance":
                request = self._compliance_request(record, endpoint)
                if request is None:
                    logger.debug(
                        f"Audit record {record.audit_id} names no use case; "
                        "not sent to compliance"
                    )
                    continue
            else:
                request = {
                    "url": endpoint,
                    "json": json.loads(record.model_dump_json()),
                }
            self._deliver(name, record.audit_id, headers, request)

    def _compliance_request(
        self, record: AuditRecord, endpoint: str
    ) -> dict[str, Any] | None:
        """Build the upload the compliance manager's input API expects.

        Returns:
            Keyword arguments for the POST, or ``None`` when the record
            belongs to no use case and so cannot be filed.
        """
        use_case = use_case_for(
            record, self.compliance_use_case_id
        )
        if use_case is None:
            return None
        document = to_turtle(record).encode("utf-8")
        return {
            "url": f"{endpoint.rstrip('/')}/input",
            "files": {
                "file": (
                    f"crm-{record.audit_id}.ttl",
                    document,
                    "text/turtle",
                )
            },
            "data": {
                "use_case_id": use_case,
                "service": record.client_id or COMPONENT,
                "component": COMPONENT,
                "component_status": component_status(record),
            },
        }

    def _deliver(
        self,
        name: str,
        audit_id: str,
        headers: dict[str, str],
        request: dict[str, Any],
    ) -> None:
        """POST one record to one service, retrying transient failures.

        A refusal (4xx) is final: sending the same record again cannot
        succeed. Anything else is retried with a doubling pause, after which
        the record survives only in the local file.
        """
        url = request["url"]
        problem = "no attempt made"
        for attempt in range(1, self.attempts + 1):
            try:
                response = httpx.post(
                    headers=headers, timeout=self.timeout, **request
                )
                if response.status_code < 400:
                    logger.debug(
                        f"Audit record {audit_id} forwarded to {name}"
                    )
                    return
                problem = f"HTTP {response.status_code}"
                if response.status_code < 500:
                    logger.warning(
                        f"{name} refused audit record {audit_id} "
                        f"({url}): {problem} {response.text[:200]}"
                    )
                    return
            except Exception as exc:
                problem = str(exc)
            if attempt < self.attempts:
                time.sleep(self.retry_backoff * 2 ** (attempt - 1))
        logger.warning(
            f"Failed to forward audit record {audit_id} to {name} "
            f"({url}) after {self.attempts} attempts: {problem}"
        )

    def shutdown(self) -> None:
        """Wait for in-flight forwards to finish."""
        self._pool.shutdown(wait=True)
