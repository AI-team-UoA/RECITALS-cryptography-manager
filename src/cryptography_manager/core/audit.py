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
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, final

import httpx
from loguru import logger

from ..api.models import AuditRecord

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
    ):
        """Initialise the logger.

        Args:
            log_path: JSON-lines file receiving every record.
            targets: Downstream services to forward to, keyed by name.
            timeout: Per-request timeout when forwarding.
        """
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.targets = targets or {}
        self.timeout = timeout
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
        operation: str | None = None,
        backend: str | None = None,
        execution_time: float = 0.0,
        parameters: dict[str, Any] | None = None,
        error_message: str | None = None,
    ) -> AuditRecord:
        """Construct a sanitised audit record.

        Args:
            status: Workflow outcome.
            user_id: Identifier of the requesting user, if known.
            operation: Requested cryptographic operation.
            backend: Library used.
            execution_time: Duration of execution, in seconds.
            parameters: Raw parameters; sanitised before being stored.
            error_message: Failure detail, if any.

        Returns:
            The record, ready to be emitted.
        """
        return AuditRecord(
            user_id=user_id,
            operation=operation,
            backend=backend,
            status=status,
            execution_time=round(execution_time, 6),
            parameters=sanitize(parameters or {}),
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
        payload = json.loads(record.model_dump_json())
        for name, endpoint in self.targets.items():
            url = (
                f"{endpoint.rstrip('/')}/input"
                if name == "compliance"
                else endpoint
            )
            try:
                response = httpx.post(
                    url, json=payload, timeout=self.timeout
                )
                response.raise_for_status()
                logger.debug(
                    f"Audit record {record.audit_id} forwarded to {name}"
                )
            except Exception as exc:
                logger.warning(
                    f"Failed to forward audit record {record.audit_id} "
                    f"to {name} ({url}): {exc}"
                )

    def shutdown(self) -> None:
        """Wait for in-flight forwards to finish."""
        self._pool.shutdown(wait=True)
