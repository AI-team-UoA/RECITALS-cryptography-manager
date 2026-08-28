"""
Shared fixtures.

Tests run against the real backends -- real Tink keysets, real PyDP queries, a
real local OpenID Connect provider, a real ASGI client. Nothing cryptographic
is mocked, because a test that mocks the cryptography verifies only that the
mock was called.

Every fixture that touches state is scoped so it cannot leak between tests:
budget accounting and audit trails are per-test temporary directories, since a
budget shared across tests would make results depend on execution order.
"""

from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Iterator

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from cryptography_manager.adapters import (
    DifferentialPrivacyAdapter,
    EncryptionAdapter,
)
from cryptography_manager.config import Config
from cryptography_manager.config.settings import Settings
from cryptography_manager.core.audit import AuditLogger
from cryptography_manager.core.budget import InMemoryBudgetStore
from cryptography_manager.core.manager import CryptographyManager
from cryptography_manager.core.workflow import CryptographyWorkflow

# A short, well-known dataset. Integer values keep PyDP's dtype handling
# unambiguous; the float cases opt in explicitly where they need to.
SAMPLE_DATA: list[int] = list(range(100))
SAMPLE_BOUNDS: dict[str, int] = {"lower_bound": 0, "upper_bound": 99}


# --------------------------------------------------------------------------
# Cryptographic adapters
# --------------------------------------------------------------------------


@pytest.fixture
def enc() -> EncryptionAdapter:
    """The Tink-backed encryption adapter."""
    return EncryptionAdapter()


@pytest.fixture
def keyset(enc: EncryptionAdapter):
    """A freshly generated keyset, unique per test."""
    return enc.generate_keyset()


@pytest.fixture
def config() -> Config:
    """Configuration with a budget and bounds but no fixed query plan."""
    return Config(
        {
            "differential_privacy": {
                "privacy_budget_limit": 10.0,
                "default_delta": 1e-5,
                "data": SAMPLE_BOUNDS,
            }
        }
    )


@pytest.fixture
def repo_config() -> Config:
    """The configuration file shipped in the repository."""
    loaded = Config()
    loaded.load_from_file("config.yaml")
    return loaded


@pytest.fixture
def dp(config: Config) -> DifferentialPrivacyAdapter:
    """A DP adapter with no configured query plan."""
    return DifferentialPrivacyAdapter(config)


# --------------------------------------------------------------------------
# Stateful components
# --------------------------------------------------------------------------


@pytest.fixture
def audit_path(tmp_path):
    """Path to this test's audit trail."""
    return tmp_path / "audit" / "crm-audit.jsonl"


@pytest.fixture
def audit(audit_path) -> AuditLogger:
    """An audit logger writing to a per-test file, forwarding nowhere."""
    return AuditLogger(log_path=audit_path)


@pytest.fixture
def audit_records(audit_path):
    """Read back the audit records written during a test."""

    def _read() -> list[dict[str, Any]]:
        if not audit_path.exists():
            return []
        text = audit_path.read_text().strip()
        if not text:
            return []
        return [json.loads(line) for line in text.split("\n")]

    return _read


@pytest.fixture
def budget_store() -> InMemoryBudgetStore:
    """A per-user budget store starting with one epsilon each."""
    return InMemoryBudgetStore(total_epsilon=1.0)


@pytest.fixture
def workflow(
    config: Config, audit: AuditLogger, budget_store: InMemoryBudgetStore
) -> CryptographyWorkflow:
    """A workflow wired to per-test audit and budget state."""
    return CryptographyWorkflow(
        CryptographyManager(config=config), audit, budget_store
    )


# --------------------------------------------------------------------------
# HTTP client
# --------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch) -> Iterator[Any]:
    """A test client for an application with isolated state.

    Settings are passed explicitly rather than read from the process
    environment, so tests never depend on each other's environment or on the
    cached process-wide settings object.
    """
    from fastapi.testclient import TestClient

    from cryptography_manager.main import create_app

    settings = Settings(
        auth_mode="dev",
        config_path="./config.yaml",
        audit_log_path=str(tmp_path / "audit.jsonl"),
        budget_store_path=str(tmp_path / "budgets.json"),
    )
    app = create_app(settings)
    with TestClient(app) as test_client:
        test_client.audit_file = tmp_path / "audit.jsonl"
        test_client.budget_file = tmp_path / "budgets.json"
        yield test_client


@pytest.fixture
def auth_header() -> dict[str, str]:
    """An Authorization header the development verifier accepts."""
    return {"Authorization": "Bearer test-token-alice"}


@pytest.fixture
def dp_request() -> dict[str, Any]:
    """A well-formed differential privacy request body."""
    return {
        "operation": "differential_privacy",
        "backend": "pydp",
        "input_data": {"data": SAMPLE_DATA},
        "parameters": {
            "query_type": "BoundedMean",
            "epsilon_cost": 0.1,
            **SAMPLE_BOUNDS,
        },
    }


# --------------------------------------------------------------------------
# A real OpenID Connect provider
# --------------------------------------------------------------------------


class _OIDCProvider:
    """A minimal but genuine OIDC provider serving discovery and JWKS."""

    def __init__(self) -> None:
        self.key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        )
        self.private_pem = self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        self.public_pem = self.key.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        jwk = json.loads(RSAAlgorithm.to_jwk(self.key.public_key()))
        jwk.update({"kid": "test-key-1", "use": "sig", "alg": "RS256"})
        self.jwk = jwk

        provider = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                """Stay quiet; the test output is the interesting part."""

            def do_GET(self) -> None:  # noqa: N802
                if self.path.endswith("openid-configuration"):
                    body: dict[str, Any] = {
                        "issuer": provider.issuer,
                        "jwks_uri": f"{provider.issuer}/jwks",
                    }
                elif self.path.endswith("/jwks"):
                    body = {"keys": [provider.jwk]}
                else:
                    self.send_response(404)
                    self.end_headers()
                    return
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        # Port 0 lets the OS choose, so parallel runs cannot collide.
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.issuer = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()

    def mint(
        self,
        subject: str = "user-42",
        expires_in: int = 300,
        issuer: str | None = None,
        audience: str | None = "crm",
        key: bytes | None = None,
        **extra: Any,
    ) -> str:
        """Issue a signed token, optionally malformed for negative tests."""
        import jwt

        now = datetime.now(timezone.utc)
        claims: dict[str, Any] = {
            "sub": subject,
            "iss": issuer if issuer is not None else self.issuer,
            "iat": now,
        }
        if audience is not None:
            claims["aud"] = audience
        if expires_in is not None:
            claims["exp"] = now + timedelta(seconds=expires_in)
        claims.update(extra)
        return jwt.encode(
            claims,
            key if key is not None else self.private_pem,
            algorithm="RS256",
            headers={"kid": "test-key-1"},
        )


@pytest.fixture(scope="session")
def oidc() -> Iterator[_OIDCProvider]:
    """A running OpenID Connect provider, shared across the session."""
    provider = _OIDCProvider()
    provider.start()
    yield provider
    provider.stop()


@pytest.fixture
def oidc_settings(oidc: _OIDCProvider) -> Settings:
    """Settings pointing at the local provider."""
    return Settings(
        auth_mode="oidc", oidc_issuer=oidc.issuer, oidc_client_id="crm"
    )
