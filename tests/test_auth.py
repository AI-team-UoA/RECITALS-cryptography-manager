"""Bearer token verification, including the classic JWT attacks."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from cryptography_manager.api.auth import (
    DevTokenVerifier,
    OIDCTokenVerifier,
    build_verifier,
    extract_bearer,
)
from cryptography_manager.config.settings import Settings


class TestHeaderParsing:
    @pytest.mark.parametrize(
        "header,expected",
        [
            ("Bearer abc123", "abc123"),
            ("bearer abc", "abc"),
            ("BEARER abc", "abc"),
            ("Bearer  padded  ", "padded"),
            (None, None),
            ("", None),
            ("Basic abc", None),
            ("abc", None),
            ("Bearer   ", None),
        ],
    )
    def test_extraction(self, header, expected):
        assert extract_bearer(header) == expected


class TestDevVerifier:
    @pytest.fixture
    def verifier(self):
        return DevTokenVerifier()

    @pytest.mark.parametrize("token", [None, "", "   "])
    def test_missing_tokens_are_still_rejected(self, verifier, token):
        """Even the permissive mode refuses an absent token.

        Otherwise the unauthorized path would never be exercised in
        development, and would first be tried in production.
        """
        assert not verifier.verify(token).ok

    def test_opaque_token_yields_a_stable_identity(self, verifier):
        first = verifier.verify("opaque-token")
        second = verifier.verify("opaque-token")
        assert first.ok
        assert first.user_id == second.user_id

    def test_different_tokens_get_different_identities(self, verifier):
        assert (
            verifier.verify("aaa").user_id != verifier.verify("bbb").user_id
        )

    def test_the_token_never_appears_in_the_identity(self, verifier):
        """The identity reaches audit records and budget state.

        Putting the raw credential there would spread a replayable secret
        into files intended to be shipped to other services.
        """
        token = "super-secret-token-value"
        assert token not in verifier.verify(token).user_id

    def test_subject_is_read_from_a_jwt(self, verifier):
        token = jwt.encode(
            {"sub": "alice"}, "a" * 32, algorithm="HS256"
        )
        assert verifier.verify(token).user_id == "alice"


@pytest.mark.slow
class TestOIDCVerifier:
    @pytest.fixture
    def verifier(self, oidc_settings):
        return OIDCTokenVerifier(oidc_settings)

    def test_a_valid_token_is_accepted(self, verifier, oidc):
        result = verifier.verify(oidc.mint(subject="user-42"))
        assert result.ok
        assert result.user_id == "user-42"
        assert result.claims["iss"] == oidc.issuer

    def test_an_expired_token_is_rejected(self, verifier, oidc):
        result = verifier.verify(oidc.mint(expires_in=-60))
        assert not result.ok
        assert "expired" in result.error.lower()

    def test_a_token_without_expiry_is_rejected(self, verifier, oidc):
        assert not verifier.verify(oidc.mint(expires_in=None)).ok

    def test_a_wrong_issuer_is_rejected(self, verifier, oidc):
        assert not verifier.verify(
            oidc.mint(issuer="https://evil.example")
        ).ok

    def test_a_forged_signature_is_rejected(self, verifier, oidc):
        other = rsa.generate_private_key(
            public_exponent=65537, key_size=2048
        ).private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        result = verifier.verify(oidc.mint(subject="admin", key=other))
        assert not result.ok

    def test_algorithm_confusion_is_rejected(self, verifier, oidc):
        """The classic JWT break.

        An attacker takes the provider's public key -- which is public by
        definition -- and uses it as an HMAC secret, hoping the verifier will
        accept HS256. Restricting the accepted algorithms to asymmetric ones
        is what closes this. PyJWT refuses to mint such a token, so it is
        assembled by hand exactly as an attacker would.
        """

        def b64(raw: bytes) -> bytes:
            return base64.urlsafe_b64encode(raw).rstrip(b"=")

        header = b64(
            json.dumps(
                {"alg": "HS256", "typ": "JWT", "kid": "test-key-1"}
            ).encode()
        )
        payload = b64(
            json.dumps(
                {
                    "sub": "admin",
                    "iss": oidc.issuer,
                    "aud": "crm",
                    "exp": 9999999999,
                }
            ).encode()
        )
        signing_input = header + b"." + payload
        signature = b64(
            hmac.new(oidc.public_pem, signing_input, hashlib.sha256).digest()
        )
        forged = (signing_input + b"." + signature).decode()

        assert not verifier.verify(forged).ok

    def test_missing_token_is_rejected(self, verifier):
        assert not verifier.verify(None).ok

    def test_an_unreachable_provider_fails_closed(self, oidc):
        """A provider outage must never be read as a valid token."""
        verifier = OIDCTokenVerifier(
            Settings(auth_mode="oidc", oidc_issuer="http://127.0.0.1:9")
        )
        assert not verifier.verify(oidc.mint()).ok

    def test_audience_is_enforced_when_enabled(self, oidc):
        verifier = OIDCTokenVerifier(
            Settings(
                auth_mode="oidc",
                oidc_issuer=oidc.issuer,
                oidc_client_id="crm",
                oidc_verify_audience=True,
            )
        )
        assert verifier.verify(oidc.mint(audience="crm")).ok
        assert not verifier.verify(oidc.mint(audience="someone-else")).ok


class TestVerifierSelection:
    def test_development_is_the_default(self):
        assert isinstance(build_verifier(Settings()), DevTokenVerifier)

    def test_oidc_is_selected_when_configured(self, oidc_settings):
        assert isinstance(
            build_verifier(oidc_settings), OIDCTokenVerifier
        )

    def test_oidc_without_an_issuer_is_refused_at_startup(self, monkeypatch):
        """Fail at startup rather than on the first request."""
        monkeypatch.delenv("KEYCLOAK_URL", raising=False)
        monkeypatch.delenv("CRM_OIDC_ISSUER", raising=False)
        with pytest.raises(ValueError, match="requires an issuer"):
            Settings(auth_mode="oidc")


class TestSettingsAliases:
    def test_deployment_env_names_are_accepted(self, monkeypatch):
        """Existing deployments should not have to rename variables."""
        monkeypatch.setenv("KEYCLOAK_URL", "https://ilm.example/auth")
        monkeypatch.setenv("KEYCLOAK_REALM", "recitals")
        monkeypatch.setenv("LEDGER_ENDPOINT", "https://ledger.example")
        settings = Settings(auth_mode="oidc")
        assert settings.issuer_url == (
            "https://ilm.example/auth/realms/recitals"
        )
        assert settings.audit_targets == {"ledger": "https://ledger.example"}

    def test_issuer_without_a_realm(self, monkeypatch):
        monkeypatch.setenv("CRM_OIDC_ISSUER", "https://idp.example/")
        monkeypatch.delenv("KEYCLOAK_REALM", raising=False)
        assert Settings(auth_mode="oidc").issuer_url == "https://idp.example"
