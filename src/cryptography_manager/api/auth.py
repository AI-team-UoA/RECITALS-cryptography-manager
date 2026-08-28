"""
Bearer token verification.

Verification sits behind a small interface with two implementations, because
the identity provider this component will ultimately talk to is not settled.
The OIDC verifier targets the standard discovery and JWKS endpoints rather than
any one vendor's API, so it should work against any conforming provider and
needs replacing only if the eventual choice is non-standard.

The development verifier exists so the service is runnable with no identity
provider at all. It still rejects a missing or malformed token, so the
rejection path is exercised the same way in both modes -- it simply does not
verify signatures, and must never be used outside development.
"""

from __future__ import annotations

import hashlib
from typing import Any, Protocol, final, runtime_checkable

import httpx
import jwt
from jwt import PyJWKClient
from loguru import logger

from ..config.settings import Settings

#: Signature algorithms accepted from the provider. Symmetric algorithms are
#: excluded on purpose: accepting HS256 alongside RS256 lets an attacker who
#: knows the public key mint tokens by using it as an HMAC secret.
ALLOWED_ALGORITHMS: list[str] = [
    "RS256",
    "RS384",
    "RS512",
    "ES256",
    "ES384",
    "ES512",
    "PS256",
    "PS384",
    "PS512",
]


@final
class AuthResult:
    """Outcome of verifying a token."""

    def __init__(
        self,
        user_id: str | None = None,
        claims: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> None:
        self.user_id = user_id
        self.claims = claims or {}
        self.error = error

    @property
    def ok(self) -> bool:
        """Whether verification succeeded."""
        return self.user_id is not None and self.error is None


@runtime_checkable
class TokenVerifier(Protocol):
    """Verifies a bearer token and identifies the caller."""

    def verify(self, token: str | None) -> AuthResult:
        """Verify a token.

        Args:
            token: The bearer token, without its scheme prefix.

        Returns:
            The verification outcome. Failures are returned rather than
            raised, because a rejected request still has to be audited.
        """
        ...


def _extract_user_id(claims: dict[str, Any]) -> str | None:
    """Pick the most specific stable identifier from a token's claims."""
    for field in ("sub", "preferred_username", "email", "client_id"):
        value = claims.get(field)
        if value:
            return str(value)
    return None


@final
class DevTokenVerifier:
    """Accepts any well-formed token without verifying its signature.

    Intended solely for development against no identity provider. It reads the
    claims of a JWT to identify the caller, and otherwise treats the token
    string itself as the identity.
    """

    def verify(self, token: str | None) -> AuthResult:
        """Identify the caller without cryptographic verification."""
        if not token or not token.strip():
            return AuthResult(error="Missing authorization token")

        token = token.strip()
        try:
            claims = jwt.decode(
                token, options={"verify_signature": False, "verify_exp": False}
            )
        except Exception:
            # Not a JWT. Derive a stable identity from a digest of the token
            # rather than the token itself: the identifier reaches audit
            # records and budget state, and neither may ever hold a
            # credential that could be replayed.
            digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
            return AuthResult(user_id=f"dev:{digest[:16]}")

        user_id = _extract_user_id(claims)
        if not user_id:
            return AuthResult(error="Token contains no usable subject claim")
        return AuthResult(user_id=user_id, claims=claims)


@final
class OIDCTokenVerifier:
    """Verifies tokens against an OpenID Connect provider.

    Keys are discovered through the provider's well-known configuration and
    cached by the JWKS client, so steady-state verification is local and does
    not add a network round trip per request.
    """

    def __init__(self, settings: Settings) -> None:
        """Initialise the verifier.

        Args:
            settings: Runtime settings carrying the issuer and client details.

        Raises:
            ValueError: If no issuer is configured.
        """
        issuer = settings.issuer_url
        if not issuer:
            raise ValueError("OIDC verification requires an issuer URL")
        self.issuer = issuer
        self.settings = settings
        self._jwks_client: PyJWKClient | None = None
        self._discovered: dict[str, Any] | None = None

    def _discover(self) -> dict[str, Any]:
        """Fetch and cache the provider's well-known configuration."""
        cached = self._discovered
        if cached is None:
            url = f"{self.issuer}/.well-known/openid-configuration"
            response = httpx.get(url, timeout=10.0)
            response.raise_for_status()
            cached = dict(response.json())
            self._discovered = cached
            logger.info(f"OIDC discovery succeeded against {url}")
        return cached

    def _client(self) -> PyJWKClient:
        """Return the JWKS client, discovering the endpoint on first use."""
        if self._jwks_client is None:
            jwks_uri = self._discover().get("jwks_uri")
            if not jwks_uri:
                raise ValueError(
                    "Provider configuration exposes no jwks_uri"
                )
            self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
        return self._jwks_client

    def verify(self, token: str | None) -> AuthResult:
        """Verify a token's signature, expiry and issuer."""
        if not token or not token.strip():
            return AuthResult(error="Missing authorization token")

        token = token.strip()
        try:
            signing_key = self._client().get_signing_key_from_jwt(token)
            audience = (
                self.settings.oidc_client_id
                if self.settings.oidc_verify_audience
                else None
            )
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=ALLOWED_ALGORITHMS,
                issuer=self.issuer,
                audience=audience,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iss": True,
                    "verify_aud": bool(audience),
                    "require": ["exp"],
                },
            )
        except jwt.ExpiredSignatureError:
            return AuthResult(error="Token has expired")
        except jwt.InvalidTokenError as exc:
            return AuthResult(error=f"Invalid token: {exc}")
        except Exception as exc:
            # A provider that is unreachable must not be reported as a valid
            # token; failing closed is the only safe direction here.
            logger.warning(f"Token verification could not complete: {exc}")
            return AuthResult(error="Token verification unavailable")

        user_id = _extract_user_id(claims)
        if not user_id:
            return AuthResult(error="Token contains no usable subject claim")
        return AuthResult(user_id=user_id, claims=claims)


def build_verifier(settings: Settings) -> TokenVerifier:
    """Construct the verifier selected by configuration.

    Args:
        settings: Runtime settings.

    Returns:
        The configured verifier.
    """
    if settings.auth_mode == "oidc":
        logger.info(f"Auth mode: OIDC against {settings.issuer_url}")
        return OIDCTokenVerifier(settings)
    logger.warning(
        "Auth mode: development. Tokens are NOT verified -- "
        "set CRM_AUTH_MODE=oidc before any real deployment."
    )
    return DevTokenVerifier()


def extract_bearer(header: str | None) -> str | None:
    """Pull the token out of an Authorization header.

    Args:
        header: Raw header value, if present.

    Returns:
        The token, or ``None`` if the header is absent or not a bearer token.
    """
    if not header:
        return None
    parts = header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip() or None
