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
import threading
import time
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
        permissions: frozenset[str] | None = None,
    ) -> None:
        self.user_id = user_id
        self.claims = claims or {}
        self.error = error
        #: Permissions the token grants, or ``None`` when they are not being
        #: enforced and every action is allowed.
        self.permissions = permissions

    @property
    def client_id(self) -> str | None:
        """The client the token was issued to, if it says."""
        value = self.claims.get("azp") or self.claims.get("client_id")
        return str(value) if value else None

    @property
    def issuer(self) -> str | None:
        """The issuer of the token, if it says."""
        value = self.claims.get("iss")
        return str(value) if value else None

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


def extract_permissions(
    claims: dict[str, Any], audience: str | None, prefix: str
) -> frozenset[str]:
    """Collect the permissions a token grants.

    Providers disagree on where authorization lives, so every usual place is
    read: the space-separated ``scope`` claim, realm-level roles, and the
    roles granted on this service specifically. Roles of that last kind are
    already scoped to this service by where they sit, so a bare ``encrypt``
    there is taken to mean ``<prefix>.encrypt``.

    Args:
        claims: The verified token claims.
        audience: This service's client ID, keying its client-level roles.
        prefix: Namespace of this service's permissions.

    Returns:
        Every permission name found.
    """
    granted: set[str] = set()

    scope = claims.get("scope")
    if isinstance(scope, str):
        granted.update(scope.split())

    realm = claims.get("realm_access")
    if isinstance(realm, dict) and isinstance(realm.get("roles"), list):
        granted.update(str(role) for role in realm["roles"])

    resources = claims.get("resource_access")
    if audience and isinstance(resources, dict):
        own = resources.get(audience)
        if isinstance(own, dict) and isinstance(own.get("roles"), list):
            for role in own["roles"]:
                name = str(role)
                granted.add(name)
                if not name.startswith(f"{prefix}."):
                    granted.add(f"{prefix}.{name}")

    return frozenset(granted)


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
            jwks_uri = (
                self.settings.oidc_jwks_uri
                or self._discover().get("jwks_uri")
            )
            if not jwks_uri:
                raise ValueError(
                    "Provider configuration exposes no jwks_uri"
                )
            self._jwks_client = PyJWKClient(jwks_uri, cache_keys=True)
        return self._jwks_client

    def verify(self, token: str | None) -> AuthResult:
        """Verify a token's signature, expiry, issuer and audience."""
        if not token or not token.strip():
            return AuthResult(error="Missing authorization token")

        token = token.strip()
        try:
            signing_key = self._client().get_signing_key_from_jwt(token)
            audience = self.settings.audience_to_verify
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

        permissions = None
        if self.settings.oidc_enforce_permissions:
            permissions = extract_permissions(
                claims,
                self.settings.expected_audience,
                self.settings.oidc_permission_prefix,
            )
        return AuthResult(
            user_id=user_id, claims=claims, permissions=permissions
        )


@final
class ServiceTokenProvider:
    """Obtains this service's own access token for calls it makes.

    Uses the client credentials grant and holds the token until shortly
    before it expires, so outbound calls do not each cost a round trip to
    the provider.
    """

    #: Seconds before expiry at which a token is no longer handed out.
    LEEWAY = 30.0

    def __init__(self, settings: Settings) -> None:
        """Initialise the provider.

        Args:
            settings: Runtime settings carrying issuer and client details.
        """
        self.settings = settings
        self._token: str | None = None
        self._expires_at = 0.0
        self._token_endpoint: str | None = None
        self._lock = threading.Lock()

    def _endpoint(self) -> str:
        """Return the token endpoint, discovering it on first use."""
        if self._token_endpoint is None:
            url = (
                f"{self.settings.issuer_url}"
                "/.well-known/openid-configuration"
            )
            response = httpx.get(url, timeout=10.0)
            response.raise_for_status()
            endpoint = response.json().get("token_endpoint")
            if not endpoint:
                raise ValueError(
                    "Provider configuration exposes no token_endpoint"
                )
            self._token_endpoint = str(endpoint)
        return self._token_endpoint

    def token(self) -> str | None:
        """Return a valid access token, or ``None`` if none can be had.

        Never raises: the callers are best-effort deliveries that must go
        ahead, unauthenticated if need be, rather than fail.
        """
        with self._lock:
            if self._token and time.monotonic() < self._expires_at:
                return self._token
            try:
                response = httpx.post(
                    self._endpoint(),
                    data={
                        "grant_type": "client_credentials",
                        "client_id": self.settings.oidc_client_id,
                        "client_secret": self.settings.oidc_client_secret,
                    },
                    timeout=10.0,
                )
                response.raise_for_status()
                body = response.json()
                self._token = str(body["access_token"])
                lifetime = float(body.get("expires_in", 60))
                self._expires_at = (
                    time.monotonic() + max(lifetime - self.LEEWAY, 0.0)
                )
            except Exception as exc:
                logger.warning(f"Could not obtain a service token: {exc}")
                self._token = None
            return self._token


def build_service_token_provider(
    settings: Settings,
) -> ServiceTokenProvider | None:
    """Construct the outbound token provider, if one is configured.

    Args:
        settings: Runtime settings.

    Returns:
        A provider when the service has an identity provider and client
        credentials of its own, otherwise ``None``.
    """
    if (
        settings.auth_mode == "oidc"
        and settings.oidc_client_id
        and settings.oidc_client_secret
    ):
        return ServiceTokenProvider(settings)
    return None


def build_verifier(settings: Settings) -> TokenVerifier:
    """Construct the verifier selected by configuration.

    Args:
        settings: Runtime settings.

    Returns:
        The configured verifier.
    """
    if settings.auth_mode == "oidc":
        logger.info(f"Auth mode: OIDC against {settings.issuer_url}")
        if not settings.audience_to_verify:
            logger.warning(
                "Token audience is NOT verified: tokens issued for other "
                "services are accepted. Set CRM_OIDC_AUDIENCE or "
                "CRM_OIDC_CLIENT_ID."
            )
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
