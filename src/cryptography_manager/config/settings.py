"""
Environment-derived runtime settings.

These are deployment concerns -- where to send audit records, how to verify
tokens, where to keep state -- as opposed to the cryptographic parameters in
the YAML configuration file. Keeping them apart means the same config file can
be mounted into different environments without editing.

Field names use a ``CRM_`` prefix, but the unprefixed names some deployments
already set are accepted as aliases so nothing has to be renamed to adopt this.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal, final

from pydantic import AliasChoices, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


@final
class Settings(BaseSettings):
    """Runtime settings resolved from the environment."""

    model_config = SettingsConfigDict(
        env_prefix="CRM_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
        # Fields with environment aliases stay settable by their own name
        # when settings are constructed in code.
        populate_by_name=True,
    )

    # ---- authentication ----
    auth_mode: Literal["dev", "oidc"] = Field(
        default="dev",
        description=(
            "'oidc' verifies bearer tokens against an identity provider. "
            "'dev' accepts any non-empty token and trusts its claims, so the "
            "service is runnable without one -- never use it in production."
        ),
    )
    oidc_issuer: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_OIDC_ISSUER", "OIDC_ISSUER", "KEYCLOAK_URL"
        ),
        description="Issuer base URL, used for discovery.",
    )
    oidc_realm: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_OIDC_REALM", "OIDC_REALM", "KEYCLOAK_REALM"
        ),
        description="Realm appended to the issuer, if the provider uses one.",
    )
    oidc_client_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_OIDC_CLIENT_ID", "OIDC_CLIENT_ID", "KEYCLOAK_CLIENT_ID"
        ),
        description="Client ID, also checked as the expected audience.",
    )
    oidc_client_secret: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_OIDC_CLIENT_SECRET",
            "OIDC_CLIENT_SECRET",
            "KEYCLOAK_CLIENT_SECRET",
        ),
        description="Client secret. Injected at runtime, never baked in.",
    )
    oidc_audience: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_OIDC_AUDIENCE", "OIDC_AUDIENCE", "EXPECTED_AUDIENCE"
        ),
        description=(
            "Audience a token must carry. Defaults to the client ID, which "
            "is also where client-level roles are looked up."
        ),
    )
    oidc_jwks_uri: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_OIDC_JWKS_URI", "OIDC_JWKS_URI", "JWKS_URI"
        ),
        description=(
            "Signing key endpoint. Discovered from the issuer when unset."
        ),
    )
    oidc_verify_audience: bool | None = Field(
        default=None,
        description=(
            "Whether a token must name this service as its audience. Unset, "
            "it is verified whenever an audience or client ID is configured. "
            "Without it, a token minted for any other service of the same "
            "issuer is accepted here too."
        ),
    )
    oidc_enforce_permissions: bool = Field(
        default=True,
        description=(
            "Whether each action requires its own permission in the token, "
            "as a scope or a client role. Off, any valid token may do "
            "anything."
        ),
    )
    oidc_permission_prefix: str = Field(
        default="crypto",
        description=(
            "Namespace of the permissions, as in 'crypto.encrypt'."
        ),
    )

    # ---- downstream integrations ----
    ledger_endpoint: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_LEDGER_ENDPOINT", "LEDGER_ENDPOINT"
        ),
        description="Distributed ledger receiving audit records.",
    )
    compliance_endpoint: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_CM_ENDPOINT", "CM_ENDPOINT", "COMPLIANCE_ENDPOINT"
        ),
        description="Compliance manager receiving task metadata and status.",
    )
    identity_endpoint: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_ILM_ENDPOINT", "ILM_ENDPOINT", "IDENTITY_ENDPOINT"
        ),
        description="Identity manager receiving audit records.",
    )
    compliance_use_case_id: str | None = Field(
        default=None,
        validation_alias=AliasChoices(
            "CRM_CM_USE_CASE_ID", "CM_USE_CASE_ID"
        ),
        description=(
            "Use case the compliance manager files records under. A request "
            "can name its own in metadata.use_case_id."
        ),
    )
    forward_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        description="Per-request timeout when forwarding audit records.",
    )
    forward_attempts: int = Field(
        default=3,
        ge=1,
        description="Deliveries tried per audit record and downstream.",
    )

    # ---- local state ----
    config_path: str = Field(
        default="./config.yaml",
        validation_alias=AliasChoices("CRM_CONFIG_PATH", "CONFIG_PATH"),
        description="Cryptographic configuration file to load at startup.",
    )
    audit_log_path: str = Field(
        default="./audit/crm-audit.jsonl",
        description="Append-only JSON-lines file receiving audit records.",
    )
    budget_store_path: str | None = Field(
        default="./audit/budgets.json",
        description=(
            "Per-user privacy budget state. Set empty to keep budgets in "
            "memory, which loses them on restart."
        ),
    )
    log_level: str = Field(
        default="INFO",
        validation_alias=AliasChoices("CRM_LOG_LEVEL", "LOG_LEVEL"),
    )
    max_request_bytes: int = Field(
        default=10 * 1024 * 1024,
        gt=0,
        description=(
            "Largest request body accepted. A differential privacy request "
            "carries its dataset inline, so without a ceiling a few "
            "concurrent callers can exhaust the process's memory."
        ),
    )

    @model_validator(mode="after")
    def _check_oidc_configured(self) -> "Settings":
        """Fail fast if OIDC is selected but no issuer was supplied."""
        if self.auth_mode == "oidc" and not self.oidc_issuer:
            raise ValueError(
                "auth_mode='oidc' requires an issuer; set CRM_OIDC_ISSUER "
                "(or KEYCLOAK_URL)"
            )
        if (
            self.auth_mode == "oidc"
            and self.oidc_verify_audience is True
            and not self.expected_audience
        ):
            raise ValueError(
                "Audience verification needs to know this service's "
                "audience; set CRM_OIDC_AUDIENCE or CRM_OIDC_CLIENT_ID, or "
                "disable it with CRM_OIDC_VERIFY_AUDIENCE=false"
            )
        return self

    @property
    def expected_audience(self) -> str | None:
        """Audience this service answers to, falling back to its client ID."""
        return self.oidc_audience or self.oidc_client_id

    @property
    def audience_to_verify(self) -> str | None:
        """Audience tokens are checked against, or ``None`` for no check."""
        if self.oidc_verify_audience is False:
            return None
        return self.expected_audience

    @property
    def issuer_url(self) -> str | None:
        """Full issuer URL, including the realm segment when one is set."""
        if not self.oidc_issuer:
            return None
        issuer = self.oidc_issuer.rstrip("/")
        if self.oidc_realm:
            return f"{issuer}/realms/{self.oidc_realm}"
        return issuer

    @property
    def audit_targets(self) -> dict[str, str]:
        """Configured downstream audit sinks, keyed by name."""
        candidates = {
            "ledger": self.ledger_endpoint,
            "compliance": self.compliance_endpoint,
            "identity": self.identity_endpoint,
        }
        return {k: v for k, v in candidates.items() if v}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings, read from the environment once."""
    return Settings()
