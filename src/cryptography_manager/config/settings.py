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
    oidc_verify_audience: bool = Field(
        default=False,
        description=(
            "Whether to require the token audience to match the client ID. "
            "Off by default because providers differ in how they populate it."
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
    forward_timeout_seconds: float = Field(
        default=5.0,
        gt=0,
        description="Per-request timeout when forwarding audit records.",
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

    @model_validator(mode="after")
    def _check_oidc_configured(self) -> "Settings":
        """Fail fast if OIDC is selected but no issuer was supplied."""
        if self.auth_mode == "oidc" and not self.oidc_issuer:
            raise ValueError(
                "auth_mode='oidc' requires an issuer; set CRM_OIDC_ISSUER "
                "(or KEYCLOAK_URL)"
            )
        return self

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
