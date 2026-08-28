"""
Service entry point.

Builds the FastAPI application and wires together the pieces a request needs:
configuration, the manager that dispatches to backends, per-user budget
accounting, audit logging and token verification. Everything is assembled once
at startup and shared, because rebuilding adapters or re-reading budget state
per request would be both slow and, in the budget's case, wrong.
"""

from __future__ import annotations

import sys
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from loguru import logger

from .api.auth import build_verifier
from .api.routes import router
from .config import Config
from .config.settings import Settings, get_settings
from .core.audit import AuditLogger
from .core.budget import BudgetStore, FileBudgetStore, InMemoryBudgetStore
from .core.manager import CryptographyManager
from .core.workflow import CryptographyWorkflow

TITLE = "RECITALS Cryptography Manager"
VERSION = "0.2.0"
DESCRIPTION = (
    "Unified interface for differential privacy, encryption and key "
    "management. Homomorphic encryption and secure multi-party computation "
    "are recognised but not yet implemented."
)


def _configure_logging(level: str) -> None:
    """Route loguru output to stderr at the requested level."""
    logger.remove()
    logger.add(sys.stderr, level=level.upper())


def _build_budget_store(
    settings: Settings, config: Config
) -> BudgetStore:
    """Construct the privacy budget store described by configuration."""
    section = config.get_submodule_config("differential_privacy") or {}
    total = float(section.get("privacy_budget_limit", 1.0))
    delta = section.get("default_delta")

    if settings.budget_store_path:
        return FileBudgetStore(
            total_epsilon=total,
            path=settings.budget_store_path,
            delta=delta,
        )
    logger.warning(
        "Privacy budgets are held in memory and will reset when this "
        "process restarts; set CRM_BUDGET_STORE_PATH to persist them."
    )
    return InMemoryBudgetStore(total_epsilon=total, delta=delta)


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the application.

    Args:
        settings: Runtime settings; read from the environment when omitted.

    Returns:
        The configured application.
    """
    settings = settings or get_settings()
    _configure_logging(settings.log_level)

    config = Config()
    config_path = Path(settings.config_path)
    if config_path.exists():
        config.load_from_file(config_path)
        logger.info(f"Loaded configuration from {config_path}")
    else:
        logger.warning(
            f"No configuration file at {config_path}; using defaults"
        )

    manager = CryptographyManager(config=config)
    audit = AuditLogger(
        log_path=settings.audit_log_path,
        targets=settings.audit_targets,
        timeout=settings.forward_timeout_seconds,
    )
    budget_store = _build_budget_store(settings, config)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        """Let in-flight audit forwards finish before the process exits."""
        yield
        audit.shutdown()

    app = FastAPI(
        title=TITLE,
        version=VERSION,
        description=DESCRIPTION,
        lifespan=lifespan,
    )

    app.state.settings = settings
    app.state.config = config
    app.state.manager = manager
    app.state.audit = audit
    app.state.budget_store = budget_store
    app.state.verifier = build_verifier(settings)
    app.state.workflow = CryptographyWorkflow(manager, audit, budget_store)

    app.include_router(router)

    targets = ", ".join(settings.audit_targets) or "local file only"
    logger.info(f"{TITLE} ready; audit targets: {targets}")
    return app


app = create_app()


def main() -> None:
    """Console script entry point: serve the API with uvicorn."""
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "cryptography_manager.main:app",
        host="0.0.0.0",
        port=8000,
        log_level=settings.log_level.lower(),
    )
