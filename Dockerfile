# check=skip=SecretsUsedInArgOrEnv
# ^ CRM_AUTH_MODE trips Docker's secret heuristic purely for containing
#   "AUTH". It selects a verification mode and holds no credential.

# Build stage: resolve and install dependencies into a self-contained venv.
#
# Split from the runtime stage so that uv, the lockfile and the build tooling
# never ship in the final image -- only the virtual environment and the
# application code do.
FROM python:3.10-slim AS builder

# Pinned to the uv that produced uv.lock: the lockfile revision is not
# readable by older releases, and an unpinned tag would make builds drift.
COPY --from=ghcr.io/astral-sh/uv:0.12.7 /uv /usr/local/bin/uv

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never

WORKDIR /app

# Dependencies are installed before the source is copied so that editing code
# does not invalidate the dependency layer.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --no-dev \
        --extra dp --extra smpc

COPY src/ ./src/
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-dev --extra dp --extra smpc


# Runtime stage.
FROM python:3.10-slim AS runtime

LABEL org.opencontainers.image.title="RECITALS Cryptography Manager" \
      org.opencontainers.image.description="Differential privacy, encryption \
and key management for the RECITALS platform" \
      org.opencontainers.image.source="https://github.com/AI-team-UoA/RECITALS-cryptography-manager" \
      org.opencontainers.image.licenses="Apache-2.0"

# curl is needed by the healthcheck below. Nothing else is added: every extra
# package in a cryptographic service is additional attack surface.
RUN apt-get update \
    && apt-get install --no-install-recommends -y curl \
    && rm -rf /var/lib/apt/lists/*

# Run as an unprivileged user. The service needs no root capability, and a
# container that writes audit records as root produces files the host cannot
# manage.
RUN groupadd --gid 1000 crm \
    && useradd --uid 1000 --gid crm --create-home crm

WORKDIR /app

COPY --from=builder --chown=crm:crm /app/.venv /app/.venv
COPY --chown=crm:crm src/ ./src/
COPY --chown=crm:crm config.yaml ./config.yaml

# Audit records and privacy budget state persist here. Declared as a volume so
# that budgets survive container replacement -- a budget that resets on restart
# is not a privacy guarantee.
RUN mkdir -p /app/audit && chown -R crm:crm /app/audit
VOLUME ["/app/audit"]

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    CRM_CONFIG_PATH=/app/config.yaml \
    CRM_AUDIT_LOG_PATH=/app/audit/crm-audit.jsonl \
    CRM_BUDGET_STORE_PATH=/app/audit/budgets.json \
    CRM_AUTH_MODE=dev \
    CRM_LOG_LEVEL=INFO

USER crm

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://localhost:8000/health || exit 1

CMD ["uvicorn", "cryptography_manager.main:app", \
     "--host", "0.0.0.0", "--port", "8000"]
