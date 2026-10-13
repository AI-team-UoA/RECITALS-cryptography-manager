<p align="center">
    <img src="assets/recitalslogo.png" alt="Recitals Logo" width="180"/>
</p>
<h1 align="center">RECITALS Cryptography Manager</h1>
<p align="center">
    Differential privacy, encryption and key management for the RECITALS platform
</p>
<p align="center">
    <a href="https://ai-team-uoa.github.io/RECITALS-cryptography-manager/"><b>Documentation</b></a>
    &nbsp;&middot;&nbsp;
    <a href="https://ai-team-uoa.github.io/RECITALS-cryptography-manager/reference/"><b>API Reference</b></a>
</p>

## Overview

<!-- --8<-- [start:overview] -->

The RECITALS Cryptography Manager (CrM) is a modular Python library and REST
service that brings privacy-preserving and cryptographic operations to the
RECITALS platform behind a single, uniform interface. Rather than implementing
cryptography itself, it wraps vetted open-source backends and adds what a
platform component needs around them: parameter validation, privacy budget
accounting, a sanitised audit trail, and token-based authorization.

It can be used either as a Python library, imported directly into a data
processing pipeline, or as a containerised REST service that other platform
components call over HTTP.

### Supported Techniques

- **Differential privacy**: Adds calibrated statistical noise to aggregate
  queries so that the presence or absence of any single record has a
  negligible effect on the result. The strength of the guarantee is controlled
  by the privacy parameter *ε*, and every query's cost is deducted from a
  per-user budget that the service enforces.
- **Authenticated encryption**: Protects data at rest and in transit using
  vetted AEAD primitives, binding each ciphertext to its context so it cannot
  be silently replayed elsewhere.
- **Key management**: Generation, serialisation, loading and rotation of
  keysets. Rotation retains previous keys, so data encrypted before a rotation
  stays readable afterwards.

### Implementation Status

| Operation | Backend | Library | REST | Status |
| --- | --- | --- | --- | --- |
| Differential privacy | PyDP | yes | yes | Implemented |
| Encryption / decryption | Google Tink | yes | yes | Implemented |
| Key management | Google Tink | yes | yes | Implemented |
| Homomorphic encryption | Pyfhel | no | no | **Not implemented** — returns `501` |
| Secure multi-party computation | MPyC | no | no | **Not implemented** — returns `501` |

Homomorphic encryption and secure multi-party computation are recognised
operations with a settled request shape, so adding them means writing one
adapter each rather than reworking the interface.

<!-- --8<-- [end:overview] -->

## Dependencies

<!-- --8<-- [start:dependencies] -->

The **Cryptography Manager** delegates all cryptographic work to established
open-source libraries, so that the privacy and security guarantees rest on
implementations that have been reviewed far more widely than this component
could be.

### Core Libraries

<table align="center">
<tr>
    <td align="center" width="50%">
    <a href="https://github.com/OpenMined/PyDP">
    <b>PyDP</b>
    </a>
    <p align="justify">
        A Python wrapper around Google's differential privacy library,
        providing ε-differentially private aggregate statistics with noise
        calibration and sensitivity analysis inherited from a well-reviewed
        implementation.
    </p>
    </td>
    <td align="center" width="50%">
    <a href="https://developers.google.com/tink">
    <b>Google Tink</b>
    </a>
    <p align="justify">
        A misuse-resistant cryptographic library. Algorithm parameters, nonce
        generation and ciphertext tagging are handled internally, and only
        vetted primitives are reachable, leaving little room for the
        implementation errors that break real systems.
    </p>
    </td>
</tr>
</table>

### Python Infrastructure

The manager leverages a modern Python stack for performance and reliability:

* **FastAPI**: The REST service and its generated OpenAPI documentation.
* **Pydantic**: Request, response and configuration validation.
* **PyJWT**: Bearer token signature and expiry verification.
* **HTTPX**: Forwarding audit records to downstream platform services.
* **Loguru**: Structured application logging.
* **Pytest**: Automated testing and quality assurance.

<!-- --8<-- [end:dependencies] -->

## Installation

<!-- --8<-- [start:installation] -->

1. Install [uv](https://docs.astral.sh/uv/) package/project manager

2. Install the project's dependencies

    ```bash
    uv sync --extra dp --extra examples --group dev
    ```

The `dp` extra installs PyDP, which the differential privacy backend needs, and
`examples` adds pandas for the example scripts. Neither pandas nor the optional
`he`/`smpc` backends are used by the library itself.

The component targets Python 3.10, which is also what the container image
runs. PyDP is consequently held at 1.1.4: version 1.1.5 requires Python 3.11 or
newer, so the two cannot be combined.

Those two optional extras carry caveats. `he` installs **Pyfhel**, which
publishes no wheels and compiles Microsoft SEAL from source, so it needs a C++
toolchain and CMake. `smpc` installs **MPyC**; PySyft is deliberately absent,
because its pinned `numpy` and `pandas` versions cannot be satisfied alongside
this project's, and `uv` resolves every extra into a single lockfile.

<!-- --8<-- [end:installation] -->

## Usage

<!-- --8<-- [start:usage] -->

### As a library

```python
import cryptography_manager as cm

config = cm.Config()
config.load_from_file("config.yaml")

dp = cm.adapters.DifferentialPrivacyAdapter(config)

result = dp.execute_query(
    query_type="BoundedMean",
    epsilon=0.1,
    data=[1, 2, 3, 4, 5],
    lower_bound=0,
    upper_bound=10,
)
```

```python
from cryptography_manager.adapters import EncryptionAdapter

enc = EncryptionAdapter()
keyset = enc.generate_keyset()

ciphertext = enc.encrypt_bytes(b"sensitive", keyset, b"context")
plaintext = enc.decrypt_bytes(ciphertext, keyset, b"context")

# Rotation keeps old keys enabled, so existing ciphertext stays readable.
rotated = enc.rotate_keyset(keyset)
```

### As a service

```bash
uv run uvicorn cryptography_manager.main:app --reload
```

```bash
curl -X POST http://127.0.0.1:8000/cryptography \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
        "operation": "differential_privacy",
        "backend": "pydp",
        "input_data": {"data": [1, 2, 3, 4, 5]},
        "parameters": {
          "query_type": "BoundedMean",
          "epsilon_cost": 0.1,
          "lower_bound": 0,
          "upper_bound": 10
        }
      }'
```

Interactive API documentation is served at `/docs`, and a liveness and
capability report at `/health`.

<!-- --8<-- [end:usage] -->

## API

<!-- --8<-- [start:api] -->

A single endpoint executes every operation.

| Method | Endpoint | Description |
| --- | --- | --- |
| `POST` | `/cryptography` | Execute a cryptographic operation |
| `GET` | `/health` | Liveness and available operations |

### Request

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `operation` | string | yes | `differential_privacy`, `encryption`, `key_management`, `homomorphic_encryption`, `smpc` |
| `backend` | string | yes | `pydp`, `tink`, `pyfhel`, `mpyc` |
| `input_data` | object | yes | Data to process |
| `parameters` | object | no | Operation-specific; see below |
| `key_config` | object | no | Key generation or loading |
| `output_format` | string | no | `json` (default and currently the only value) |
| `metadata` | object | no | Additional execution metadata |
| `Authorization` | header | yes | `Bearer <token>` |

Unknown fields are rejected rather than ignored, so a typo in a parameter name
fails loudly instead of silently changing what runs.

**Differential privacy** — `input_data: {"data": [...]}`, and in `parameters`:
`query_type` (`Count`, `Max`, `Min`, `Median`, `BoundedMean`, `BoundedSum`,
`BoundedStandardDeviation`, `BoundedVariance`), `epsilon_cost`, and
`lower_bound` / `upper_bound`. Every query except `Count` requires bounds: they
determine sensitivity, and letting the backend infer them would spend privacy
that was never accounted for.

**Encryption** — `parameters.action` is `encrypt` or `decrypt`, with optional
`associated_data`. Input is `{"plaintext": "..."}` or
`{"ciphertext": "<base64>"}`. Ciphertext is base64 so it survives JSON.

**Key management** — `parameters.action` is `generate_key`, `rotate_key` or
`key_info`. Keysets are supplied through `key_config` as either
`{"keyset": "<json>"}` or `{"keyset_path": "..."}`.

**This component stores no key material.** `generate_key` returns the keyset to
the caller, who is responsible for keeping it and passing it back on every
subsequent call. Any operation that consumes a key requires one to be supplied:
generating a key implicitly would produce ciphertext that nobody could ever
decrypt, while reporting success.

A typical exchange:

```bash
# 1. Create a keyset and keep it. This is the only time it is handed out.
KEYSET=$(curl -s -X POST http://127.0.0.1:8000/cryptography \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"operation":"key_management","backend":"tink","input_data":{},
       "parameters":{"action":"generate_key"}}' | jq -r .result.keyset)

# 2. Encrypt, passing the keyset back in key_config.
curl -X POST http://127.0.0.1:8000/cryptography \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d "$(jq -n --arg ks "$KEYSET" '{operation:"encryption",backend:"tink",
        input_data:{plaintext:"sensitive"},
        parameters:{action:"encrypt",associated_data:"ctx"},
        key_config:{keyset:$ks}}')"
```

`rotate_key` returns the keyset with a new primary key added and the previous
keys retained, so ciphertext produced before the rotation still decrypts
afterwards. Keysets never appear in audit records.

Because the keyset travels in the request body, deployments handling real data
should terminate TLS in front of the service, and would be better served by a
keyset wrapped with a key management service. Tink supports GCP KMS, AWS KMS
and Vault natively, so that is an extension rather than a redesign.

### Response

| Field | Type | Notes |
| --- | --- | --- |
| `status` | string | Workflow outcome |
| `result` | any | Output of the operation |
| `metadata` | object | Operation-specific, e.g. `remaining_epsilon` |
| `execution_time` | number | Seconds |
| `audit_id` | string | Identifier of the audit record for this request |
| `errors` | string \| null | Populated on failure |

### Status Codes

| Code | Workflow status | Condition |
| --- | --- | --- |
| 200 | `SUCCESS` | Completed |
| 400 | `VALIDATION_ERROR` | Parameters or configuration invalid |
| 400 | `INSUFFICIENT_BUDGET` | Requested cost exceeds remaining budget |
| 401 | `UNAUTHORIZED` | Token missing or invalid |
| 403 | `FORBIDDEN` | Token valid, but lacks the permission for this action |
| 413 | `PAYLOAD_TOO_LARGE` | Request body exceeds the configured limit |
| 429 | `BUDGET_EXHAUSTED` | No privacy budget remains |
| 500 | `FAILED` | Backend raised during execution |
| 501 | `NOT_IMPLEMENTED` | Operation recognised but not yet available |

<!-- --8<-- [end:api] -->

## Configuration

<!-- --8<-- [start:configuration] -->

Cryptographic parameters live in `config.yaml` (privacy budgets, data bounds,
the library query plan). Deployment concerns come from environment variables,
so the same file can be mounted anywhere unchanged.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CRM_AUTH_MODE` | `dev` | `dev` or `oidc` |
| `CRM_OIDC_ISSUER` | – | Identity provider base URL (alias: `KEYCLOAK_URL`) |
| `CRM_OIDC_REALM` | – | Realm, if the provider uses one (alias: `KEYCLOAK_REALM`) |
| `CRM_OIDC_CLIENT_ID` | – | Client ID (alias: `KEYCLOAK_CLIENT_ID`) |
| `CRM_OIDC_CLIENT_SECRET` | – | Client secret (alias: `KEYCLOAK_CLIENT_SECRET`) |
| `CRM_OIDC_AUDIENCE` | client ID | Audience a token must carry (alias: `EXPECTED_AUDIENCE`) |
| `CRM_OIDC_JWKS_URI` | discovered | Signing key endpoint, to skip discovery (alias: `JWKS_URI`) |
| `CRM_OIDC_VERIFY_AUDIENCE` | auto | Verified whenever an audience or client ID is set; `false` disables it |
| `CRM_OIDC_ENFORCE_PERMISSIONS` | `true` | Require a per-action permission in the token |
| `CRM_OIDC_PERMISSION_PREFIX` | `crypto` | Namespace of those permissions |
| `CRM_LEDGER_ENDPOINT` | – | Distributed ledger receiving audit records (alias: `LEDGER_ENDPOINT`) |
| `CRM_CM_ENDPOINT` | – | Compliance manager; records are uploaded to `<endpoint>/input` (alias: `CM_ENDPOINT`) |
| `CRM_CM_USE_CASE_ID` | – | Use case the compliance manager files records under (alias: `CM_USE_CASE_ID`) |
| `CRM_ILM_ENDPOINT` | – | Identity manager receiving audit records |
| `CRM_FORWARD_ATTEMPTS` | `3` | Deliveries tried per audit record and downstream service |
| `CRM_CONFIG_PATH` | `./config.yaml` | Configuration file to load |
| `CRM_AUDIT_LOG_PATH` | `./audit/crm-audit.jsonl` | Local audit trail |
| `CRM_BUDGET_STORE_PATH` | `./audit/budgets.json` | Per-user budget state; unset to keep in memory |
| `CRM_LOG_LEVEL` | `INFO` | Log verbosity (alias: `LOG_LEVEL`) |
| `CRM_MAX_REQUEST_BYTES` | `10485760` | Largest accepted request body (10 MiB) |

### Authentication

Token verification is written against **generic OpenID Connect** — discovery
via `.well-known/openid-configuration`, then local JWKS signature and expiry
validation — rather than any one vendor's API, so it works with any conforming
provider. Only asymmetric signature algorithms are accepted, which closes the
algorithm-confusion attack where a token is signed with HMAC using the
provider's public key as the secret.

In `oidc` mode a token must pass four checks: signature, expiry, issuer and
audience. The audience is this service's client ID unless `CRM_OIDC_AUDIENCE`
says otherwise, and is what stops a token issued for another platform service
from being replayed here. With Keycloak, a typical configuration is:

```bash
CRM_AUTH_MODE=oidc
KEYCLOAK_URL=https://keycloak.example
KEYCLOAK_REALM=recitals
KEYCLOAK_CLIENT_ID=recitals-cryptography-manager
```

A valid token identifies the caller; it does not by itself allow anything.
Each action needs its own permission, named `crypto.<action>`:

| Action | Permission |
| --- | --- |
| `encrypt`, `decrypt` | `crypto.encrypt`, `crypto.decrypt` |
| `generate_key`, `rotate_key`, `key_info` | `crypto.generate_key`, `crypto.rotate_key`, `crypto.key_info` |
| `query` (differential privacy) | `crypto.query` |

A permission is granted by a matching entry in the token's `scope`, by a realm
role of that name, or by a client role on this service — where the prefix may
be dropped, so the role `encrypt` under
`resource_access.<client ID>.roles` grants `crypto.encrypt`. A caller without
it receives `403` and the name of the permission it lacks.

The default `dev` mode accepts any bearer token **without verifying it** and
derives a stable per-caller identity from a digest of the token, so budgets
still separate correctly. It enforces no permissions. It exists so the service
is runnable without an identity provider. **Never use it in a real
deployment.**

### Privacy Budgets

Each user gets `privacy_budget_limit` epsilon. Every differential privacy
request is checked against the remaining budget before it runs and debited only
after it succeeds, so a failed query costs nothing. A request costing more than
what remains is refused with `400`; a user with nothing left gets `429`.

Budgets persist to `CRM_BUDGET_STORE_PATH`, because a budget that resets when
the container restarts is not a privacy guarantee. The store is single-node; a
multi-replica deployment needs a shared backend, and `BudgetStore` is the seam
to add one behind.

### Audit Trail

Every request produces exactly one audit record — including requests that were
refused, so a rejection is as traceable as a success. Records are appended as
JSON lines locally and, when the corresponding endpoints are configured,
forwarded to the ledger, compliance and identity services. Forwarding is
best-effort and runs off the request path: a delivery is retried a few times,
and a downstream service that stays unreachable is logged and never fails the
caller's request. The local file remains the complete record.

Besides the outcome, a record names the caller, the client their token was
issued to and its issuer, and carries the request's `metadata`, so a caller can
pass a workflow identifier through for later correlation.

The compliance manager is sent RDF rather than JSON, as its input API requires:
each record is rendered as a Turtle document using the Data Privacy Vocabulary
and uploaded to `/input`, with the outcome reduced to `passed` or `failed`. It
files every submission under a use case, so set `CRM_CM_USE_CASE_ID`, or name
one per request in `metadata.use_case_id`; a record with neither is not sent.
The use case must already exist there.

When the service has client credentials of its own (`oidc` mode with a client
secret), it obtains a service token and presents it on these calls.

Sensitive material never reaches a record. Key material, plaintext, ciphertext,
tokens, passwords and secret shares are redacted by key name, and bulk data is
reduced to a size summary, so a record says how much was processed without
saying what it was.

<!-- --8<-- [end:configuration] -->

## Examples & Testing

<!-- --8<-- [start:examples] -->

### Testing

We use **pytest** to ensure correctness of the **Cryptography Manager**.

To run the tests in your local environment, use the following command:

```bash
# Execute the test suite with uv
uv run pytest
```

The tests run against the real backends — real Tink keysets, real PyDP queries,
a real local OpenID Connect provider, a real ASGI client. Nothing cryptographic
is mocked, because a test that mocks the cryptography verifies only that the
mock was called.

```bash
uv run pytest tests/test_auth.py    # one module
uv run pytest -k rotation -v        # anything matching a name
uv run pytest -m "not slow"         # skip tests that bind a real port

uv run ruff check src/ examples/ tests/
uv run basedpyright src/
```

### Examples

Detailed workflow examples can be found in the [**/examples**](https://github.com/AI-team-UoA/RECITALS-cryptography-manager/tree/main/examples)
directory.

To execute an example script, use the following command:

```bash
# Execute the differential privacy example with uv
uv run examples/dp.py
```

| Script | Demonstrates |
| --- | --- |
| [`dp.py`](https://github.com/AI-team-UoA/RECITALS-cryptography-manager/blob/main/examples/dp.py) | A configured plan of differentially private queries over a CSV |
| [`encryption.py`](https://github.com/AI-team-UoA/RECITALS-cryptography-manager/blob/main/examples/encryption.py) | Encryption, tamper detection and key rotation |
| [`api_client.py`](https://github.com/AI-team-UoA/RECITALS-cryptography-manager/blob/main/examples/api_client.py) | The REST API end to end, including budget exhaustion |

<!-- --8<-- [end:examples] -->

## Deployment

<!-- --8<-- [start:deployment] -->

The service runs as a container. Building from a clone needs no registry
access and is the quickest way to get an instance up:

```bash
git clone https://github.com/AI-team-UoA/RECITALS-cryptography-manager.git
cd RECITALS-cryptography-manager

docker build -t recitals-cryptography-manager .
docker run -p 8000:8000 \
  -v "$(pwd)/config.yaml:/app/config.yaml:ro" \
  -v crm-audit:/app/audit \
  recitals-cryptography-manager
```

Prebuilt images are published to
`ghcr.io/ai-team-uoa/recitals-cryptography-manager` on every push to `main`,
tagged `latest`, `main` and `sha-<commit>`.

> **The package is currently private.** Pulling it requires authenticating to
> the registry with a personal access token carrying the `read:packages` scope,
> and membership of the organisation:
>
> ```bash
> echo "$GITHUB_TOKEN" | docker login ghcr.io -u YOUR_USERNAME --password-stdin
> docker pull ghcr.io/ai-team-uoa/recitals-cryptography-manager:latest
> ```
>
> An organisation owner can make it public from the package's settings page,
> after which the pull works anonymously and no login is needed.

The image runs as an unprivileged user, exposes port 8000 and carries a
healthcheck against `/health`. Audit records and privacy budget state are
written to `/app/audit`, which is declared as a volume: a privacy budget that
resets when the container is replaced is not a guarantee of anything.

Images are `linux/amd64` only, because PyDP publishes x86_64 manylinux wheels
and no aarch64 build.

For local development and integration testing, `docker-compose.yml` brings the
service up alongside stand-ins for the three downstream services it forwards
audit records to, so that path is genuinely exercised rather than merely
configured. It builds from the working tree, so it needs no registry access
either:

```bash
docker compose up --build
docker compose logs -f ledger compliance identity   # watch records arrive
```

`.github/workflows/ci.yml` runs the linter, the type checker and the test suite
on Python 3.10, 3.11 and 3.12, then builds the image, smoke-tests it, and
publishes to the registry. Pull requests build the image to prove the
Dockerfile still works but never publish it.

<!-- --8<-- [end:deployment] -->

## Roadmap

<!-- --8<-- [start:roadmap] -->

- Homomorphic encryption and secure multi-party computation adapters.
- A Helm chart for Kubernetes deployment.
- A shared privacy budget backend, so the service can run more than one
  replica without each replica keeping its own view of every user's budget.
- JSON-LD output. The vocabulary needs to align with the compliance manager's
  graphs, which are not settled yet, so `output_format` currently accepts only
  `json` rather than silently ignoring the field.

<!-- --8<-- [end:roadmap] -->

## Contributors

<div align=center>
<table>
    <tr>
        <td align="center" width="150">
        <a href="https://www.linkedin.com/in/kchousos">
        <img src="https://github.com/kchousos.png" width="100px;" style="border-radius:50%;" alt="Konstantinos Chousos"/><br />
        <b>Konstantinos Chousos</b>
        </a><br/>
        <sub>Research Assistant</sub>
        </td>
        <td align="center" width="150">
        <a href="https://www.linkedin.com/in/dimitris-pavlou-gr">
        <img src="https://github.com/dimitriospavlougr.png" width="100px;" style="border-radius:50%;" alt="Dimitrios Pavlou"/><br />
        <b>Dimitrios Pavlou</b>
        </a><br/>
        <sub>Research Assistant</sub>
        </td>
        <td align="center" width="150">
        <a href="https://www.linkedin.com/in/stamoulisgeorge">
        <img src="https://github.com/zefyros.png" width="100px;" style="border-radius:50%;" alt="George Stamoulis"/><br />
        <b>George Stamoulis</b>
        </a><br/>
        <sub>Research Associate</sub>
        </td>
    </tr>
</table>
</div>

## Funding

This project has received funding from the European Union's Horizon Europe
research and innovation programme under grant agreement
[**No.101168490**](https://cordis.europa.eu/project/id/101168490). The European
Commission authority managing the RECITALS project is the European
Cybersecurity Competence Center.

<div align="center">
<img src="assets/eu_funded_en.png" width="200" alt="Funded by the European Union">
</div>
