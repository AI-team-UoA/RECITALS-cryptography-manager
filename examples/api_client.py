"""
Driving the Cryptography Manager over its REST API.

Walks through a differential privacy query, watches the privacy budget drain
until the service refuses further queries, performs an encryption round trip,
and shows what a not-yet-implemented operation returns.

Start the service first, in another terminal:

    uv run uvicorn cryptography_manager.main:app --reload

then run:

    uv run python examples/api_client.py

The service defaults to development authentication, which accepts any bearer
token without verifying it. Set CRM_AUTH_MODE=oidc and point CRM_OIDC_ISSUER at
an identity provider to verify tokens properly.
"""

import argparse

import httpx

TOKEN = "demo-token-for-alice"


def call(client: httpx.Client, payload: dict) -> httpx.Response:
    """Send one request and print a compact summary of the outcome."""
    response = client.post(
        "/cryptography",
        json=payload,
        headers={"Authorization": f"Bearer {TOKEN}"},
    )
    body = response.json()
    status = body.get("status", "?")
    print(f"   HTTP {response.status_code}  {status}")
    if body.get("errors"):
        print(f"   error: {body['errors']}")
    return response


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:8000",
        help="Base URL of a running Cryptography Manager",
    )
    args = parser.parse_args()

    with httpx.Client(base_url=args.url, timeout=30.0) as client:
        try:
            health = client.get("/health")
        except httpx.ConnectError:
            raise SystemExit(
                f"Could not reach {args.url}. Start the service with:\n"
                f"  uv run uvicorn cryptography_manager.main:app --reload"
            )

        print("=" * 62)
        print("Service health")
        for name, state in health.json()["operations"].items():
            print(f"   {name:<26} {state}")
        print(f"   auth mode                  "
              f"{health.json()['auth_mode']}")

        print("\n1. Rejected without a token")
        anonymous = httpx.post(
            f"{args.url}/cryptography",
            json={"operation": "differential_privacy", "backend": "pydp",
                  "input_data": {"data": [1, 2, 3]}},
        )
        print(f"   HTTP {anonymous.status_code}  "
              f"{anonymous.json()['status']}")

        data = list(range(100))
        query = {
            "operation": "differential_privacy",
            "backend": "pydp",
            "input_data": {"data": data},
            "parameters": {
                "query_type": "BoundedMean",
                "epsilon_cost": 0.25,
                "lower_bound": 0,
                "upper_bound": 99,
            },
        }

        print("\n2. A differentially private mean")
        response = call(client, query)
        body = response.json()
        if response.status_code == 200:
            true_mean = sum(data) / len(data)
            print(f"   true mean  : {true_mean:.4f}")
            print(f"   private    : {body['result']:.4f}")
            print(f"   budget left: "
                  f"{body['metadata']['remaining_epsilon']:.2f}")
            print(f"   audit id   : {body['audit_id']}")

        print("\n3. Repeating the query until the budget runs out")
        for attempt in range(2, 8):
            response = call(client, query)
            if response.status_code != 200:
                print(f"   refused after {attempt - 1} further quer"
                      f"{'y' if attempt == 2 else 'ies'}")
                break
            remaining = response.json()["metadata"]["remaining_epsilon"]
            print(f"   budget left: {remaining:.2f}")

        print("\n4. Encryption round trip")
        response = call(client, {
            "operation": "key_management", "backend": "tink",
            "input_data": {}, "parameters": {"action": "generate_key"}})
        if response.status_code != 200:
            raise SystemExit("could not generate a key")
        keyset = response.json()["result"]["keyset"]

        response = call(client, {
            "operation": "encryption", "backend": "tink",
            "input_data": {"plaintext": "confidential payload"},
            "parameters": {"action": "encrypt", "associated_data": "demo"},
            "key_config": {"keyset": keyset}})
        ciphertext = response.json()["result"]["ciphertext"]
        print(f"   ciphertext : {ciphertext[:44]}...")

        response = call(client, {
            "operation": "encryption", "backend": "tink",
            "input_data": {"ciphertext": ciphertext},
            "parameters": {"action": "decrypt", "associated_data": "demo"},
            "key_config": {"keyset": keyset}})
        print(f"   decrypted  : {response.json()['result']['plaintext']}")

        print("\n5. An operation that is not implemented yet")
        call(client, {"operation": "homomorphic_encryption",
                      "backend": "pyfhel", "input_data": {"values": [1, 2]}})

        print("\n6. A request that fails validation")
        call(client, {"operation": "differential_privacy", "backend": "pydp",
                      "input_data": {"data": data},
                      "parameters": {"query_type": "BoundedMean",
                                     "epsilon_cost": -1}})

        print("\nEvery one of the above -- including the refusals -- wrote")
        print("an audit record. Check ./audit/crm-audit.jsonl.")
        print("=" * 62)


if __name__ == "__main__":
    main()
