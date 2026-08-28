"""
Authenticated encryption and key rotation with Google Tink.

Generates a keyset at runtime, encrypts and decrypts both a string and a file,
demonstrates that tampering is detected, and rotates the key while showing that
data encrypted before the rotation still decrypts afterwards.

    uv run python examples/encryption.py

No key material is written to the repository: the keyset lives in a temporary
directory that is removed when the script exits. Real deployments should keep
keysets in a secret manager or wrap them with a key management service.
"""

import tempfile
from pathlib import Path

from cryptography_manager.adapters import EncryptionAdapter
from cryptography_manager.exceptions import StandardCryptographyError


def main() -> None:
    enc = EncryptionAdapter()

    with tempfile.TemporaryDirectory() as workspace:
        workspace = Path(workspace)

        print("=" * 60)
        print("1. Key generation")
        keyset = enc.generate_keyset()
        info = enc.keyset_info(keyset)
        print(f"   primary key id : {info['primary_key_id']}")
        print(f"   algorithm      : {info['keys'][0]['type_url']}")

        print("\n2. Encrypting a string")
        secret = "patient 4471: diagnosis withheld"
        # Associated data is authenticated but not encrypted. Binding the
        # ciphertext to its context stops it being replayed somewhere else.
        context = b"record:4471"
        ciphertext = enc.encrypt_bytes(secret.encode(), keyset, context)
        print(f"   plaintext      : {secret}")
        print(f"   ciphertext     : {ciphertext[:32].hex()}... "
              f"({len(ciphertext)} bytes)")
        recovered = enc.decrypt_bytes(ciphertext, keyset, context).decode()
        print(f"   decrypted      : {recovered}")
        assert recovered == secret

        print("\n3. Tampering is detected")
        try:
            enc.decrypt_bytes(ciphertext, keyset, b"record:9999")
            print("   ERROR: wrong context was accepted")
        except StandardCryptographyError:
            print("   wrong associated data rejected, as expected")

        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= 0x01
        try:
            enc.decrypt_bytes(bytes(corrupted), keyset, context)
            print("   ERROR: corrupted ciphertext was accepted")
        except StandardCryptographyError:
            print("   modified ciphertext rejected, as expected")

        print("\n4. Encrypting a file")
        source = workspace / "secret.txt"
        source.write_text("the quick brown fox jumps over the lazy dog\n")
        encrypted = enc.encrypt_file(source, keyset)
        decrypted = enc.decrypt_file(encrypted, keyset)
        print(f"   {source.name} -> {encrypted.name} -> {decrypted.name}")
        print(f"   round trip intact: "
              f"{decrypted.read_text() == source.read_text()}")

        print("\n5. Key rotation")
        rotated = enc.rotate_keyset(keyset)
        rotated_info = enc.keyset_info(rotated)
        print(f"   keys in keyset : {rotated_info['key_count']}")
        print(f"   new primary    : {rotated_info['primary_key_id']}")
        # Old keys stay enabled, so data encrypted before the rotation is
        # still readable. Tink identifies the right key from the ciphertext.
        old = enc.decrypt_bytes(ciphertext, rotated, context).decode()
        print(f"   pre-rotation ciphertext still decrypts: {old == secret}")
        fresh = enc.encrypt_bytes(b"new data", rotated, context)
        print("   new data encrypts under the new primary key: "
              f"{enc.decrypt_bytes(fresh, rotated, context) == b'new data'}")

        print("\n6. Persisting a keyset")
        path = workspace / "keyset.json"
        path.write_text(enc.serialize_keyset(rotated))
        reloaded = enc.load_keyset(path.read_text())
        print(f"   saved to {path.name} and reloaded: "
              f"{enc.keyset_info(reloaded) == rotated_info}")
        print("   (this file holds raw key material -- never commit it)")
        print("=" * 60)


if __name__ == "__main__":
    main()
