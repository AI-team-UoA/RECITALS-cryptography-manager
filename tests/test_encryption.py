"""Authenticated encryption, keyset lifecycle and key rotation via Tink."""

from __future__ import annotations

import base64
import json

import pytest

from cryptography_manager.adapters.encryption import DEFAULT_TEMPLATE
from cryptography_manager.exceptions import (
    KeyManagementError,
    StandardCryptographyError,
)

PLAINTEXT = "RECITALS sensitive payload äöü \U0001f510".encode()
CONTEXT = b"record:4471"


class TestKeysetLifecycle:
    def test_generated_keyset_has_one_primary_key(self, enc, keyset):
        info = enc.keyset_info(keyset)
        assert info["key_count"] == 1
        assert info["primary_key_id"] == info["keys"][0]["key_id"]

    def test_serialise_and_load_round_trip(self, enc, keyset):
        restored = enc.load_keyset(enc.serialize_keyset(keyset))
        assert enc.keyset_info(restored) == enc.keyset_info(keyset)

    @pytest.mark.parametrize(
        "template",
        ["AES256_GCM_SIV", "AES256_GCM", "AES128_GCM", "XCHACHA20_POLY1305"],
    )
    def test_every_allowlisted_template_works(self, enc, template):
        handle = enc.generate_keyset(template)
        assert enc.decrypt_bytes(
            enc.encrypt_bytes(PLAINTEXT, handle, CONTEXT), handle, CONTEXT
        ) == PLAINTEXT

    def test_unknown_template_is_rejected(self, enc):
        with pytest.raises(KeyManagementError, match="Unsupported key"):
            enc.generate_keyset("ROT13")

    def test_malformed_keyset_is_rejected(self, enc):
        with pytest.raises(KeyManagementError, match="Failed to parse"):
            enc.load_keyset("{not a keyset}")

    def test_keyset_info_never_exposes_key_material(self, enc, keyset):
        raw = json.loads(enc.serialize_keyset(keyset))
        secret = raw["key"][0]["keyData"]["value"]
        assert secret not in json.dumps(enc.keyset_info(keyset))


class TestEncryptDecrypt:
    def test_round_trip(self, enc, keyset):
        ciphertext = enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT)
        assert ciphertext != PLAINTEXT
        assert enc.decrypt_bytes(ciphertext, keyset, CONTEXT) == PLAINTEXT

    def test_encryption_is_randomised(self, enc, keyset):
        first = enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT)
        second = enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT)
        assert first != second, "identical ciphertexts leak equality"

    def test_wrong_associated_data_is_rejected(self, enc, keyset):
        ciphertext = enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT)
        with pytest.raises(StandardCryptographyError):
            enc.decrypt_bytes(ciphertext, keyset, b"record:9999")

    def test_wrong_keyset_is_rejected(self, enc, keyset):
        ciphertext = enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT)
        with pytest.raises(StandardCryptographyError):
            enc.decrypt_bytes(ciphertext, enc.generate_keyset(), CONTEXT)

    def test_tampered_ciphertext_is_rejected(self, enc, keyset):
        ciphertext = bytearray(enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT))
        ciphertext[-1] ^= 0x01
        with pytest.raises(StandardCryptographyError):
            enc.decrypt_bytes(bytes(ciphertext), keyset, CONTEXT)

    def test_empty_plaintext_round_trips(self, enc, keyset):
        assert enc.decrypt_bytes(
            enc.encrypt_bytes(b"", keyset, CONTEXT), keyset, CONTEXT
        ) == b""


class TestRotation:
    """Rotation is built at the protobuf layer, so it is tested closely.

    The property that matters is that rotating never strands data: old keys
    stay enabled, and Tink picks the right one from the ciphertext prefix.
    """

    def test_rotation_adds_a_key_and_moves_the_primary(self, enc, keyset):
        before = enc.keyset_info(keyset)
        after = enc.keyset_info(enc.rotate_keyset(keyset))
        assert after["key_count"] == before["key_count"] + 1
        assert after["primary_key_id"] != before["primary_key_id"]

    def test_old_keys_are_retained_and_enabled(self, enc, keyset):
        before = enc.keyset_info(keyset)
        after = enc.keyset_info(enc.rotate_keyset(keyset))
        assert before["primary_key_id"] in [k["key_id"] for k in after["keys"]]
        assert all(k["status"] == "ENABLED" for k in after["keys"])

    def test_ciphertext_survives_repeated_rotation(self, enc, keyset):
        ciphertext = enc.encrypt_bytes(PLAINTEXT, keyset, CONTEXT)
        rotated = keyset
        for _ in range(3):
            rotated = enc.rotate_keyset(rotated)
        assert enc.keyset_info(rotated)["key_count"] == 4
        assert enc.decrypt_bytes(ciphertext, rotated, CONTEXT) == PLAINTEXT

    def test_new_data_uses_the_new_primary(self, enc, keyset):
        rotated = enc.rotate_keyset(keyset)
        fresh = enc.encrypt_bytes(b"new", rotated, CONTEXT)
        assert enc.decrypt_bytes(fresh, rotated, CONTEXT) == b"new"
        # The original keyset never saw the new key, so it cannot read this.
        with pytest.raises(StandardCryptographyError):
            enc.decrypt_bytes(fresh, keyset, CONTEXT)

    def test_rotated_keyset_survives_serialisation(self, enc, keyset):
        rotated = enc.rotate_keyset(keyset)
        restored = enc.load_keyset(enc.serialize_keyset(rotated))
        assert enc.keyset_info(restored) == enc.keyset_info(rotated)


class TestFileHelpers:
    def test_round_trip(self, enc, keyset, tmp_path):
        source = tmp_path / "secret.txt"
        source.write_text("the quick brown fox")
        encrypted = enc.encrypt_file(source, keyset)
        assert encrypted.name == "secret.txt.enc"
        decrypted = enc.decrypt_file(encrypted, keyset)
        assert decrypted.read_text() == source.read_text()

    def test_non_enc_suffix_is_rejected(self, enc, keyset, tmp_path):
        path = tmp_path / "plain.txt"
        path.write_text("x")
        with pytest.raises(StandardCryptographyError, match="'.enc' file"):
            enc.decrypt_file(path, keyset)

    def test_ciphertext_is_bound_to_the_filename(self, enc, keyset, tmp_path):
        source = tmp_path / "secret.txt"
        source.write_text("payload")
        encrypted = enc.encrypt_file(source, keyset)
        renamed = encrypted.with_name("other.txt.enc")
        encrypted.rename(renamed)
        # The associated data is the original name, so a rename breaks it.
        with pytest.raises(StandardCryptographyError):
            enc.decrypt_file(renamed, keyset)


class TestAdapterInterface:
    def test_generate_encrypt_decrypt_cycle(self, enc):
        result, _ = enc.execute(
            action="generate_key", input_data={}, parameters={}
        )
        keyset = result["keyset"]

        result, meta = enc.execute(
            action="encrypt",
            input_data={"plaintext": "hello"},
            parameters={"associated_data": "ctx"},
            key_config={"keyset": keyset},
        )
        ciphertext = result["ciphertext"]
        assert base64.b64decode(ciphertext, validate=True)
        assert meta["keyset_info"]["key_count"] == 1

        result, _ = enc.execute(
            action="decrypt",
            input_data={"ciphertext": ciphertext},
            parameters={"associated_data": "ctx"},
            key_config={"keyset": keyset},
        )
        assert result["plaintext"] == "hello"

    def test_key_info_returns_no_key_material(self, enc):
        result, meta = enc.execute(
            action="key_info", input_data={}, parameters={}
        )
        assert result == {}
        assert "keys" in meta["keyset_info"]

    def test_rotate_through_the_adapter(self, enc, keyset):
        _, meta = enc.execute(
            action="rotate_key",
            input_data={},
            parameters={},
            key_config={"keyset": enc.serialize_keyset(keyset)},
        )
        assert meta["keyset_info"]["key_count"] == 2

    def test_keyset_loaded_from_a_path(self, enc, keyset, tmp_path):
        path = tmp_path / "keyset.json"
        path.write_text(enc.serialize_keyset(keyset))
        _, meta = enc.execute(
            action="key_info",
            input_data={},
            parameters={},
            key_config={"keyset_path": str(path)},
        )
        assert meta["keyset_info"] == enc.keyset_info(keyset)

    def test_missing_keyset_path_is_rejected(self, enc, tmp_path):
        with pytest.raises(KeyManagementError, match="not found"):
            enc.execute(
                action="key_info",
                input_data={},
                parameters={},
                key_config={"keyset_path": str(tmp_path / "nope.json")},
            )

    @pytest.mark.parametrize(
        "action,input_data,match",
        [
            ("bogus", {}, "Unsupported encryption action"),
            ("encrypt", {}, "must contain 'plaintext'"),
            ("decrypt", {}, "must contain 'ciphertext'"),
            ("decrypt", {"ciphertext": "!!not-base64!!"}, "not valid base64"),
        ],
    )
    def test_bad_input_is_rejected(self, enc, action, input_data, match):
        with pytest.raises(StandardCryptographyError, match=match):
            enc.execute(
                action=action, input_data=input_data, parameters={}
            )

    def test_default_template_is_nonce_misuse_resistant(self):
        # AES-GCM-SIV tolerates nonce reuse, which matters because callers
        # here do not manage nonces themselves.
        assert DEFAULT_TEMPLATE == "AES256_GCM_SIV"
