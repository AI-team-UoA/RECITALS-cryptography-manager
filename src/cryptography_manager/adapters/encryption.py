"""
Encryption, decryption and key management via Google Tink.

Tink is used rather than a raw cipher library because it is misuse-resistant:
algorithm parameters, nonce generation and ciphertext tagging are handled
internally, and only vetted primitives are reachable. This adapter exposes the
AEAD primitive plus the keyset lifecycle operations (generation, serialisation,
loading and rotation).

The byte-level operations are the core; the file helpers are a thin convenience
layer for the library and example code. A REST caller cannot pass file
paths, so nothing above this module depends on the filesystem.
"""

from __future__ import annotations

import base64
from pathlib import Path
from typing import Any, ClassVar, final

import tink
from loguru import logger
from tink import aead, json_proto_keyset_format, proto_keyset_format
from tink import secret_key_access
from tink.proto import tink_pb2

from ..exceptions import BackendImportError, KeyManagementError
from ..exceptions import StandardCryptographyError
from .base import AdapterResult, CryptographicAdapter

try:
    aead.register()  # Register the AEAD primitive with Tink's registry.
except Exception as exc:  # pragma: no cover - environment problem
    raise BackendImportError(f"Failed to initialise Tink backend: {exc}")

# tink_pb2 is generated at build time and ships no type stubs, so a checker
# cannot see these attributes even though they exist at runtime. Binding them
# once keeps the rest of the module readable and confines the untyped surface
# to three lines.
_proto: Any = tink_pb2
_Keyset: Any = _proto.Keyset
_KeyStatus: Any = _proto.KeyStatusType
_OutputPrefix: Any = _proto.OutputPrefixType


# Only AEAD templates are offered: authenticated encryption is the right
# default for data at rest, and restricting the set prevents a caller from
# selecting a weaker mode. AES256_GCM_SIV is nonce-misuse resistant, which is
# the safest choice when callers may not manage nonces carefully.
_KEY_TEMPLATES: dict[str, str] = {
    "AES256_GCM_SIV": "AES256_GCM_SIV",
    "AES256_GCM": "AES256_GCM",
    "AES128_GCM": "AES128_GCM",
    "XCHACHA20_POLY1305": "XCHACHA20_POLY1305",
}

DEFAULT_TEMPLATE = "AES256_GCM_SIV"


def _template(name: str):
    """Resolve a key template name against the allowlist."""
    if name not in _KEY_TEMPLATES:
        supported = ", ".join(sorted(_KEY_TEMPLATES))
        raise KeyManagementError(
            f"Unsupported key template '{name}'; supported: {supported}",
            operation="key_template",
        )
    return getattr(aead.aead_key_templates, _KEY_TEMPLATES[name])


@final
class EncryptionAdapter(CryptographicAdapter):
    """Symmetric authenticated encryption and keyset management via Tink."""

    operation: ClassVar[str] = "encryption"
    backend: ClassVar[str] = "tink"

    # ---------------- key management ----------------

    @staticmethod
    def generate_keyset(
        template: str = DEFAULT_TEMPLATE,
    ) -> tink.KeysetHandle:
        """Generate a new keyset containing a single primary key.

        Args:
            template: Name of an allowlisted AEAD key template.

        Returns:
            A handle to the newly generated keyset.
        """
        return tink.new_keyset_handle(_template(template))

    @staticmethod
    def serialize_keyset(handle: tink.KeysetHandle) -> str:
        """Serialise a keyset to cleartext JSON.

        The output contains raw key material and must be stored in a secret
        manager or encrypted at rest. It is never written to an audit record.

        Args:
            handle: The keyset to serialise.

        Returns:
            The keyset as a JSON string.
        """
        return json_proto_keyset_format.serialize(
            handle, secret_key_access.TOKEN
        )

    @staticmethod
    def load_keyset(serialized: str) -> tink.KeysetHandle:
        """Load a keyset from its cleartext JSON representation.

        Args:
            serialized: JSON produced by :meth:`serialize_keyset`.

        Returns:
            A handle to the loaded keyset.

        Raises:
            KeyManagementError: If the keyset cannot be parsed.
        """
        try:
            return json_proto_keyset_format.parse(
                serialized, secret_key_access.TOKEN
            )
        except Exception as exc:
            raise KeyManagementError(
                f"Failed to parse keyset: {exc}", operation="load_keyset"
            )

    @staticmethod
    def rotate_keyset(
        handle: tink.KeysetHandle,
        template: str = DEFAULT_TEMPLATE,
    ) -> tink.KeysetHandle:
        """Add a fresh key to a keyset and promote it to primary.

        Existing keys are retained and stay enabled, so ciphertexts produced
        before the rotation remain decryptable. Tink prefixes each ciphertext
        with its key ID, which is what makes this work.

        tink-py 1.12 exposes no ``KeysetManager``, so the merge is done at the
        protobuf layer using the public ``tink.proto`` and
        ``proto_keyset_format`` modules rather than private attributes.

        Args:
            handle: The keyset to rotate.
            template: Template for the new primary key.

        Returns:
            A handle to the rotated keyset.

        Raises:
            KeyManagementError: If the rotation fails.
        """
        try:
            current = _Keyset.FromString(
                proto_keyset_format.serialize(handle, secret_key_access.TOKEN)
            )
            fresh = _Keyset.FromString(
                proto_keyset_format.serialize(
                    tink.new_keyset_handle(_template(template)),
                    secret_key_access.TOKEN,
                )
            )

            existing_ids = {k.key_id for k in current.key}
            for key in fresh.key:
                if key.key_id in existing_ids:
                    raise KeyManagementError(
                        f"Generated key ID {key.key_id} already present",
                        operation="rotate_keyset",
                    )
                current.key.append(key)

            current.primary_key_id = fresh.primary_key_id

            rotated = proto_keyset_format.parse(
                current.SerializeToString(), secret_key_access.TOKEN
            )
        except KeyManagementError:
            raise
        except Exception as exc:
            raise KeyManagementError(
                f"Failed to rotate keyset: {exc}", operation="rotate_keyset"
            )

        logger.info(
            f"Keyset rotated: new primary key ID {current.primary_key_id}, "
            f"{len(current.key)} key(s) retained"
        )
        return rotated

    @staticmethod
    def keyset_info(handle: tink.KeysetHandle) -> dict[str, Any]:
        """Describe a keyset without exposing key material.

        Only key IDs, type URLs, status and prefix type are returned, making
        the result safe to log and to return over the API.

        Args:
            handle: The keyset to describe.

        Returns:
            Keyset metadata suitable for audit and API responses.
        """
        info = handle.keyset_info()
        return {
            "primary_key_id": info.primary_key_id,
            "key_count": len(info.key_info),
            "keys": [
                {
                    "key_id": k.key_id,
                    "type_url": k.type_url,
                    "status": _KeyStatus.Name(k.status),
                    "output_prefix_type": _OutputPrefix.Name(
                        k.output_prefix_type
                    ),
                }
                for k in info.key_info
            ],
        }

    # ---------------- byte-level operations ----------------

    @staticmethod
    def _primitive(handle: tink.KeysetHandle) -> aead.Aead:
        """Obtain the AEAD primitive for a keyset."""
        try:
            return handle.primitive(aead.Aead)
        except Exception as exc:
            raise StandardCryptographyError(
                f"Keyset does not provide an AEAD primitive: {exc}",
                algorithm="aead",
                operation="primitive",
            )

    def encrypt_bytes(
        self,
        plaintext: bytes,
        handle: tink.KeysetHandle,
        associated_data: bytes = b"",
    ) -> bytes:
        """Encrypt bytes with authenticated encryption.

        Args:
            plaintext: Data to encrypt.
            handle: Keyset providing the AEAD primitive.
            associated_data: Context bound to the ciphertext. It is
                authenticated but not encrypted, and the exact same value must
                be supplied to decrypt.

        Returns:
            The ciphertext.

        Raises:
            StandardCryptographyError: If encryption fails.
        """
        try:
            return self._primitive(handle).encrypt(
                plaintext, associated_data
            )
        except StandardCryptographyError:
            raise
        except Exception as exc:
            raise StandardCryptographyError(
                f"Encryption failed: {exc}",
                algorithm="aead",
                operation="encrypt",
            )

    def decrypt_bytes(
        self,
        ciphertext: bytes,
        handle: tink.KeysetHandle,
        associated_data: bytes = b"",
    ) -> bytes:
        """Decrypt bytes produced by :meth:`encrypt_bytes`.

        Args:
            ciphertext: Data to decrypt.
            handle: Keyset providing the AEAD primitive.
            associated_data: The exact value used at encryption time.

        Returns:
            The recovered plaintext.

        Raises:
            StandardCryptographyError: If decryption or authentication fails.
        """
        try:
            return self._primitive(handle).decrypt(
                ciphertext, associated_data
            )
        except StandardCryptographyError:
            raise
        except Exception as exc:
            # Covers a wrong key, mismatched associated data and tampering
            # alike; the distinction is deliberately not surfaced.
            raise StandardCryptographyError(
                f"Decryption failed: {exc}",
                algorithm="aead",
                operation="decrypt",
            )

    # ---------------- file helpers ----------------

    def encrypt_file(
        self,
        path: str | Path,
        handle: tink.KeysetHandle,
        output: str | Path | None = None,
    ) -> Path:
        """Encrypt a file, binding the ciphertext to its basename.

        Args:
            path: File to encrypt.
            handle: Keyset providing the AEAD primitive.
            output: Destination; defaults to ``path`` with ``.enc`` appended.

        Returns:
            Path to the ciphertext file.
        """
        path = Path(path)
        destination = Path(output) if output else path.with_suffix(
            path.suffix + ".enc"
        )
        associated_data = path.name.encode("utf-8")
        ciphertext = self.encrypt_bytes(
            path.read_bytes(), handle, associated_data
        )
        destination.write_bytes(ciphertext)
        return destination

    def decrypt_file(
        self,
        path: str | Path,
        handle: tink.KeysetHandle,
        output: str | Path | None = None,
    ) -> Path:
        """Decrypt a file produced by :meth:`encrypt_file`.

        Args:
            path: Ciphertext file; must end in ``.enc``.
            handle: Keyset providing the AEAD primitive.
            output: Destination; defaults to ``path`` with ``.dec`` appended.

        Returns:
            Path to the recovered plaintext file.

        Raises:
            StandardCryptographyError: If the filename is not ``.enc``.
        """
        path = Path(path)
        if path.suffix != ".enc":
            raise StandardCryptographyError(
                f"Expected a '.enc' file, got '{path.name}'",
                algorithm="aead",
                operation="decrypt_file",
            )
        # The associated data is the *original* filename, so strip '.enc'.
        associated_data = path.with_suffix("").name.encode("utf-8")
        destination = Path(output) if output else path.with_suffix(
            path.suffix + ".dec"
        )
        plaintext = self.decrypt_bytes(
            path.read_bytes(), handle, associated_data
        )
        destination.write_bytes(plaintext)
        return destination

    # ---------------- adapter entry point ----------------

    def _resolve_keyset(
        self, key_config: dict[str, Any] | None
    ) -> tink.KeysetHandle:
        """Build a keyset handle from a request's ``key_config``.

        Supports an inline serialised keyset, a filesystem path, or generating
        an ephemeral one. Key material supplied inline is never echoed back.

        Args:
            key_config: Key generation or loading configuration.

        Returns:
            A keyset handle.
        """
        config = key_config or {}
        if "keyset" in config:
            return self.load_keyset(config["keyset"])
        if "keyset_path" in config:
            keyset_path = Path(config["keyset_path"])
            if not keyset_path.exists():
                raise KeyManagementError(
                    f"Keyset file not found: {keyset_path}",
                    operation="load_keyset",
                )
            return self.load_keyset(keyset_path.read_text(encoding="utf-8"))
        return self.generate_keyset(config.get("template", DEFAULT_TEMPLATE))

    def execute(
        self,
        *,
        action: str,
        input_data: dict[str, Any],
        parameters: dict[str, Any],
        key_config: dict[str, Any] | None = None,
    ) -> AdapterResult:
        """Run an encryption or key-management action.

        Args:
            action: One of ``encrypt``, ``decrypt``, ``generate_key``,
                ``rotate_key`` or ``key_info``.
            input_data: For ``encrypt``, ``{"plaintext": <str>}``; for
                ``decrypt``, ``{"ciphertext": <base64 str>}``.
            parameters: May carry ``associated_data`` and ``template``.
            key_config: Keyset selection; see :meth:`_resolve_keyset`.

        Returns:
            A ``(result, metadata)`` pair. Ciphertext is base64-encoded so it
            survives a JSON round trip.

        Raises:
            StandardCryptographyError: If the action is unknown or fails.
        """
        associated_data = parameters.get("associated_data", "")
        associated = (
            associated_data.encode("utf-8")
            if isinstance(associated_data, str)
            else bytes(associated_data)
        )

        if action == "generate_key":
            handle = self.generate_keyset(
                (key_config or {}).get("template", DEFAULT_TEMPLATE)
            )
            return (
                {"keyset": self.serialize_keyset(handle)},
                {"keyset_info": self.keyset_info(handle)},
            )

        if action == "rotate_key":
            handle = self._resolve_keyset(key_config)
            rotated = self.rotate_keyset(
                handle, (key_config or {}).get("template", DEFAULT_TEMPLATE)
            )
            return (
                {"keyset": self.serialize_keyset(rotated)},
                {"keyset_info": self.keyset_info(rotated)},
            )

        if action == "key_info":
            handle = self._resolve_keyset(key_config)
            return ({}, {"keyset_info": self.keyset_info(handle)})

        if action == "encrypt":
            if "plaintext" not in input_data:
                raise StandardCryptographyError(
                    "input_data must contain 'plaintext'",
                    algorithm="aead",
                    operation="encrypt",
                )
            handle = self._resolve_keyset(key_config)
            ciphertext = self.encrypt_bytes(
                str(input_data["plaintext"]).encode("utf-8"),
                handle,
                associated,
            )
            return (
                {"ciphertext": base64.b64encode(ciphertext).decode("ascii")},
                {"keyset_info": self.keyset_info(handle)},
            )

        if action == "decrypt":
            if "ciphertext" not in input_data:
                raise StandardCryptographyError(
                    "input_data must contain 'ciphertext'",
                    algorithm="aead",
                    operation="decrypt",
                )
            handle = self._resolve_keyset(key_config)
            try:
                raw = base64.b64decode(
                    str(input_data["ciphertext"]), validate=True
                )
            except Exception as exc:
                raise StandardCryptographyError(
                    f"ciphertext is not valid base64: {exc}",
                    algorithm="aead",
                    operation="decrypt",
                )
            plaintext = self.decrypt_bytes(raw, handle, associated)
            return (
                {"plaintext": plaintext.decode("utf-8", errors="replace")},
                {"keyset_info": self.keyset_info(handle)},
            )

        raise StandardCryptographyError(
            f"Unsupported encryption action: {action}",
            algorithm="aead",
            operation=action,
        )
