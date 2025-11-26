"""
Cryptography Manager's Encryption/Decryption submodule.
"""

import os

import tink
from tink import aead

aead.register()  # Register AEAD primitive


class Encryption:
    @staticmethod
    def _get_aead_primitive(keyset_handle: tink.KeysetHandle) -> aead.Aead:
        """Gets an AEAD primitive from a KeysetHandle.

        Args:
            keyset_handle (tink.KeysetHandle): The handle to the keyset.

        Returns:
            tink.aead.Aead: The AEAD primitive.
        """
        return keyset_handle.primitive(aead.Aead)

    def encrypt(self, data: str, keyset_handle: tink.KeysetHandle):
        """Encrypts stored data, binding to the file's basename as associated data.

        Writes ciphertext to `data + '.enc'`.

        Args:
            data (str): Path to the stored data to encrypt.
            keyset_handle (tink.KeysetHandle): Handle to the keyset object containing the key.
        """
        aead = self._get_aead_primitive(keyset_handle)
        associated_data = os.path.basename(data).encode("utf-8")
        with open(data, "rb") as f_in:
            plaintext = f_in.read()
        ciphertext = aead.encrypt(plaintext, associated_data)
        with open(data + ".enc", "wb") as f_out:
            f_out.write(ciphertext)

    def decrypt(self, enc_data: str, keyset_handle: tink.KeysetHandle):
        """Decrypts stored encrypted data, using the original file's basename as associated data.

        Writes plaintext to `enc_data + '.dec'`.

        Args:
            enc_data (str): Path to the encrypted data file.
            keyset_handle (tink.KeysetHandle): Handle to the keyset object containing the key.
        """
        # Remove '.enc' extension to get original data filename for associated data
        if not enc_data.endswith(".enc"):
            raise ValueError("Encrypted file should have .enc extension")
        basename = os.path.basename(enc_data[:-4])  # Remove '.enc'
        associated_data = basename.encode("utf-8")
        aead = self._get_aead_primitive(keyset_handle)
        with open(enc_data, "rb") as f_in:
            ciphertext = f_in.read()
        plaintext = aead.decrypt(ciphertext, associated_data)
        with open(enc_data + ".dec", "wb") as f_out:
            f_out.write(plaintext)

    @staticmethod
    def gen_key() -> tink.KeysetHandle:
        """Generates a key for the AEAD primitive using AES256_GCM_SIV.

        Returns:
            tink.KeysetHandle: The generated keyset handle.
        """
        return tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM_SIV)

    @staticmethod
    def save_keyset(keyset_handle: tink.KeysetHandle, path: str):
        """Saves a keyset to a file in plaintext JSON format.

        Args:
            keyset_handle (tink.KeysetHandle): The keyset handle to save.
            path (str): Path where the keyset will be saved.
        """
        with open(path, "w") as f:
            tink.JsonKeysetWriter(f).write(keyset_handle._keyset)

    @staticmethod
    def load_keyset(path: str) -> tink.KeysetHandle:
        """Loads a keyset from a plaintext JSON file.

        Args:
            path (str): Path to the keyset file.

        Returns:
            tink.KeysetHandle: The loaded keyset handle.
        """
        with open(path, "r") as f:
            json_content = f.read()
        keyset_data = tink.JsonKeysetReader(json_content).read()
        return tink.KeysetHandle._create(keyset_data)


# Example usage
if __name__ == "__main__":
    import sys

    # Check if a path to secret.txt is provided
    if len(sys.argv) > 1:
        secret_file = sys.argv[1]
    else:
        secret_file = input("Enter path of file to encrypt: ")

    # Generate and save a new keyset (on first use)
    keyset_handle = Encryption.gen_key()
    Encryption.save_keyset(keyset_handle, "mykey.json")

    # Load the keyset for later use
    keyset_handle = Encryption.load_keyset("mykey.json")

    enc = Encryption()
    enc.encrypt(secret_file, keyset_handle)  # ciphertext binds to secret file
    enc.decrypt(
        f"{secret_file}.enc", keyset_handle
    )  # decryption requires `secret_file` basename as context

    print(f"Encryption complete: {secret_file}.enc")
    print(f"Decryption complete: {secret_file}.enc.dec")
