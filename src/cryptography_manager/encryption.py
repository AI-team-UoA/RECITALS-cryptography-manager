"""
Cryptography Manager's Encryption/Decryption submodule.
"""

import tink


class Encryption:
    def encrypt(self, data: str, keyset: tink.KeysetHandle):
        """
        Encrypt stored data.

        Args:
            data (str): Path to the stored data.
            keyset (tink.KeysetHandle): Handle to the keyset object containing the key.
        """
        ...

    def decrypt(self, enc_data: str, keyset: tink.KeysetHandle):
        """
        Decrypt stored encrypted data.

        Args:
            enc_data (str): Path to the encrypted data.
            keyset (tink.KeysetHandle): Handle to the keyset object containing the key.
        """
        ...

    def gen_key():
        """
        Generates a key for AEAD primitive, using AES256_GCM_SIV implementation.

        > *AES128_GCM_SIV is nearly as fast as AES128_GCM. It has the same limits as
        > AES128_GCM on the number of messages and message size, but when these
        > limits are exceeded, it fails in a less catastrophic way: it may only leak
        > the fact that two messages are equal. This makes it safer to use than
        > AES128_GCM, but it is less widely used in practice.*
        """
        ...
