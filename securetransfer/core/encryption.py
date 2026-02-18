"""Encryption module using AES-256-GCM and X25519.

CRITICAL: Compress BEFORE encrypting. Call compression first, then pass
the compressed data to encryption. Never reuse a nonce; always authenticate
before using decrypted data (GCM tag verification is automatic).
"""

from __future__ import annotations

import os
import struct
import time
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from loguru import logger


# --- Exception classes -------------------------------------------------------


class EncryptionError(Exception):
    """Raised when an encryption operation fails."""

    pass


class DecryptionError(Exception):
    """Raised when decryption fails (e.g. authentication tag verification)."""

    pass


class KeyManagerError(Exception):
    """Raised when key loading, saving, or derivation fails (e.g. wrong password)."""

    pass


# --- KeyManager ---------------------------------------------------------------


class KeyManager:
    """X25519 key generation, ECDH shared secret, and symmetric key derivation."""

    def __init__(self) -> None:
        """Initialize the key manager."""
        pass

    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate a new X25519 key pair.

        Returns:
            Tuple of (private_key_bytes, public_key_bytes), each 32 bytes.
        """
        start = time.perf_counter()
        private_key = X25519PrivateKey.generate()
        private_key_bytes = private_key.private_bytes_raw()
        public_key_bytes = private_key.public_key().public_bytes_raw()
        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.debug(
            "generate_keypair: 32-byte private, 32-byte public in {:.2f} ms",
            elapsed_ms,
        )
        return (private_key_bytes, public_key_bytes)

    def derive_shared_secret(
        self,
        private_key_bytes: bytes,
        peer_public_key_bytes: bytes,
    ) -> bytes:
        """Compute X25519 ECDH shared secret.

        Args:
            private_key_bytes: Our 32-byte private key.
            peer_public_key_bytes: Peer's 32-byte public key.

        Returns:
            32-byte shared secret (must be passed to KDF before use).

        Raises:
            KeyManagerError: If key bytes are invalid.
        """
        try:
            start = time.perf_counter()
            private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
            peer_public_key = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
            shared = private_key.exchange(peer_public_key)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug("derive_shared_secret in {:.2f} ms", elapsed_ms)
            return shared
        except Exception as e:
            logger.exception("derive_shared_secret failed")
            raise KeyManagerError("Shared secret derivation failed") from e

    def derive_symmetric_key(self, shared_secret: bytes, salt: bytes) -> bytes:
        """Derive a 32-byte AES key from shared secret using HKDF-SHA256.

        Args:
            shared_secret: Raw ECDH shared secret.
            salt: Salt for HKDF (e.g. from generate_salt()).

        Returns:
            32-byte key suitable for AES-256.
        """
        start = time.perf_counter()
        key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"securetransfer-aes256",
        ).derive(shared_secret)
        elapsed_ms = (time.perf_counter() - start) * 1000
        logger.debug("derive_symmetric_key in {:.2f} ms", elapsed_ms)
        return key

    def save_keypair(
        self,
        private_key_bytes: bytes,
        filepath: str,
        password: str,
    ) -> None:
        """Serialize and encrypt the private key to a PEM file.

        The public key can be derived from the private key when loading.

        Args:
            private_key_bytes: 32-byte X25519 private key.
            filepath: Path to write the PEM file.
            password: Password to encrypt the private key.

        Raises:
            KeyManagerError: On serialization or I/O failure.
        """
        try:
            start = time.perf_counter()
            private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.BestAvailableEncryption(
                    password.encode("utf-8")
                ),
            )
            Path(filepath).write_bytes(pem)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info("save_keypair: {} in {:.2f} ms", filepath, elapsed_ms)
        except Exception as e:
            logger.exception("save_keypair failed")
            raise KeyManagerError(f"Failed to save keypair: {e}") from e

    def load_keypair(self, filepath: str, password: str) -> tuple[bytes, bytes]:
        """Load private (and derive public) key from password-protected PEM file.

        Args:
            filepath: Path to the PEM file.
            password: Password used when saving.

        Returns:
            Tuple of (private_key_bytes, public_key_bytes), each 32 bytes.

        Raises:
            KeyManagerError: If file not found, wrong password, or invalid key.
        """
        try:
            start = time.perf_counter()
            path = Path(filepath)
            if not path.exists():
                raise KeyManagerError(f"Key file not found: {filepath}")
            pem = path.read_bytes()
            private_key = serialization.load_pem_private_key(
                pem,
                password=password.encode("utf-8"),
            )
            if not isinstance(private_key, X25519PrivateKey):
                raise KeyManagerError("Key file is not an X25519 private key")
            private_key_bytes = private_key.private_bytes_raw()
            public_key_bytes = private_key.public_key().public_bytes_raw()
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info("load_keypair: {} in {:.2f} ms", filepath, elapsed_ms)
            return (private_key_bytes, public_key_bytes)
        except KeyManagerError:
            raise
        except Exception as e:
            logger.exception("load_keypair failed")
            raise KeyManagerError(f"Failed to load keypair (wrong password?): {e}") from e

    def generate_salt(self) -> bytes:
        """Generate a 16-byte cryptographically secure random salt.

        Returns:
            16-byte salt for use with derive_symmetric_key.
        """
        return os.urandom(16)


# --- AESCipher ---------------------------------------------------------------
# CRITICAL: Never reuse a nonce. We generate fresh os.urandom(12) for every
# encrypt() call. GCM tag verification is automatic on decrypt(); always
# authenticate before using decrypted data.


NONCE_SIZE = 12
TAG_SIZE = 16


class AESCipher:
    """AES-256-GCM authenticated encryption for bytes and files."""

    def __init__(self, key: bytes) -> None:
        """Initialize with a 32-byte AES-256 key.

        Args:
            key: Exactly 32-byte key.

        Raises:
            ValueError: If key length is not 32.
        """
        if len(key) != 32:
            raise ValueError("AES-256 key must be 32 bytes")
        self._key = key
        self._aesgcm = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        """Encrypt with AES-256-GCM. Never reuses a nonce.

        Output format: nonce (12 bytes) + tag (16 bytes) + ciphertext.

        Args:
            plaintext: Data to encrypt.

        Returns:
            nonce || tag || ciphertext (all concatenated).

        Raises:
            EncryptionError: On encryption failure.
        """
        # CRITICAL: Never reuse a nonce. Generate fresh os.urandom(12) for every encrypt.
        nonce = os.urandom(NONCE_SIZE)
        try:
            start = time.perf_counter()
            # encrypt() returns ciphertext with 16-byte tag appended
            ct_and_tag = self._aesgcm.encrypt(nonce, plaintext, None)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug(
                "encrypt: {} bytes -> {} bytes in {:.2f} ms",
                len(plaintext),
                NONCE_SIZE + TAG_SIZE + len(plaintext),
                elapsed_ms,
            )
            return nonce + ct_and_tag
        except Exception as e:
            logger.exception("encrypt failed")
            raise EncryptionError("Encryption failed") from e

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt and verify GCM tag. Always authenticate before using data.

        Expects format: nonce (12) + tag (16) + ciphertext.

        Args:
            ciphertext: nonce || tag || ciphertext from encrypt().

        Returns:
            Plaintext bytes.

        Raises:
            DecryptionError: If tag verification fails (tampered/wrong key).
            EncryptionError: If ciphertext is too short.
        """
        if len(ciphertext) < NONCE_SIZE + TAG_SIZE:
            raise DecryptionError("Ciphertext too short (missing nonce or tag)")
        nonce = ciphertext[:NONCE_SIZE]
        ct_and_tag = ciphertext[NONCE_SIZE:]
        try:
            start = time.perf_counter()
            # GCM tag verification is automatic; InvalidTag on failure
            plaintext = self._aesgcm.decrypt(nonce, ct_and_tag, None)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.debug(
                "decrypt: {} bytes -> {} bytes in {:.2f} ms",
                len(ciphertext),
                len(plaintext),
                elapsed_ms,
            )
            return plaintext
        except InvalidTag as e:
            logger.warning("decrypt: authentication tag verification failed")
            raise DecryptionError("Authentication failed (tampered or wrong key)") from e
        except Exception as e:
            logger.exception("decrypt failed")
            raise DecryptionError("Decryption failed") from e

    def encrypt_file(
        self,
        input_path: str,
        output_path: str,
        chunk_size: int = 65536,
    ) -> None:
        """Encrypt a file in chunks; each chunk uses a unique nonce.

        Protocol: compress before encrypting. Ensure input is compressed
        to avoid encrypting uncompressed data.

        Args:
            input_path: Source file path.
            output_path: Destination file path.
            chunk_size: Plaintext chunk size in bytes (default 64 KiB).

        Raises:
            EncryptionError: On I/O or encryption failure.
        """
        # Protocol order: compress then encrypt. Warn if caller may have skipped compression.
        logger.warning(
            "encrypt_file: protocol requires compress-before-encrypt; "
            "ensure input is already compressed"
        )
        inp = Path(input_path)
        if not inp.exists():
            raise EncryptionError(f"File not found: {input_path}")
        start = time.perf_counter()
        try:
            with open(inp, "rb") as f_in:
                with open(output_path, "wb") as f_out:
                    while True:
                        chunk = f_in.read(chunk_size)
                        if not chunk:
                            break
                        # Fresh nonce per chunk (never reuse)
                        encrypted = self.encrypt(chunk)
                        # Store length of this blob (4 bytes big-endian) then blob
                        f_out.write(struct.pack(">I", len(encrypted)))
                        f_out.write(encrypted)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "encrypt_file: {} -> {} in {:.2f} ms",
                input_path,
                output_path,
                elapsed_ms,
            )
        except EncryptionError:
            raise
        except Exception as e:
            logger.exception("encrypt_file failed")
            raise EncryptionError(f"File encryption failed: {e}") from e

    def decrypt_file(
        self,
        input_path: str,
        output_path: str,
        chunk_size: int = 65536,
    ) -> None:
        """Decrypt a file encrypted with encrypt_file.

        Chunk boundaries are read from the stored length prefix; chunk_size
        is only used as a read buffer hint for the encrypted blobs.

        Args:
            input_path: Encrypted file path.
            output_path: Destination plaintext file path.
            chunk_size: Unused for parsing; kept for API symmetry.

        Raises:
            DecryptionError: On tag failure or corrupt data.
            EncryptionError: On I/O failure.
        """
        _ = chunk_size  # kept for API symmetry
        inp = Path(input_path)
        if not inp.exists():
            raise EncryptionError(f"File not found: {input_path}")
        start = time.perf_counter()
        try:
            with open(inp, "rb") as f_in:
                with open(output_path, "wb") as f_out:
                    while True:
                        len_buf = f_in.read(4)
                        if not len_buf:
                            break
                        if len(len_buf) != 4:
                            raise DecryptionError("Truncated length prefix")
                        blob_len = struct.unpack(">I", len_buf)[0]
                        if blob_len > 10 * 1024 * 1024:  # 10 MB sanity limit
                            raise DecryptionError("Chunk length unreasonable")
                        blob = f_in.read(blob_len)
                        if len(blob) != blob_len:
                            raise DecryptionError("Truncated chunk")
                        plaintext = self.decrypt(blob)
                        f_out.write(plaintext)
            elapsed_ms = (time.perf_counter() - start) * 1000
            logger.info(
                "decrypt_file: {} -> {} in {:.2f} ms",
                input_path,
                output_path,
                elapsed_ms,
            )
        except DecryptionError:
            raise
        except Exception as e:
            logger.exception("decrypt_file failed")
            raise DecryptionError(f"File decryption failed: {e}") from e
