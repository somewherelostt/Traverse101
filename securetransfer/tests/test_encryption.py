"""Tests for encryption module."""

import os
import tempfile
from pathlib import Path

import pytest

from securetransfer.core.encryption import (
    AESCipher,
    DecryptionError,
    EncryptionError,
    KeyManager,
    KeyManagerError,
    NONCE_SIZE,
    TAG_SIZE,
)


def test_encrypt_decrypt_roundtrip() -> None:
    """Encrypting then decrypting returns original plaintext."""
    key = os.urandom(32)
    cipher = AESCipher(key)
    plaintext = b"secret message and more data"
    encrypted = cipher.encrypt(plaintext)
    assert isinstance(encrypted, bytes)
    assert len(encrypted) == NONCE_SIZE + TAG_SIZE + len(plaintext)
    decrypted = cipher.decrypt(encrypted)
    assert decrypted == plaintext


def test_wrong_key_raises_error() -> None:
    """Decrypting with a different key raises DecryptionError."""
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    cipher1 = AESCipher(key1)
    cipher2 = AESCipher(key2)
    encrypted = cipher1.encrypt(b"secret")
    with pytest.raises(DecryptionError, match="Authentication failed|wrong key"):
        cipher2.decrypt(encrypted)


def test_tampered_ciphertext_raises_error() -> None:
    """Tampering with ciphertext raises DecryptionError (tag verification fails)."""
    key = os.urandom(32)
    cipher = AESCipher(key)
    encrypted = bytearray(cipher.encrypt(b"secret"))
    # Flip a byte in the ciphertext (after nonce+tag we have payload; or flip tag)
    encrypted[NONCE_SIZE + 10] ^= 0x01
    with pytest.raises(DecryptionError, match="Authentication failed|tampered"):
        cipher.decrypt(bytes(encrypted))


def test_nonce_uniqueness() -> None:
    """Encrypting the same data many times yields different nonces every time."""
    key = os.urandom(32)
    cipher = AESCipher(key)
    data = b"same plaintext"
    nonces = set()
    for _ in range(1000):
        encrypted = cipher.encrypt(data)
        nonce = encrypted[:NONCE_SIZE]
        nonces.add(nonce)
    assert len(nonces) == 1000, "Every encryption must use a unique nonce"


def test_key_exchange_shared_secret_match() -> None:
    """Alice and Bob derive the same shared secret from X25519 key exchange."""
    km = KeyManager()
    # Alice
    alice_private, alice_public = km.generate_keypair()
    # Bob
    bob_private, bob_public = km.generate_keypair()
    # Each derives shared secret from their private key and peer's public key
    alice_shared = km.derive_shared_secret(alice_private, bob_public)
    bob_shared = km.derive_shared_secret(bob_private, alice_public)
    assert alice_shared == bob_shared
    assert len(alice_shared) == 32


def test_aes_cipher_requires_32_byte_key() -> None:
    """AESCipher rejects key that is not 32 bytes."""
    with pytest.raises(ValueError, match="32 bytes"):
        AESCipher(b"short")
    with pytest.raises(ValueError, match="32 bytes"):
        AESCipher(os.urandom(16))


def test_derive_symmetric_key_and_encrypt() -> None:
    """Derived symmetric key can be used with AESCipher."""
    km = KeyManager()
    priv_a, pub_a = km.generate_keypair()
    priv_b, pub_b = km.generate_keypair()
    shared = km.derive_shared_secret(priv_a, pub_b)
    salt = km.generate_salt()
    assert len(salt) == 16
    key = km.derive_symmetric_key(shared, salt)
    assert len(key) == 32
    cipher = AESCipher(key)
    ct = cipher.encrypt(b"message")
    pt = cipher.decrypt(ct)
    assert pt == b"message"


def test_save_and_load_keypair() -> None:
    """Save keypair to file with password, load returns same key bytes."""
    km = KeyManager()
    private_bytes, public_bytes = km.generate_keypair()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        path = f.name
    try:
        km.save_keypair(private_bytes, path, "secret_password")
        loaded_private, loaded_public = km.load_keypair(path, "secret_password")
        assert loaded_private == private_bytes
        assert loaded_public == public_bytes
    finally:
        Path(path).unlink(missing_ok=True)


def test_load_keypair_wrong_password_raises() -> None:
    """Loading keypair with wrong password raises KeyManagerError."""
    km = KeyManager()
    private_bytes, _ = km.generate_keypair()
    with tempfile.NamedTemporaryFile(suffix=".pem", delete=False) as f:
        path = f.name
    try:
        km.save_keypair(private_bytes, path, "correct")
        with pytest.raises(KeyManagerError, match="password|Failed to load"):
            km.load_keypair(path, "wrong")
    finally:
        Path(path).unlink(missing_ok=True)


def test_encrypt_decrypt_file_roundtrip() -> None:
    """encrypt_file then decrypt_file reproduces original file."""
    key = os.urandom(32)
    cipher = AESCipher(key)
    content = b"file content " * 1000
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "plain.bin"
        src.write_bytes(content)
        enc_path = Path(tmp) / "enc.bin"
        dec_path = Path(tmp) / "dec.bin"
        cipher.encrypt_file(str(src), str(enc_path), chunk_size=256)
        assert enc_path.exists()
        cipher.decrypt_file(str(enc_path), str(dec_path), chunk_size=256)
        assert dec_path.read_bytes() == content
