"""Tests for vf501.crypto."""

import pytest
from cryptography.exceptions import InvalidTag

from vf501.crypto import (
    _MAGIC,
    _VERSION,
    decrypt_bytes,
    decrypt_file,
    encrypt_bytes,
    encrypt_file,
)


PASSPHRASE = "TestP@ssw0rd!"
PLAINTEXT = b"Sensitive donor record: John Doe, $5000"


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip():
    blob = encrypt_bytes(PLAINTEXT, PASSPHRASE)
    recovered = decrypt_bytes(blob, PASSPHRASE)
    assert recovered == PLAINTEXT


def test_encrypt_different_nonces_each_call():
    blob1 = encrypt_bytes(PLAINTEXT, PASSPHRASE)
    blob2 = encrypt_bytes(PLAINTEXT, PASSPHRASE)
    # Due to random salt+nonce, ciphertexts should differ
    assert blob1 != blob2


def test_encrypt_empty_plaintext():
    blob = encrypt_bytes(b"", PASSPHRASE)
    assert decrypt_bytes(blob, PASSPHRASE) == b""


def test_encrypt_bytes_passphrase():
    blob = encrypt_bytes(PLAINTEXT, PASSPHRASE.encode())
    assert decrypt_bytes(blob, PASSPHRASE) == PLAINTEXT


# ---------------------------------------------------------------------------
# Magic / header
# ---------------------------------------------------------------------------

def test_encrypted_blob_starts_with_magic():
    blob = encrypt_bytes(PLAINTEXT, PASSPHRASE)
    assert blob[:4] == _MAGIC


def test_decrypt_wrong_magic_raises():
    blob = bytearray(encrypt_bytes(PLAINTEXT, PASSPHRASE))
    blob[:4] = b"XXXX"
    with pytest.raises(ValueError, match="Invalid magic"):
        decrypt_bytes(bytes(blob), PASSPHRASE)


def test_decrypt_wrong_version_raises():
    blob = bytearray(encrypt_bytes(PLAINTEXT, PASSPHRASE))
    blob[4] = _VERSION + 1
    with pytest.raises(ValueError, match="Unsupported encryption version"):
        decrypt_bytes(bytes(blob), PASSPHRASE)


def test_decrypt_short_blob_raises():
    with pytest.raises(ValueError, match="too short"):
        decrypt_bytes(b"VF5\x01", PASSPHRASE)


# ---------------------------------------------------------------------------
# Wrong passphrase
# ---------------------------------------------------------------------------

def test_decrypt_wrong_passphrase_raises():
    blob = encrypt_bytes(PLAINTEXT, PASSPHRASE)
    with pytest.raises(Exception):  # InvalidTag from cryptography
        decrypt_bytes(blob, "wrong_passphrase")


# ---------------------------------------------------------------------------
# Tampered ciphertext
# ---------------------------------------------------------------------------

def test_tampered_ciphertext_raises():
    blob = bytearray(encrypt_bytes(PLAINTEXT, PASSPHRASE))
    blob[-1] ^= 0xFF  # flip a bit in the GCM tag
    with pytest.raises(Exception):
        decrypt_bytes(bytes(blob), PASSPHRASE)


# ---------------------------------------------------------------------------
# File encryption
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_file_roundtrip(tmp_path):
    src = tmp_path / "plain.txt"
    enc = tmp_path / "plain.txt.enc"
    dec = tmp_path / "plain_dec.txt"
    src.write_bytes(PLAINTEXT)
    encrypt_file(src, enc, PASSPHRASE)
    assert enc.exists()
    assert enc.read_bytes() != PLAINTEXT
    decrypt_file(enc, dec, PASSPHRASE)
    assert dec.read_bytes() == PLAINTEXT
