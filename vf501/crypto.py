"""AES-256-GCM encryption and decryption for VF501.

Keys are derived from a passphrase using PBKDF2-HMAC-SHA256 with a random 16-byte
salt and 600 000 iterations (NIST SP 800-132 compliant).

Ciphertext layout (all written as a single blob):
    [4 bytes magic] [1 byte version] [16 bytes salt] [12 bytes nonce]
    [N bytes GCM ciphertext+tag]

The 16-byte GCM authentication tag is appended by the ``cryptography`` library
as part of the ciphertext returned by ``finalize_with_tag()``.
"""

import os
import struct
from pathlib import Path
from typing import Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

_MAGIC = b"VF5\x01"
_VERSION = 1
_KEY_LEN = 32       # 256-bit AES key
_SALT_LEN = 16
_NONCE_LEN = 12
_ITERATIONS = 600_000
_HEADER_LEN = len(_MAGIC) + 1 + _SALT_LEN + _NONCE_LEN  # 33 bytes


def _derive_key(passphrase: Union[str, bytes], salt: bytes) -> bytes:
    """Derive a 256-bit key from *passphrase* and *salt* via PBKDF2-HMAC-SHA256."""
    if isinstance(passphrase, str):
        passphrase = passphrase.encode()
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=_KEY_LEN,
        salt=salt,
        iterations=_ITERATIONS,
    )
    return kdf.derive(passphrase)


def encrypt_bytes(plaintext: bytes, passphrase: Union[str, bytes]) -> bytes:
    """Encrypt *plaintext* with AES-256-GCM using a PBKDF2-derived key.

    Args:
        plaintext: Raw bytes to encrypt.
        passphrase: User-supplied passphrase (str or bytes).

    Returns:
        Encrypted blob (magic + header + ciphertext).
    """
    salt = os.urandom(_SALT_LEN)
    nonce = os.urandom(_NONCE_LEN)
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    header = _MAGIC + struct.pack("B", _VERSION) + salt + nonce
    return header + ciphertext


def decrypt_bytes(blob: bytes, passphrase: Union[str, bytes]) -> bytes:
    """Decrypt a blob produced by :func:`encrypt_bytes`.

    Args:
        blob: Encrypted bytes (magic + header + ciphertext).
        passphrase: User-supplied passphrase (str or bytes).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        ValueError: If the magic/version header is invalid.
        cryptography.exceptions.InvalidTag: If authentication fails (wrong
            passphrase or tampered data).
    """
    if len(blob) < _HEADER_LEN:
        raise ValueError("Blob too short to be a valid VF501 encrypted payload")
    magic = blob[:4]
    if magic != _MAGIC:
        raise ValueError(f"Invalid magic bytes: {magic!r}")
    version = struct.unpack("B", blob[4:5])[0]
    if version != _VERSION:
        raise ValueError(f"Unsupported encryption version: {version}")
    salt = blob[5: 5 + _SALT_LEN]
    nonce = blob[5 + _SALT_LEN: 5 + _SALT_LEN + _NONCE_LEN]
    ciphertext = blob[_HEADER_LEN:]
    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


def encrypt_file(src: Union[str, Path], dst: Union[str, Path], passphrase: Union[str, bytes]) -> None:
    """Encrypt file at *src* and write ciphertext to *dst*.

    Args:
        src: Source plaintext file.
        dst: Destination ciphertext file.
        passphrase: Encryption passphrase.
    """
    plaintext = Path(src).read_bytes()
    blob = encrypt_bytes(plaintext, passphrase)
    Path(dst).write_bytes(blob)


def decrypt_file(src: Union[str, Path], dst: Union[str, Path], passphrase: Union[str, bytes]) -> None:
    """Decrypt a VF501-encrypted file at *src* and write plaintext to *dst*.

    Args:
        src: Source ciphertext file.
        dst: Destination plaintext file.
        passphrase: Decryption passphrase.
    """
    blob = Path(src).read_bytes()
    plaintext = decrypt_bytes(blob, passphrase)
    Path(dst).write_bytes(plaintext)
