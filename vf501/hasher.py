"""File hashing utilities for VF501.

Provides SHA-256 (primary), SHA-512, and MD5 hashing for files and raw data,
used for integrity verification throughout the archiver and forensic workflow.
"""

import hashlib
from pathlib import Path
from typing import Union


BUFFER_SIZE = 65536  # 64 KiB


def _hash_stream(stream, algorithms: list[str]) -> dict[str, str]:
    """Hash a file-like stream with one or more algorithms simultaneously."""
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    while chunk := stream.read(BUFFER_SIZE):
        for h in hashers.values():
            h.update(chunk)
    return {alg: h.hexdigest() for alg, h in hashers.items()}


def hash_file(path: Union[str, Path], algorithms: list[str] | None = None) -> dict[str, str]:
    """Return hex digests for *path* using the requested *algorithms*.

    Defaults to SHA-256 and MD5.

    Args:
        path: Path to the file to hash.
        algorithms: List of algorithm names (e.g. ``["sha256", "md5"]``).

    Returns:
        Mapping from algorithm name to hex digest string.
    """
    if algorithms is None:
        algorithms = ["sha256", "md5"]
    with open(path, "rb") as fh:
        return _hash_stream(fh, algorithms)


def hash_bytes(data: bytes, algorithms: list[str] | None = None) -> dict[str, str]:
    """Return hex digests for raw *data*.

    Args:
        data: Bytes to hash.
        algorithms: List of algorithm names.

    Returns:
        Mapping from algorithm name to hex digest string.
    """
    if algorithms is None:
        algorithms = ["sha256", "md5"]
    hashers = {alg: hashlib.new(alg) for alg in algorithms}
    for h in hashers.values():
        h.update(data)
    return {alg: h.hexdigest() for alg, h in hashers.items()}


def sha256_file(path: Union[str, Path]) -> str:
    """Convenience wrapper – return the SHA-256 hex digest of *path*."""
    return hash_file(path, ["sha256"])["sha256"]


def sha512_file(path: Union[str, Path]) -> str:
    """Convenience wrapper – return the SHA-512 hex digest of *path*."""
    return hash_file(path, ["sha512"])["sha512"]


def verify_file(path: Union[str, Path], expected: dict[str, str]) -> bool:
    """Verify that *path* matches every digest in *expected*.

    Args:
        path: File to verify.
        expected: Mapping of algorithm → expected hex digest.

    Returns:
        ``True`` if all digests match, ``False`` otherwise.
    """
    algorithms = list(expected.keys())
    actual = hash_file(path, algorithms)
    return all(actual.get(alg) == digest for alg, digest in expected.items())
