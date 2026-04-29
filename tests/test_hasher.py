"""Tests for vf501.hasher."""

import hashlib
from pathlib import Path

import pytest

from vf501.hasher import hash_file, hash_bytes, sha256_file, sha512_file, verify_file


# ---------------------------------------------------------------------------
# hash_bytes
# ---------------------------------------------------------------------------

def test_hash_bytes_sha256():
    data = b"hello world"
    result = hash_bytes(data, ["sha256"])
    expected = hashlib.sha256(data).hexdigest()
    assert result["sha256"] == expected


def test_hash_bytes_md5():
    data = b"donor data"
    result = hash_bytes(data, ["md5"])
    expected = hashlib.md5(data).hexdigest()
    assert result["md5"] == expected


def test_hash_bytes_multiple_algorithms():
    data = b"forensic evidence"
    result = hash_bytes(data, ["sha256", "sha512", "md5"])
    assert result["sha256"] == hashlib.sha256(data).hexdigest()
    assert result["sha512"] == hashlib.sha512(data).hexdigest()
    assert result["md5"] == hashlib.md5(data).hexdigest()


def test_hash_bytes_default_algorithms():
    data = b"default test"
    result = hash_bytes(data)
    assert "sha256" in result
    assert "md5" in result


def test_hash_bytes_empty():
    result = hash_bytes(b"", ["sha256"])
    assert result["sha256"] == hashlib.sha256(b"").hexdigest()


# ---------------------------------------------------------------------------
# hash_file
# ---------------------------------------------------------------------------

def test_hash_file(tmp_path):
    f = tmp_path / "test.txt"
    f.write_bytes(b"charity donor info")
    result = hash_file(f, ["sha256", "md5"])
    assert result["sha256"] == hashlib.sha256(b"charity donor info").hexdigest()
    assert result["md5"] == hashlib.md5(b"charity donor info").hexdigest()


def test_hash_file_large(tmp_path):
    f = tmp_path / "large.bin"
    data = b"x" * (200 * 1024)  # 200 KiB — crosses BUFFER_SIZE boundary
    f.write_bytes(data)
    result = hash_file(f, ["sha256"])
    assert result["sha256"] == hashlib.sha256(data).hexdigest()


def test_sha256_file(tmp_path):
    f = tmp_path / "s.txt"
    f.write_bytes(b"abc")
    assert sha256_file(f) == hashlib.sha256(b"abc").hexdigest()


def test_sha512_file(tmp_path):
    f = tmp_path / "s.txt"
    f.write_bytes(b"abc")
    assert sha512_file(f) == hashlib.sha512(b"abc").hexdigest()


# ---------------------------------------------------------------------------
# verify_file
# ---------------------------------------------------------------------------

def test_verify_file_pass(tmp_path):
    f = tmp_path / "v.txt"
    f.write_bytes(b"verifiable")
    digests = hash_file(f, ["sha256", "md5"])
    assert verify_file(f, digests) is True


def test_verify_file_wrong_digest(tmp_path):
    f = tmp_path / "v.txt"
    f.write_bytes(b"verifiable")
    assert verify_file(f, {"sha256": "deadbeef" * 8}) is False


def test_verify_file_partial_match(tmp_path):
    f = tmp_path / "v.txt"
    f.write_bytes(b"verifiable")
    correct_sha256 = hashlib.sha256(b"verifiable").hexdigest()
    # sha256 correct but md5 wrong
    assert verify_file(f, {"sha256": correct_sha256, "md5": "badmd5"}) is False
