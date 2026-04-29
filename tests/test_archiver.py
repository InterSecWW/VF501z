"""Tests for vf501.archiver – create, list, extract, verify, decrypt."""

import zipfile
from pathlib import Path

import pytest

from vf501.archiver import (
    IntegrityError,
    create_archive,
    decrypt_archive,
    extract_archive,
    list_archive,
    verify_archive,
)
from vf501.audit import default_log_path
from vf501.forensics import default_coc_path
from vf501.manifest import MANIFEST_FILENAME


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def sample_files(tmp_path):
    """Create a small directory tree to archive."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "report.txt").write_bytes(b"Donor: Jane Doe, Amount: $1000")
    (tmp_path / "src" / "photo.jpg").write_bytes(b"\xff\xd8\xff evidence image data")
    sub = tmp_path / "src" / "sub"
    sub.mkdir()
    (sub / "notes.txt").write_bytes(b"Case notes: forensic examination on 2025-01-01")
    return tmp_path / "src"


@pytest.fixture()
def archive_path(tmp_path, sample_files):
    """Create a .vfa archive from sample_files, return archive path."""
    out = tmp_path / "test.vfa"
    create_archive(out, [sample_files], label="Test Case", actor="testuser")
    return out


# ---------------------------------------------------------------------------
# create_archive
# ---------------------------------------------------------------------------

def test_create_produces_vfa_file(tmp_path, sample_files):
    out = tmp_path / "case.vfa"
    create_archive(out, [sample_files], label="Case 1", actor="u")
    assert out.exists()
    assert out.stat().st_size > 0


def test_create_is_valid_zip(archive_path):
    assert zipfile.is_zipfile(archive_path)


def test_create_contains_manifest(archive_path):
    with zipfile.ZipFile(archive_path) as zf:
        assert MANIFEST_FILENAME in zf.namelist()


def test_create_manifest_has_correct_file_count(tmp_path, sample_files):
    out = tmp_path / "c.vfa"
    manifest = create_archive(out, [sample_files], actor="u")
    # 3 files: report.txt, photo.jpg, sub/notes.txt
    assert len(manifest.files) == 3


def test_create_manifest_label(tmp_path, sample_files):
    out = tmp_path / "c.vfa"
    manifest = create_archive(out, [sample_files], label="My Label", actor="u")
    assert manifest.label == "My Label"


def test_create_manifest_hashes_present(tmp_path, sample_files):
    out = tmp_path / "c.vfa"
    manifest = create_archive(out, [sample_files], actor="u")
    for entry in manifest.files:
        assert len(entry.sha256) == 64
        assert len(entry.md5) == 32


def test_create_writes_audit_log(tmp_path, sample_files):
    out = tmp_path / "c.vfa"
    create_archive(out, [sample_files], actor="u")
    log_path = default_log_path(out)
    assert log_path.exists()


def test_create_writes_coc_file(tmp_path, sample_files):
    out = tmp_path / "c.vfa"
    create_archive(out, [sample_files], actor="u")
    coc_path = default_coc_path(out)
    assert coc_path.exists()


def test_create_with_encryption(tmp_path, sample_files):
    out = tmp_path / "enc.vfa"
    create_archive(out, [sample_files], passphrase="secret123", actor="u")
    enc = Path(str(out) + ".enc")
    assert enc.exists()


def test_create_extra_metadata(tmp_path, sample_files):
    out = tmp_path / "c.vfa"
    manifest = create_archive(
        out, [sample_files], actor="u",
        extra={"case_number": "CHR-001", "classification": "RESTRICTED"},
    )
    assert manifest.extra["case_number"] == "CHR-001"


def test_create_with_notes_map(tmp_path):
    f = tmp_path / "evidence.bin"
    f.write_bytes(b"binary evidence")
    out = tmp_path / "c.vfa"
    manifest = create_archive(
        out, [f], actor="u",
        notes_map={str(f.resolve()): "Chain tag #001"},
    )
    assert manifest.files[0].notes == "Chain tag #001"


# ---------------------------------------------------------------------------
# list_archive
# ---------------------------------------------------------------------------

def test_list_archive_returns_manifest(archive_path):
    manifest = list_archive(archive_path)
    assert manifest.label == "Test Case"
    assert len(manifest.files) == 3


def test_list_archive_file_names(archive_path):
    manifest = list_archive(archive_path)
    names = {f.name for f in manifest.files}
    assert any("report.txt" in n for n in names)
    assert any("notes.txt" in n for n in names)


# ---------------------------------------------------------------------------
# extract_archive
# ---------------------------------------------------------------------------

def test_extract_archive_creates_files(tmp_path, archive_path):
    dest = tmp_path / "extracted"
    members = extract_archive(archive_path, dest, actor="u")
    assert len(members) == 3
    assert any((dest / m).exists() for m in members)


def test_extract_archive_verifies_by_default(tmp_path, archive_path):
    dest = tmp_path / "extracted"
    # Should not raise
    extract_archive(archive_path, dest, actor="u")


def test_extract_archive_raises_on_tampered_file(tmp_path, archive_path):
    """Tamper with a file inside the zip and ensure extraction raises."""
    # Rewrite archive with modified content
    import io
    tampered = tmp_path / "tampered.vfa"
    with zipfile.ZipFile(archive_path, "r") as src_zf:
        with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as dst_zf:
            for item in src_zf.infolist():
                data = src_zf.read(item.filename)
                if item.filename != MANIFEST_FILENAME:
                    data = data + b" TAMPERED"
                dst_zf.writestr(item, data)

    dest = tmp_path / "out"
    with pytest.raises(IntegrityError):
        extract_archive(tampered, dest, verify=True, actor="u")


def test_extract_archive_no_verify_succeeds_on_tampered(tmp_path, archive_path):
    """Without verify, extraction succeeds even on tampered archives."""
    import io
    tampered = tmp_path / "tampered.vfa"
    with zipfile.ZipFile(archive_path, "r") as src_zf:
        with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as dst_zf:
            for item in src_zf.infolist():
                data = src_zf.read(item.filename)
                if item.filename != MANIFEST_FILENAME:
                    data = data + b" TAMPERED"
                dst_zf.writestr(item, data)
    dest = tmp_path / "out"
    members = extract_archive(tampered, dest, verify=False, actor="u")
    assert len(members) == 3


# ---------------------------------------------------------------------------
# verify_archive
# ---------------------------------------------------------------------------

def test_verify_archive_passes_for_clean_archive(archive_path):
    ok, errors = verify_archive(archive_path, actor="u")
    assert ok
    assert errors == []


def test_verify_archive_fails_for_tampered_archive(tmp_path, archive_path):
    tampered = tmp_path / "tampered.vfa"
    with zipfile.ZipFile(archive_path, "r") as src_zf:
        with zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as dst_zf:
            for item in src_zf.infolist():
                data = src_zf.read(item.filename)
                if item.filename != MANIFEST_FILENAME:
                    data = data + b" TAMPERED"
                dst_zf.writestr(item, data)
    ok, errors = verify_archive(tampered, actor="u")
    assert not ok
    assert len(errors) > 0


# ---------------------------------------------------------------------------
# Encrypt / decrypt round-trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_roundtrip(tmp_path, sample_files):
    out = tmp_path / "enc.vfa"
    create_archive(out, [sample_files], passphrase="p@ss!", actor="u")
    enc = Path(str(out) + ".enc")
    assert enc.exists()

    decrypted = tmp_path / "dec.vfa"
    decrypt_archive(enc, decrypted, "p@ss!", actor="u")
    assert decrypted.exists()

    ok, errors = verify_archive(decrypted, actor="u")
    assert ok


def test_decrypt_wrong_passphrase_raises(tmp_path, sample_files):
    out = tmp_path / "enc.vfa"
    create_archive(out, [sample_files], passphrase="correct", actor="u")
    enc = Path(str(out) + ".enc")
    dec = tmp_path / "dec.vfa"
    with pytest.raises(Exception):
        decrypt_archive(enc, dec, "wrong", actor="u")
