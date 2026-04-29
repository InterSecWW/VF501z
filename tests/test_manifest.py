"""Tests for vf501.manifest."""

import json

import pytest

from vf501.manifest import FileEntry, Manifest, MANIFEST_FILENAME


def _sample_manifest() -> Manifest:
    m = Manifest(
        label="Test Archive",
        created_at="2025-01-01T00:00:00+00:00",
        creator="testuser",
        description="Test description",
    )
    m.add_file(FileEntry(
        name="docs/report.pdf",
        original_path="/home/user/docs/report.pdf",
        size=1024,
        sha256="a" * 64,
        md5="b" * 32,
        mtime="2025-01-01T00:00:00+00:00",
        notes="Evidence item 1",
    ))
    return m


# ---------------------------------------------------------------------------
# Serialisation round-trip
# ---------------------------------------------------------------------------

def test_to_json_is_valid_json():
    m = _sample_manifest()
    data = m.to_json()
    parsed = json.loads(data)
    assert parsed["label"] == "Test Archive"
    assert len(parsed["files"]) == 1


def test_from_json_roundtrip():
    m = _sample_manifest()
    m2 = Manifest.from_json(m.to_json())
    assert m2.label == m.label
    assert m2.creator == m.creator
    assert len(m2.files) == 1
    assert m2.files[0].name == "docs/report.pdf"
    assert m2.files[0].notes == "Evidence item 1"


def test_from_json_bytes():
    m = _sample_manifest()
    m2 = Manifest.from_json(m.to_json().encode())
    assert m2.label == m.label


# ---------------------------------------------------------------------------
# File entries
# ---------------------------------------------------------------------------

def test_add_file():
    m = Manifest(label="L", created_at="2025-01-01T00:00:00+00:00")
    assert m.files == []
    entry = FileEntry(
        name="a.txt", original_path="/a.txt", size=10,
        sha256="c" * 64, md5="d" * 32,
    )
    m.add_file(entry)
    assert len(m.files) == 1


def test_get_file_found():
    m = _sample_manifest()
    entry = m.get_file("docs/report.pdf")
    assert entry is not None
    assert entry.size == 1024


def test_get_file_not_found():
    m = _sample_manifest()
    assert m.get_file("nonexistent.txt") is None


# ---------------------------------------------------------------------------
# Extra metadata
# ---------------------------------------------------------------------------

def test_extra_metadata_roundtrip():
    m = Manifest(
        label="Charity Run",
        created_at="2025-06-01T00:00:00+00:00",
        extra={"case_number": "CHR-2025-001", "donor_id_masked": "***456"},
    )
    m2 = Manifest.from_json(m.to_json())
    assert m2.extra["case_number"] == "CHR-2025-001"
    assert m2.extra["donor_id_masked"] == "***456"


# ---------------------------------------------------------------------------
# Manifest filename constant
# ---------------------------------------------------------------------------

def test_manifest_filename_value():
    assert MANIFEST_FILENAME == "__vf501_manifest__.json"
