"""Tests for vf501.forensics."""

import json
from pathlib import Path

import pytest

from vf501.forensics import (
    ChainOfCustody,
    compute_archive_sha256,
    default_coc_path,
    verify_archive_integrity,
)


# ---------------------------------------------------------------------------
# compute_archive_sha256
# ---------------------------------------------------------------------------

def test_compute_archive_sha256(tmp_path):
    import hashlib
    f = tmp_path / "archive.vfa"
    f.write_bytes(b"archive content")
    digest = compute_archive_sha256(f)
    expected = hashlib.sha256(b"archive content").hexdigest()
    assert digest == expected


# ---------------------------------------------------------------------------
# verify_archive_integrity
# ---------------------------------------------------------------------------

def test_verify_archive_integrity_pass(tmp_path):
    import hashlib
    f = tmp_path / "archive.vfa"
    f.write_bytes(b"data")
    expected = hashlib.sha256(b"data").hexdigest()
    ok, reason = verify_archive_integrity(f, expected)
    assert ok
    assert reason == ""


def test_verify_archive_integrity_fail(tmp_path):
    f = tmp_path / "archive.vfa"
    f.write_bytes(b"data")
    ok, reason = verify_archive_integrity(f, "0" * 64)
    assert not ok
    assert "mismatch" in reason


# ---------------------------------------------------------------------------
# ChainOfCustody – basic events
# ---------------------------------------------------------------------------

def make_coc(tmp_path, name="test.vfa.coc") -> ChainOfCustody:
    return ChainOfCustody(tmp_path / name, actor="investigator")


def test_record_event_creates_file(tmp_path):
    coc = make_coc(tmp_path)
    coc_path = tmp_path / "test.vfa.coc"
    assert not coc_path.exists()
    coc.record_event("acquired", "case42.vfa", purpose="Initial seizure")
    assert coc_path.exists()


def test_record_event_fields(tmp_path):
    coc = make_coc(tmp_path)
    event = coc.record_event(
        "examined",
        "case42.vfa",
        purpose="Forensic analysis",
        location="Lab A",
        notes="Bit-for-bit copy verified",
        archive_sha256="abc123",
    )
    assert event["event_type"] == "examined"
    assert event["custodian"] == "investigator"
    assert event["archive"] == "case42.vfa"
    assert event["purpose"] == "Forensic analysis"
    assert event["location"] == "Lab A"
    assert event["notes"] == "Bit-for-bit copy verified"
    assert event["archive_sha256"] == "abc123"


def test_multiple_events(tmp_path):
    coc = make_coc(tmp_path)
    for ev in ["acquired", "transferred", "examined", "stored"]:
        coc.record_event(ev, "case.vfa")
    events = coc.events()
    assert len(events) == 4
    assert [e["event_type"] for e in events] == ["acquired", "transferred", "examined", "stored"]


def test_events_empty_when_no_file(tmp_path):
    coc = ChainOfCustody(tmp_path / "nonexistent.coc")
    assert coc.events() == []


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def test_coc_persists_across_instances(tmp_path):
    coc_path = tmp_path / "evidence.coc"
    coc1 = ChainOfCustody(coc_path, actor="alice")
    coc1.record_event("acquired", "ev.vfa")
    coc2 = ChainOfCustody(coc_path, actor="bob")
    coc2.record_event("transferred", "ev.vfa", notes="Handed to Bob")
    events = coc2.events()
    assert len(events) == 2
    assert events[0]["custodian"] == "alice"
    assert events[1]["custodian"] == "bob"


# ---------------------------------------------------------------------------
# default_coc_path
# ---------------------------------------------------------------------------

def test_default_coc_path():
    p = default_coc_path("/evidence/case42.vfa")
    assert str(p) == "/evidence/case42.vfa.coc"
