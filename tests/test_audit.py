"""Tests for vf501.audit."""

import json
import time
from pathlib import Path

import pytest

from vf501.audit import AuditLog, default_log_path


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_log(tmp_path, name="test.vfa") -> tuple[AuditLog, Path]:
    log_path = tmp_path / (name + ".log")
    log = AuditLog(log_path, actor="testuser")
    return log, log_path


# ---------------------------------------------------------------------------
# Basic recording
# ---------------------------------------------------------------------------

def test_record_creates_log_file(tmp_path):
    log, log_path = make_log(tmp_path)
    assert not log_path.exists()
    log.record("create", "test.vfa", details={"files": 3})
    assert log_path.exists()


def test_record_fields(tmp_path):
    log, log_path = make_log(tmp_path)
    log.record("create", "test.vfa", details={"file_count": 5, "archive_sha256": "aaa"})
    entries = log.entries()
    assert len(entries) == 1
    e = entries[0]
    assert e["operation"] == "create"
    assert e["actor"] == "testuser"
    assert e["archive"] == "test.vfa"
    assert e["details"]["file_count"] == 5


def test_record_multiple_entries(tmp_path):
    log, log_path = make_log(tmp_path)
    log.record("create", "test.vfa")
    log.record("verify", "test.vfa", details={"ok": True})
    log.record("extract", "test.vfa", details={"dest": "/tmp"})
    assert len(log.entries()) == 3


def test_record_no_details(tmp_path):
    log, log_path = make_log(tmp_path)
    log.record("list", "test.vfa")
    entries = log.entries()
    assert entries[0]["details"] == {}


# ---------------------------------------------------------------------------
# Integrity chain
# ---------------------------------------------------------------------------

def test_chain_intact_single_entry(tmp_path):
    log, _ = make_log(tmp_path)
    log.record("create", "test.vfa")
    ok, errors = log.verify_chain()
    assert ok
    assert errors == []


def test_chain_intact_multiple_entries(tmp_path):
    log, _ = make_log(tmp_path)
    for op in ["create", "verify", "extract", "custody"]:
        log.record(op, "test.vfa")
    ok, errors = log.verify_chain()
    assert ok
    assert errors == []


def test_chain_broken_on_tamper(tmp_path):
    log, log_path = make_log(tmp_path)
    log.record("create", "test.vfa")
    log.record("verify", "test.vfa")
    # Tamper with the first entry
    lines = log_path.read_text().splitlines()
    obj = json.loads(lines[0])
    obj["actor"] = "TAMPERED"
    lines[0] = json.dumps(obj)
    log_path.write_text("\n".join(lines) + "\n")
    ok, errors = log.verify_chain()
    assert not ok
    assert len(errors) > 0


def test_chain_empty_log(tmp_path):
    log, _ = make_log(tmp_path)
    ok, errors = log.verify_chain()
    assert ok
    assert errors == []


# ---------------------------------------------------------------------------
# Persistence across instances
# ---------------------------------------------------------------------------

def test_log_persists_across_instances(tmp_path):
    log_path = tmp_path / "arch.vfa.log"
    log1 = AuditLog(log_path, actor="user1")
    log1.record("create", "arch.vfa")
    log2 = AuditLog(log_path, actor="user2")
    log2.record("verify", "arch.vfa")
    entries = log2.entries()
    assert len(entries) == 2
    ok, _ = log2.verify_chain()
    assert ok


# ---------------------------------------------------------------------------
# default_log_path
# ---------------------------------------------------------------------------

def test_default_log_path():
    p = default_log_path("/evidence/case42.vfa")
    assert str(p) == "/evidence/case42.vfa.log"
