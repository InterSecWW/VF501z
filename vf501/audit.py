"""Append-only audit log for VF501.

Every significant operation (archive creation, extraction, verification,
encryption, chain-of-custody updates) is recorded as a JSON object appended to
a newline-delimited JSON log file (``<archive>.vfa.log`` by default).

Each entry contains:
    - ``timestamp``  ISO-8601 UTC
    - ``operation``  short operation name (e.g. ``"create"``, ``"extract"``)
    - ``actor``      username / process identifier
    - ``archive``    path to the ``.vfa`` file
    - ``details``    arbitrary dict with operation-specific fields
    - ``integrity``  SHA-256 of the previous log entry (chain of entries)
"""

from __future__ import annotations

import getpass
import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class AuditLog:
    """Append-only audit log backed by a newline-delimited JSON file.

    Args:
        log_path: Path to the ``.vfa.log`` file.  Created on first write.
        actor: Override for the acting user.  Defaults to the OS username.
    """

    def __init__(self, log_path: str | Path, actor: Optional[str] = None) -> None:
        self.log_path = Path(log_path)
        try:
            self.actor = actor or getpass.getuser()
        except Exception:
            self.actor = "unknown"
        try:
            self.host = socket.gethostname()
        except Exception:
            self.host = "unknown"
        self._prev_digest: Optional[str] = self._last_entry_digest()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record(self, operation: str, archive: str | Path, details: dict[str, Any] | None = None) -> dict[str, Any]:
        """Append a new audit entry.

        Args:
            operation: Short operation identifier string.
            archive: Path to the archive being operated on.
            details: Optional operation-specific fields.

        Returns:
            The entry dict that was written.
        """
        entry: dict[str, Any] = {
            "timestamp": _now_utc(),
            "operation": operation,
            "actor": self.actor,
            "host": self.host,
            "archive": str(archive),
            "details": details or {},
            "prev_entry_sha256": self._prev_digest,
        }
        line = json.dumps(entry, ensure_ascii=False)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
        self._prev_digest = hashlib.sha256(line.encode()).hexdigest()
        return entry

    def entries(self) -> list[dict[str, Any]]:
        """Return all audit entries as a list of dicts (oldest first)."""
        if not self.log_path.exists():
            return []
        result = []
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    result.append(json.loads(line))
        return result

    def verify_chain(self) -> tuple[bool, list[str]]:
        """Verify the integrity chain of all log entries.

        Each entry's ``prev_entry_sha256`` must match the SHA-256 of the
        immediately preceding entry's raw JSON line.

        Returns:
            A tuple ``(ok, errors)`` where *ok* is ``True`` when the chain is
            intact and *errors* is a list of human-readable problem strings.
        """
        if not self.log_path.exists():
            return True, []
        errors: list[str] = []
        prev_digest: Optional[str] = None
        with self.log_path.open("r", encoding="utf-8") as fh:
            for lineno, raw_line in enumerate(fh, start=1):
                raw_line = raw_line.rstrip("\n")
                if not raw_line.strip():
                    continue
                try:
                    entry = json.loads(raw_line)
                except json.JSONDecodeError as exc:
                    errors.append(f"Line {lineno}: JSON parse error – {exc}")
                    prev_digest = None
                    continue
                recorded_prev = entry.get("prev_entry_sha256")
                if recorded_prev != prev_digest:
                    errors.append(
                        f"Line {lineno}: chain broken – expected prev_sha256 "
                        f"{prev_digest!r}, got {recorded_prev!r}"
                    )
                prev_digest = hashlib.sha256(raw_line.encode()).hexdigest()
        return len(errors) == 0, errors

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _last_entry_digest(self) -> Optional[str]:
        """Return SHA-256 of the last line in the log file, or None."""
        if not self.log_path.exists():
            return None
        last_line: Optional[str] = None
        with self.log_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                stripped = line.rstrip("\n")
                if stripped.strip():
                    last_line = stripped
        if last_line is None:
            return None
        return hashlib.sha256(last_line.encode()).hexdigest()


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def default_log_path(archive_path: str | Path) -> Path:
    """Return the conventional ``<archive>.vfa.log`` path for *archive_path*."""
    return Path(str(archive_path) + ".log")
