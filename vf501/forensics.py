"""Chain-of-custody and forensic integrity verification for VF501.

A **chain-of-custody** (CoC) record is a separate JSON file
(``<archive>.vfa.coc``) that tracks every transfer, examination, and storage
event for a piece of digital evidence.  It is independent of the audit log so
that the evidence file and its custody record can be stored separately or
submitted to a court independently.

A **forensic verification** checks:
1. The archive's SHA-256 digest matches the one recorded at creation time.
2. Every file inside the archive hashes to the digest stored in the manifest.
3. The audit-log chain is unbroken.
"""

from __future__ import annotations

import getpass
import hashlib
import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


COC_EXTENSION = ".coc"


# ---------------------------------------------------------------------------
# Chain-of-custody file
# ---------------------------------------------------------------------------

class ChainOfCustody:
    """Append-only chain-of-custody record stored as newline-delimited JSON.

    Args:
        coc_path: Path to the ``.coc`` file (created on first write).
        actor: Override for the custodian name.
    """

    def __init__(self, coc_path: str | Path, actor: Optional[str] = None) -> None:
        self.coc_path = Path(coc_path)
        try:
            self.actor = actor or getpass.getuser()
        except Exception:
            self.actor = "unknown"
        try:
            self.host = socket.gethostname()
        except Exception:
            self.host = "unknown"

    def record_event(
        self,
        event_type: str,
        archive: str | Path,
        *,
        purpose: str = "",
        location: str = "",
        notes: str = "",
        archive_sha256: Optional[str] = None,
    ) -> dict[str, Any]:
        """Append a chain-of-custody event.

        Args:
            event_type: One of ``"acquired"``, ``"transferred"``,
                ``"examined"``, ``"stored"``, ``"verified"``, or any
                custom string.
            archive: Path to the evidence archive.
            purpose: Reason for this event.
            location: Physical or logical location of the evidence.
            notes: Free-text notes.
            archive_sha256: SHA-256 of the archive at this moment (optional
                but recommended for verified events).

        Returns:
            The event dict that was written.
        """
        event: dict[str, Any] = {
            "timestamp": _now_utc(),
            "event_type": event_type,
            "custodian": self.actor,
            "host": self.host,
            "archive": str(archive),
            "archive_sha256": archive_sha256,
            "purpose": purpose,
            "location": location,
            "notes": notes,
        }
        self.coc_path.parent.mkdir(parents=True, exist_ok=True)
        with self.coc_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")
        return event

    def events(self) -> list[dict[str, Any]]:
        """Return all CoC events (oldest first)."""
        if not self.coc_path.exists():
            return []
        result = []
        with self.coc_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    result.append(json.loads(line))
        return result


# ---------------------------------------------------------------------------
# Forensic verification
# ---------------------------------------------------------------------------

class ForensicVerificationError(Exception):
    """Raised when forensic verification fails."""


def compute_archive_sha256(archive_path: str | Path) -> str:
    """Return the SHA-256 hex digest of an archive file."""
    h = hashlib.sha256()
    with open(archive_path, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


def verify_archive_integrity(
    archive_path: str | Path,
    expected_sha256: str,
) -> tuple[bool, str]:
    """Verify the SHA-256 of *archive_path* against *expected_sha256*.

    Args:
        archive_path: Path to the ``.vfa`` archive.
        expected_sha256: The digest recorded at creation / last verification.

    Returns:
        ``(True, "")`` on success; ``(False, <reason>)`` on failure.
    """
    actual = compute_archive_sha256(archive_path)
    if actual != expected_sha256:
        return False, (
            f"Archive SHA-256 mismatch: expected {expected_sha256!r}, "
            f"got {actual!r}"
        )
    return True, ""


def default_coc_path(archive_path: str | Path) -> Path:
    """Return the conventional ``<archive>.vfa.coc`` path."""
    return Path(str(archive_path) + COC_EXTENSION)


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
