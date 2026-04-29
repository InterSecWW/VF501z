"""Archive manifest for VF501.

A manifest is a JSON document stored inside every ``.vfa`` archive under the
reserved name ``__vf501_manifest__.json``.  It records:

* Archive-level metadata (creator, timestamp, label, description)
* Per-file entries: original path, size, SHA-256 digest, MD5 digest,
  modification time, and any per-file notes

The manifest is written *last* into the archive so that its own presence is
captured; a SHA-256 digest of the final archive file is stored separately in
the audit log.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

MANIFEST_FILENAME = "__vf501_manifest__.json"


@dataclass
class FileEntry:
    """Metadata for a single file stored in an archive."""

    name: str
    """Relative path inside the archive (forward-slash separated)."""

    original_path: str
    """Absolute or relative path of the file at archiving time."""

    size: int
    """File size in bytes."""

    sha256: str
    """SHA-256 hex digest of the **original** (pre-compression) file."""

    md5: str
    """MD5 hex digest of the **original** file."""

    mtime: Optional[str] = None
    """ISO-8601 modification timestamp of the source file, or ``None``."""

    notes: str = ""
    """Optional free-text notes (e.g. evidence tag, chain-of-custody ref)."""


@dataclass
class Manifest:
    """Top-level manifest document for a ``.vfa`` archive."""

    label: str
    """Human-readable archive label."""

    created_at: str
    """ISO-8601 UTC timestamp of archive creation."""

    creator: str = ""
    """Username or system identifier of the creator."""

    description: str = ""
    """Free-text description of the archive contents."""

    files: list[FileEntry] = field(default_factory=list)
    """Ordered list of file entries."""

    extra: dict[str, Any] = field(default_factory=dict)
    """Arbitrary key/value metadata (e.g. case number, donor ID mask)."""

    @staticmethod
    def now_utc() -> str:
        """Return current time as an ISO-8601 UTC string."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")

    def add_file(self, entry: FileEntry) -> None:
        """Append a :class:`FileEntry` to the manifest."""
        self.files.append(entry)

    def to_json(self, indent: int = 2) -> str:
        """Serialise the manifest to a JSON string."""
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)

    @staticmethod
    def from_json(data: str | bytes) -> "Manifest":
        """Deserialise a manifest from a JSON string or bytes."""
        obj = json.loads(data)
        files = [FileEntry(**f) for f in obj.pop("files", [])]
        manifest = Manifest(**obj)
        manifest.files = files
        return manifest

    def get_file(self, name: str) -> Optional[FileEntry]:
        """Return the :class:`FileEntry` for *name*, or ``None`` if not found."""
        for entry in self.files:
            if entry.name == name:
                return entry
        return None
