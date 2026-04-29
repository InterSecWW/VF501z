"""Core VF501 archiver – create, list, extract, and verify ``.vfa`` archives.

A ``.vfa`` (VF501 Archive) file is a standard ZIP container with:
  - Compressed file data (DEFLATE, level 6)
  - An embedded ``__vf501_manifest__.json`` recording per-file SHA-256/MD5
    digests, sizes, and modification timestamps
  - An audit log written alongside the archive (``<archive>.vfa.log``)
  - Optionally, an AES-256-GCM-encrypted payload (the ZIP bytes are encrypted
    as a single blob and stored as ``<archive>.vfa.enc``)

Design goals
~~~~~~~~~~~~
* **Auditable** – every operation is recorded in the audit log.
* **Forensically clean** – file contents are never modified; hashes are
  verified on extraction; original metadata is preserved.
* **Donor-data safe** – optional passphrase encryption protects sensitive data.
"""

from __future__ import annotations

import getpass
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .audit import AuditLog, default_log_path
from .crypto import decrypt_bytes, encrypt_bytes
from .forensics import ChainOfCustody, compute_archive_sha256, default_coc_path
from .hasher import hash_file, verify_file
from .manifest import FileEntry, Manifest, MANIFEST_FILENAME


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def create_archive(
    archive_path: str | Path,
    sources: list[str | Path],
    *,
    label: str = "",
    description: str = "",
    passphrase: Optional[str] = None,
    actor: Optional[str] = None,
    extra: Optional[dict] = None,
    notes_map: Optional[dict[str, str]] = None,
) -> Manifest:
    """Create a ``.vfa`` archive from *sources*.

    Args:
        archive_path: Destination path (should end in ``.vfa``).
        sources: Files (or directories) to archive.  Directories are walked
            recursively.
        label: Human-readable archive label.
        description: Free-text description.
        passphrase: If provided, the archive ZIP bytes are AES-256-GCM
            encrypted and stored as ``<archive_path>.enc`` in addition to the
            plain ``.vfa`` file.
        actor: Override for the operator name recorded in the audit log.
        extra: Extra key/value metadata stored in the manifest.
        notes_map: Mapping from source path string → per-file notes.

    Returns:
        The :class:`~vf501.manifest.Manifest` of the created archive.
    """
    archive_path = Path(archive_path)
    actor = actor or _current_user()
    notes_map = notes_map or {}
    extra = extra or {}

    manifest = Manifest(
        label=label or archive_path.stem,
        created_at=Manifest.now_utc(),
        creator=actor,
        description=description,
        extra=extra,
    )

    # Collect all source files
    file_paths: list[Path] = []
    for src in sources:
        src = Path(src)
        if src.is_dir():
            file_paths.extend(p for p in src.rglob("*") if p.is_file())
        else:
            file_paths.append(src)

    # Write ZIP archive
    with zipfile.ZipFile(archive_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for fpath in file_paths:
            fpath = fpath.resolve()
            arcname = _arcname(fpath, file_paths)
            digests = hash_file(fpath, ["sha256", "md5"])
            stat = fpath.stat()
            mtime = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(timespec="seconds")
            entry = FileEntry(
                name=arcname,
                original_path=str(fpath),
                size=stat.st_size,
                sha256=digests["sha256"],
                md5=digests["md5"],
                mtime=mtime,
                notes=notes_map.get(str(fpath), ""),
            )
            manifest.add_file(entry)
            zf.write(fpath, arcname=arcname)

        # Embed manifest
        zf.writestr(MANIFEST_FILENAME, manifest.to_json())

    # Audit log
    archive_sha256 = compute_archive_sha256(archive_path)
    log = AuditLog(default_log_path(archive_path), actor=actor)
    log.record("create", archive_path, details={
        "label": label,
        "file_count": len(file_paths),
        "archive_sha256": archive_sha256,
        "encrypted": passphrase is not None,
    })

    # Optional encryption
    if passphrase is not None:
        enc_path = Path(str(archive_path) + ".enc")
        raw = archive_path.read_bytes()
        enc_path.write_bytes(encrypt_bytes(raw, passphrase))
        log.record("encrypt", archive_path, details={"enc_path": str(enc_path)})

    # Chain-of-custody: record acquisition
    coc = ChainOfCustody(default_coc_path(archive_path), actor=actor)
    coc.record_event(
        "acquired",
        archive_path,
        purpose="Archive created",
        archive_sha256=archive_sha256,
    )

    return manifest


def list_archive(archive_path: str | Path) -> Manifest:
    """Read and return the :class:`~vf501.manifest.Manifest` from *archive_path*.

    Args:
        archive_path: Path to a ``.vfa`` file.

    Returns:
        The embedded manifest.

    Raises:
        KeyError: If no manifest is found inside the archive.
    """
    archive_path = Path(archive_path)
    with zipfile.ZipFile(archive_path, "r") as zf:
        manifest_json = zf.read(MANIFEST_FILENAME)
    return Manifest.from_json(manifest_json)


def extract_archive(
    archive_path: str | Path,
    dest_dir: str | Path,
    *,
    verify: bool = True,
    actor: Optional[str] = None,
) -> list[str]:
    """Extract all files from *archive_path* into *dest_dir*.

    Args:
        archive_path: Path to a ``.vfa`` file.
        dest_dir: Destination directory (created if necessary).
        verify: If ``True`` (default), verify every extracted file against the
            SHA-256 and MD5 digests recorded in the manifest.
        actor: Operator name for the audit log.

    Returns:
        List of extracted file paths (relative to *dest_dir*).

    Raises:
        IntegrityError: If *verify* is ``True`` and any file fails digest
            verification.
    """
    archive_path = Path(archive_path)
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    actor = actor or _current_user()

    manifest = list_archive(archive_path)

    with zipfile.ZipFile(archive_path, "r") as zf:
        members = [n for n in zf.namelist() if n != MANIFEST_FILENAME]
        zf.extractall(dest_dir, members=members)

    failed: list[str] = []
    if verify:
        for entry in manifest.files:
            extracted = dest_dir / entry.name
            if not extracted.exists():
                failed.append(f"{entry.name}: file not found after extraction")
                continue
            if not verify_file(extracted, {"sha256": entry.sha256, "md5": entry.md5}):
                failed.append(
                    f"{entry.name}: digest mismatch "
                    f"(expected sha256={entry.sha256})"
                )

    # Audit log
    log = AuditLog(default_log_path(archive_path), actor=actor)
    log.record("extract", archive_path, details={
        "dest_dir": str(dest_dir),
        "file_count": len(members),
        "verify": verify,
        "integrity_failures": failed,
    })

    if failed:
        raise IntegrityError(
            f"Integrity verification failed for {len(failed)} file(s):\n"
            + "\n".join(f"  {f}" for f in failed)
        )

    return members


def verify_archive(
    archive_path: str | Path,
    *,
    actor: Optional[str] = None,
) -> tuple[bool, list[str]]:
    """Verify the integrity of every file inside *archive_path* in-place.

    Files are extracted to a temporary in-memory buffer for hashing; nothing
    is written to disk (other than the audit log entry).

    Args:
        archive_path: Path to a ``.vfa`` file.
        actor: Operator name for the audit log.

    Returns:
        ``(ok, errors)`` – *ok* is ``True`` when all digests match.
    """
    import tempfile
    import shutil

    archive_path = Path(archive_path)
    actor = actor or _current_user()
    manifest = list_archive(archive_path)

    errors: list[str] = []

    with tempfile.TemporaryDirectory(prefix="vf501_verify_") as tmpdir:
        tmp = Path(tmpdir)
        with zipfile.ZipFile(archive_path, "r") as zf:
            members = [n for n in zf.namelist() if n != MANIFEST_FILENAME]
            zf.extractall(tmp, members=members)

        for entry in manifest.files:
            fpath = tmp / entry.name
            if not fpath.exists():
                errors.append(f"{entry.name}: missing in archive")
                continue
            if not verify_file(fpath, {"sha256": entry.sha256, "md5": entry.md5}):
                actual = hash_file(fpath, ["sha256", "md5"])
                errors.append(
                    f"{entry.name}: digest mismatch – "
                    f"manifest sha256={entry.sha256}, actual={actual['sha256']}"
                )

    ok = len(errors) == 0
    log = AuditLog(default_log_path(archive_path), actor=actor)
    log.record("verify", archive_path, details={
        "ok": ok,
        "errors": errors,
        "file_count": len(manifest.files),
    })
    return ok, errors


def decrypt_archive(
    enc_path: str | Path,
    archive_path: str | Path,
    passphrase: str,
    *,
    actor: Optional[str] = None,
) -> None:
    """Decrypt a ``.vfa.enc`` file back to a ``.vfa`` archive.

    Args:
        enc_path: Path to the encrypted file (``<name>.vfa.enc``).
        archive_path: Destination path for the decrypted ``.vfa`` archive.
        passphrase: Decryption passphrase.
        actor: Operator name.
    """
    enc_path = Path(enc_path)
    archive_path = Path(archive_path)
    actor = actor or _current_user()

    raw = decrypt_bytes(enc_path.read_bytes(), passphrase)
    archive_path.write_bytes(raw)

    log = AuditLog(default_log_path(archive_path), actor=actor)
    log.record("decrypt", archive_path, details={"enc_path": str(enc_path)})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class IntegrityError(Exception):
    """Raised when extracted files fail digest verification."""


def _current_user() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


def _arcname(fpath: Path, all_paths: list[Path]) -> str:
    """Derive a stable archive member name from a file path.

    If all source paths share a common parent, strip that prefix so the
    archive does not embed absolute paths.  Otherwise use the file name only.
    """
    if len(all_paths) == 1:
        return fpath.name
    try:
        # Find common ancestor
        parents = [p.resolve().parent for p in all_paths]
        common = Path(os.path.commonpath(parents))
        return str(fpath.relative_to(common)).replace(os.sep, "/")
    except ValueError:
        return fpath.name
