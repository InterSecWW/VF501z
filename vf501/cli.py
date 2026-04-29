"""VF501 command-line interface.

Usage examples::

    # Create an archive
    vf501 create evidence.vfa file1.txt file2.txt --label "Case 42" --encrypt

    # List contents
    vf501 list evidence.vfa

    # Extract (with integrity verification)
    vf501 extract evidence.vfa ./output/

    # Verify in-place
    vf501 verify evidence.vfa

    # Show audit log
    vf501 audit-log evidence.vfa

    # Chain-of-custody events
    vf501 custody evidence.vfa
    vf501 custody evidence.vfa --add-event "transferred" --purpose "Sent to lab"
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

import click

from .archiver import create_archive, decrypt_archive, extract_archive, list_archive, verify_archive
from .audit import AuditLog, default_log_path
from .forensics import ChainOfCustody, compute_archive_sha256, default_coc_path


# ---------------------------------------------------------------------------
# Root group
# ---------------------------------------------------------------------------

@click.group()
@click.version_option(package_name="vf501")
def cli() -> None:
    """VF501 – auditable file archiver for sensitive data and digital forensics."""


# ---------------------------------------------------------------------------
# create
# ---------------------------------------------------------------------------

@cli.command("create")
@click.argument("archive", metavar="ARCHIVE.vfa", type=click.Path())
@click.argument("sources", nargs=-1, required=True, metavar="FILE_OR_DIR...")
@click.option("--label", default="", help="Human-readable archive label.")
@click.option("--description", default="", help="Free-text description.")
@click.option("--encrypt/--no-encrypt", default=False,
              help="Encrypt the archive with AES-256-GCM (prompts for passphrase).")
@click.option("--notes", "notes_list", multiple=True,
              metavar="PATH:NOTE",
              help="Per-file note in the form 'path:note'.  May be repeated.")
@click.option("--extra", "extra_list", multiple=True,
              metavar="KEY=VALUE",
              help="Extra metadata key=value pairs.  May be repeated.")
def cmd_create(
    archive: str,
    sources: tuple[str, ...],
    label: str,
    description: str,
    encrypt: bool,
    notes_list: tuple[str, ...],
    extra_list: tuple[str, ...],
) -> None:
    """Create a new VF501 archive from FILE_OR_DIR sources."""
    passphrase: Optional[str] = None
    if encrypt:
        passphrase = click.prompt("Passphrase", hide_input=True, confirmation_prompt=True)

    notes_map = {}
    for item in notes_list:
        if ":" in item:
            path_part, _, note = item.partition(":")
            notes_map[path_part] = note

    extra: dict = {}
    for item in extra_list:
        if "=" in item:
            k, _, v = item.partition("=")
            extra[k.strip()] = v.strip()

    try:
        manifest = create_archive(
            archive,
            list(sources),
            label=label,
            description=description,
            passphrase=passphrase,
            extra=extra,
            notes_map=notes_map,
        )
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Created {archive}")
    click.echo(f"  Label      : {manifest.label}")
    click.echo(f"  Files      : {len(manifest.files)}")
    click.echo(f"  Created at : {manifest.created_at}")
    if encrypt:
        click.echo(f"  Encrypted  : {archive}.enc")


# ---------------------------------------------------------------------------
# list
# ---------------------------------------------------------------------------

@cli.command("list")
@click.argument("archive", metavar="ARCHIVE.vfa", type=click.Path(exists=True))
@click.option("--json", "as_json", is_flag=True, help="Output manifest as JSON.")
def cmd_list(archive: str, as_json: bool) -> None:
    """List contents of a VF501 archive."""
    try:
        manifest = list_archive(archive)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    if as_json:
        click.echo(manifest.to_json())
        return

    click.echo(f"Archive : {archive}")
    click.echo(f"Label   : {manifest.label}")
    click.echo(f"Created : {manifest.created_at}")
    if manifest.description:
        click.echo(f"Desc    : {manifest.description}")
    if manifest.extra:
        for k, v in manifest.extra.items():
            click.echo(f"  {k}: {v}")
    click.echo(f"\n{'Name':<40} {'Size':>10}  {'SHA-256':>64}  Notes")
    click.echo("-" * 120)
    for f in manifest.files:
        click.echo(f"{f.name:<40} {f.size:>10}  {f.sha256}  {f.notes}")


# ---------------------------------------------------------------------------
# extract
# ---------------------------------------------------------------------------

@cli.command("extract")
@click.argument("archive", metavar="ARCHIVE.vfa", type=click.Path(exists=True))
@click.argument("dest", metavar="DEST_DIR", type=click.Path(), default=".")
@click.option("--no-verify", is_flag=True, help="Skip integrity verification.")
def cmd_extract(archive: str, dest: str, no_verify: bool) -> None:
    """Extract a VF501 archive to DEST_DIR."""
    try:
        members = extract_archive(archive, dest, verify=not no_verify)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)

    click.echo(f"Extracted {len(members)} file(s) to {dest}")
    if not no_verify:
        click.echo("  Integrity verification: PASSED")


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------

@cli.command("verify")
@click.argument("archive", metavar="ARCHIVE.vfa", type=click.Path(exists=True))
def cmd_verify(archive: str) -> None:
    """Verify the integrity of every file in a VF501 archive."""
    ok, errors = verify_archive(archive)
    if ok:
        click.echo(f"PASSED  {archive}")
    else:
        click.echo(f"FAILED  {archive}", err=True)
        for err in errors:
            click.echo(f"  {err}", err=True)
        sys.exit(1)


# ---------------------------------------------------------------------------
# decrypt
# ---------------------------------------------------------------------------

@cli.command("decrypt")
@click.argument("enc_file", metavar="ARCHIVE.vfa.enc", type=click.Path(exists=True))
@click.argument("output", metavar="OUTPUT.vfa", type=click.Path())
def cmd_decrypt(enc_file: str, output: str) -> None:
    """Decrypt an encrypted VF501 archive."""
    passphrase = click.prompt("Passphrase", hide_input=True)
    try:
        decrypt_archive(enc_file, output, passphrase)
    except Exception as exc:
        click.echo(f"Error: {exc}", err=True)
        sys.exit(1)
    click.echo(f"Decrypted to {output}")


# ---------------------------------------------------------------------------
# audit-log
# ---------------------------------------------------------------------------

@cli.command("audit-log")
@click.argument("archive", metavar="ARCHIVE.vfa", type=click.Path())
@click.option("--verify-chain", is_flag=True, help="Verify the log's integrity chain.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON lines.")
def cmd_audit_log(archive: str, verify_chain: bool, as_json: bool) -> None:
    """Display the audit log for an archive."""
    import json as _json
    log_path = default_log_path(archive)
    if not log_path.exists():
        click.echo(f"No audit log found at {log_path}", err=True)
        sys.exit(1)

    log = AuditLog(log_path)

    if verify_chain:
        ok, errors = log.verify_chain()
        if ok:
            click.echo("Audit log chain: INTACT")
        else:
            click.echo("Audit log chain: BROKEN", err=True)
            for err in errors:
                click.echo(f"  {err}", err=True)
            sys.exit(1)
        return

    entries = log.entries()
    if as_json:
        for entry in entries:
            click.echo(_json.dumps(entry))
        return

    click.echo(f"Audit log: {log_path}  ({len(entries)} entries)")
    click.echo("-" * 80)
    for e in entries:
        click.echo(
            f"{e['timestamp']}  [{e['operation']:10s}]  actor={e['actor']}"
        )
        for k, v in e.get("details", {}).items():
            click.echo(f"    {k}: {v}")


# ---------------------------------------------------------------------------
# custody
# ---------------------------------------------------------------------------

@cli.command("custody")
@click.argument("archive", metavar="ARCHIVE.vfa", type=click.Path())
@click.option("--add-event", "event_type", default=None,
              help="Add a custody event (e.g. 'transferred', 'examined').")
@click.option("--purpose", default="", help="Purpose of the event.")
@click.option("--location", default="", help="Physical/logical location.")
@click.option("--notes", default="", help="Free-text notes.")
@click.option("--json", "as_json", is_flag=True, help="Output events as JSON.")
def cmd_custody(
    archive: str,
    event_type: Optional[str],
    purpose: str,
    location: str,
    notes: str,
    as_json: bool,
) -> None:
    """View or update the chain-of-custody record for an archive."""
    import json as _json
    coc_path = default_coc_path(archive)
    coc = ChainOfCustody(coc_path)

    if event_type:
        sha256 = None
        if Path(archive).exists():
            sha256 = compute_archive_sha256(archive)
        event = coc.record_event(
            event_type,
            archive,
            purpose=purpose,
            location=location,
            notes=notes,
            archive_sha256=sha256,
        )
        click.echo(f"Recorded '{event_type}' event.")
        click.echo(f"  Timestamp: {event['timestamp']}")
        return

    events = coc.events()
    if not events:
        click.echo(f"No custody events found for {archive}")
        return

    if as_json:
        for ev in events:
            click.echo(_json.dumps(ev))
        return

    click.echo(f"Chain-of-custody: {coc_path}  ({len(events)} events)")
    click.echo("-" * 80)
    for ev in events:
        click.echo(
            f"{ev['timestamp']}  [{ev['event_type']:15s}]  "
            f"custodian={ev['custodian']}"
        )
        if ev.get("archive_sha256"):
            click.echo(f"    archive_sha256: {ev['archive_sha256']}")
        if ev.get("purpose"):
            click.echo(f"    purpose: {ev['purpose']}")
        if ev.get("notes"):
            click.echo(f"    notes: {ev['notes']}")
