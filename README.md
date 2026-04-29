# VF501z

**VF501** is a modern, auditable file archiver designed for two demanding audiences:

1. **Charity organisations** protecting sensitive donor data – archives are
   optionally encrypted with AES-256-GCM (PBKDF2-derived keys) so that donor
   records stay confidential at rest and in transit.
2. **Digital-forensics professionals** who need verifiable, forensically clean
   evidence handling – every archive embeds a cryptographic manifest, an
   append-only audit log (with SHA-256 integrity chaining), and a
   chain-of-custody record.

---

## Features

| Feature | Detail |
|---|---|
| `.vfa` archive format | Standard ZIP (DEFLATE-6) with an embedded JSON manifest |
| Per-file hashing | SHA-256 + MD5 recorded in the manifest at creation time |
| Integrity verification | Automatic on extraction; on-demand `verify` command |
| AES-256-GCM encryption | PBKDF2-HMAC-SHA256 key derivation (600 000 iterations) |
| Append-only audit log | Newline-delimited JSON, each entry hashed to the previous (tamper-evident chain) |
| Chain-of-custody records | Separate `.coc` file; records acquired / transferred / examined / stored events |
| Extra metadata | Arbitrary key-value pairs in the manifest (case number, donor-ID mask, …) |
| Per-file notes | Evidence tags, exhibit references |
| Python API | All features accessible programmatically via `vf501.*` modules |

---

## Installation

```bash
pip install .            # or: pip install -e . (editable / development)
```

**Requirements:** Python ≥ 3.10, `cryptography ≥ 41`, `click ≥ 8`

---

## Quick start

### Create an archive

```bash
# Basic
vf501 create evidence.vfa report.pdf photo.jpg notes.txt \
      --label "Case 42 – Q1 Donors" \
      --description "Quarterly donor report plus forensic exhibits"

# With encryption (prompts for passphrase)
vf501 create evidence.vfa report.pdf photo.jpg \
      --label "Encrypted Donors" --encrypt

# With extra metadata and per-file evidence notes
vf501 create evidence.vfa exhibit_A.pdf \
      --label "Exhibit A" \
      --extra "case_number=CHR-2025-042" \
      --extra "classification=RESTRICTED" \
      --notes "exhibit_A.pdf:Chain-of-custody tag #001"
```

### List contents

```bash
vf501 list evidence.vfa          # tabular view
vf501 list evidence.vfa --json   # full manifest as JSON
```

### Extract

```bash
vf501 extract evidence.vfa ./output/   # verifies SHA-256 + MD5 on every file
vf501 extract evidence.vfa ./output/ --no-verify   # skip verification
```

### Verify integrity

```bash
vf501 verify evidence.vfa   # exits 0 on pass, 1 on failure
```

### Decrypt an encrypted archive

```bash
vf501 decrypt evidence.vfa.enc decrypted.vfa
```

### Audit log

```bash
vf501 audit-log evidence.vfa                # tabular summary
vf501 audit-log evidence.vfa --json         # JSON lines
vf501 audit-log evidence.vfa --verify-chain # verify tamper-evident chain
```

### Chain-of-custody

```bash
# View custody events
vf501 custody evidence.vfa

# Record a new event
vf501 custody evidence.vfa \
      --add-event "transferred" \
      --purpose "Sent to forensic lab" \
      --location "Lab A – Building 3"
```

---

## Archive format

A `.vfa` file is a valid ZIP archive that can be opened with any ZIP tool.
It always contains a reserved entry `__vf501_manifest__.json`:

```json
{
  "label": "Case 42",
  "created_at": "2025-06-01T12:00:00+00:00",
  "creator": "alice",
  "description": "...",
  "extra": { "case_number": "CHR-001" },
  "files": [
    {
      "name": "report.pdf",
      "original_path": "/home/alice/docs/report.pdf",
      "size": 204800,
      "sha256": "e3b0c44298fc1c149afb...",
      "md5": "d41d8cd98f00b204e9800998ecf8427e",
      "mtime": "2025-05-31T09:30:00+00:00",
      "notes": "Chain-of-custody tag #001"
    }
  ]
}
```

Alongside the `.vfa` file the tool creates:
- `<archive>.vfa.log` – append-only audit log
- `<archive>.vfa.coc` – chain-of-custody record
- `<archive>.vfa.enc` – AES-256-GCM-encrypted archive blob (only when `--encrypt` is used)

---

## Running tests

```bash
pip install pytest
pytest
```

71 tests covering hasher, crypto, manifest, audit log, forensics, and the
full archiver (create / list / extract / verify / encrypt / decrypt).

---

## Security notes

* Encryption uses AES-256-GCM which provides **authenticated encryption** –
  any bit-flip in the ciphertext is detected before decryption.
* The key is derived with **PBKDF2-HMAC-SHA256 at 600 000 iterations** (NIST
  SP 800-132 compliant) with a random 16-byte salt per encryption call.
* The audit log uses a **SHA-256 integrity chain**: each entry records the
  hash of the previous entry so any deletion or modification is detectable.
* Original file data is **never modified** during archiving or extraction.
