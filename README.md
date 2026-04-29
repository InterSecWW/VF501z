# VF501z
VF-501 Compression

**Forensic-Grade Compression + Encryption for Charity & Digital Forensics**

**Free • Open Source • Cross-Platform (Windows + Linux + macOS)**  
**Georgia Registered 501(c)(3) Nonprofit Project**

---

## What is VF501?

VF501 is a modern, auditable file archiver designed specifically for **charity organizations** protecting sensitive donor data and for **digital forensics professionals** who need verifiable, forensically clean evidence handling.

It combines:
- Best-in-class practical compression (`zstd` + content-defined deduplication)
- Strong, modern encryption (`XChaCha20-Poly1305` + `Argon2id`)
- Exhaustive forensic metadata capture (exceeds WinRAR, 7-Zip, and most forensic imagers)
- Beautiful, trustworthy user experience

---

## Key Features (15 Total)

### Core Capabilities
- **.vf501** (compressed) and **.vf501x** (encrypted + compressed) formats
- Always-encrypted filenames + metadata
- Full WinRAR-style feature parity + modern improvements
- Cross-platform static binaries

### Innovative & Forensic Features
1. **Forensic Timeline Export** — Plaso-compatible JSONL/CSV (loads directly in Autopsy)
2. **One-Click Evidence Package** — Signed manifest + PDF report + watermark
3. **Secure Source Wipe + Verification** — Multi-pass wipe with BLAKE3 confirmation
4. **Read-Only FUSE Mount** — Mount encrypted archives without full extraction
5. **Hardware-Backed Key Derivation** — YubiKey / age identity support
6. **Encrypted Filename/Metadata Search** — Zero-knowledge search in header
7. **Smart Profile Recommender** — Auto-suggests optimal compression/encryption
8. **Cross-Format Upgrade Import** — RAR/7z/zip → VF501 with metadata upgrade
9. **Forensic Sidecar Index** — FTK-style JSON/CSV/SQLite export
10. **Gentle 30-Day Donation Prompt** — Non-nagware, fully configurable

### Donor Appreciation ("Thank You") Features (Unlocked after donation)
11. **Advanced Dedup Visualizer** — Interactive treemap + sunburst
12. **Custom Branded Reports** — Add your logo + professional templates
13. **Donor Badge + Priority** — "Supporter" badge + 90-day prompts + priority support
14. **Early Access Lab** — Immediate access to experimental features
15. **"Charity Champion" Mode** — Special theme + animated impact counter

---

## Quick Start

### GUI (Recommended for most users)

```bash
# Download the latest release for your platform
# Windows: VF501-1.0.0-x86_64-pc-windows-msvc.exe
# Linux:  VF501-1.0.0-x86_64-unknown-linux-musl
# macOS:  VF501-1.0.0-x86_64-apple-darwin

# Run
./vf501-gui
```

### CLI

```bash
# Create encrypted archive
vf501 a -e --level 19 --forensic --wipe-source archive.vf501x /path/to/data

# Extract with forensic restore
vf501 x --forensic-restore archive.vf501x /destination

# Generate Plaso timeline
vf501 timeline archive.vf501x --output timeline.jsonl

# Create Evidence Package
vf501 evidence archive.vf501x --output evidence-package.pdf
```

---

## Installation

### From Source (Developers)

```bash
git clone https://github.com/vf501/vf501
cd vf501
cargo build --release
```

### Pre-built Binaries

Download from the [Releases](https://github.com/vf501/vf501/releases) page. All binaries are statically linked where possible and signed.

---

## Testing & Quality

VF501 maintains extremely high standards:

- **100% roundtrip fidelity** on forensic test corpus (NTFS ADS, ACLs, xattr, btime, sparse files, Unicode paths)
- **Property-based + fuzz testing** on format parser (minimum 1M iterations per release)
- **Cross-platform validation** on Windows NTFS, Linux ext4/xfs, macOS APFS
- **Security audit path** (planned NCC-style audit before v1.0)
- Full `cargo audit` + `cargo deny` + reproducible builds

See the [Development Guide](docs/DEVELOPMENT_GUIDE.md) for detailed testing strategy.

---

## Development Strategy & Contributing

We follow a **phased, gated development model**:

| Phase | Focus                              | Key Deliverables                     | Gate Criteria |
|-------|------------------------------------|--------------------------------------|-------------|
| 0     | Foundation & Hardening             | Repo, CI, logging, panic hooks       | `cargo test --all` + clippy clean |
| 1     | Core Engine                        | Compression, encryption, metadata    | 100% forensic roundtrip |
| 2     | CLI + Unique Features              | All 15 features + Plaso export       | Evil archive tests pass |
| 3     | GUI + Polish                       | Tauri interface, accessibility       | Screen reader + contrast AA |
| 4     | Advanced & Security                | Recovery, FUSE, supply-chain signing | External audit scope defined |
| 5     | Release Readiness                  | Docs, governance, reproducible builds| Full matrix + fuzz clean |

**Good First Issues** are labeled in the repo. We especially welcome help with:
- New compression profiles
- i18n / accessibility
- Plaso parser improvements
- Documentation

Please read [CONTRIBUTING.md](CONTRIBUTING.md) and the [Development Guide](docs/DEVELOPMENT_GUIDE.md) before opening a PR.

---

## Donation & Supporter Benefits

VF501 is developed and maintained by a **Georgia Registered 501(c)(3) Nonprofit**.

If you find VF501 useful, please consider supporting the project:

→ **[Donate at givebutter.com/VF-501](https://givebutter.com/VF-501)**

**As a thank you to our donors, we unlock these special features** to make your work even easier and more impactful:
- Advanced Dedup Visualizer (treemap + sunburst)
- Custom Branded Reports (your logo + templates)
- Donor Badge + 90-day prompts + priority support
- Early Access to experimental features
- "Charity Champion" Mode with animated impact counter

---

## License

**AGPLv3-or-later** — Strong copyleft chosen to protect the charity mission and encourage contributions.

---

## Links

- **Website**: https://vf501.org (coming soon)
- **Documentation**: [Full Plan](docs/DEVELOPMENT_PLAN.md) • [Development Guide](docs/DEVELOPMENT_GUIDE.md)
- **Source**: https://github.com/vf501/vf501
- **Issues & Support**: https://github.com/vf501/vf501/issues
- **Donations**: https://givebutter.com/VF-501

---

**VF501 — Protecting what matters, forensically.**

*Made with care by the VF501 Core Team and our wonderful donors.*
