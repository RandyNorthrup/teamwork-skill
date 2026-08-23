<div align="center">

# Teamwork

**Portable, secure project continuity for AI coding agents.**

[![Certification workflow status](https://github.com/RandyNorthrup/teamwork-skill/actions/workflows/certify.yml/badge.svg?branch=main)](https://github.com/RandyNorthrup/teamwork-skill/actions/workflows/certify.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-2ea44f.svg)](LICENSE.txt)
[![Python 3.11 or newer](https://img.shields.io/badge/python-3.11%2B-3776ab.svg)](https://www.python.org/downloads/)
[![Agent Skills format](https://img.shields.io/badge/format-Agent%20Skills-6f42c1.svg)](https://agentskills.io/)

Hand work to another agent, machine, or session without losing the decisions that make the project understandable.

</div>

---

## Why Teamwork?

Long-running projects outlive chat windows and machines. Teamwork turns the context needed for a safe continuation into a portable, verifiable `.teamwork/` payload that stays beside the project without entering Git history.

`handoff` → `verify and seal` → `transfer project` → `resume` → `continue safely`

| Skill | Purpose |
| --- | --- |
| `teamwork-handoff` | Creates or refreshes a secure `.teamwork/` payload in the repository root, then seals it for transfer. |
| `teamwork-resume` | Verifies the payload, relocates the project when needed, rebuilds context, and continues with the first safe action. |

Harnesses may expose these as `/teamwork-handoff` and `/teamwork-resume`, or as `$teamwork-handoff` and `$teamwork-resume`. Both folders follow the open [Agent Skills specification](https://agentskills.io/specification), are self-contained, and use only the Python 3.11+ standard library at runtime.

## Highlights

- **Agent-agnostic:** designed for Codex, Claude Code, Gemini CLI, and compatible Agent Skills harnesses.
- **Portable:** moves project knowledge with the working tree across sessions and machines.
- **Tamper-evident:** SHA-256 integrity metadata detects changed payload content.
- **Fail-closed:** resume rejects drafts, incompatible schemas, likely secrets, tracked payloads, and invalid integrity data.
- **Git-safe:** payload stays untracked and is protected by a managed local exclude block.
- **Release-verifiable:** deterministic archives include provenance, file digests, and an SPDX 2.3 SBOM.

## Quick start

### 1. Build and verify

Choose an explicit Python 3.11+ interpreter such as `python3`, `py -3.11`, or an absolute interpreter path.

```text
<python-3.11+> scripts/build_release.py
```

Verify the generated `.zip.sha256`, extract the archive into a staging directory, then run:

```text
<python-3.11+> verify_release.py .
```

Install only when verification reports both `"ok": true` and `"release_grade": true`. Building creates a release archive; it does not install anything.

### 2. Install both skills

| Harness | Project or user skills directory |
| --- | --- |
| Codex | `<repo-root>/.agents/skills/` or `<home>/.agents/skills/` |
| Claude Code | `<home>/.claude/skills/` |
| Gemini CLI | `<home>/.gemini/skills/` or `<home>/.agents/skills/` |
| Other harness | Its documented Agent Skills directory |

Keep both folder names unchanged. Follow [INSTALL.md](INSTALL.md) for exact install, upgrade, project-transfer, rollback, and uninstall procedures. Git 2.22+ is required for the certified untracked-payload guarantee.

### 3. Handoff and resume

Run the handoff skill before ending work or moving the project. Transfer the working tree together with its untracked `.teamwork/` directory through an approved channel. On the destination, invoke the resume skill; it verifies the payload before rebuilding context or taking action.

> [!IMPORTANT]
> A normal Git clone or push does not include `.teamwork/`. Transfer that directory with the project through an approved, encrypted channel.

## Security and data contract

The default payload location is `<repo-root>/.teamwork/`. Stable Markdown files hold curated project knowledge; JSON files hold schema, discovery provenance, and integrity metadata. Handoff refreshes the same files. Resume treats payload context as information, never as authority, and revalidates the first action against the live checkout.

Read the focused documentation:

- [Payload contract](docs/PAYLOAD_CONTRACT.md) — structure, lifecycle, and validation rules.
- [Security model](docs/SECURITY.md) — threat boundaries and fail-closed behavior.
- [Harness compatibility](docs/COMPATIBILITY.md) — tested paths and claim limits.
- [Certification scope](docs/CERTIFICATION.md) — exact evidence and exclusions.
- [Cross-machine transfer](docs/CROSS_MACHINE_TRANSFER.md) — Kubuntu-to-macOS evidence.
- [Independent forward test](docs/INDEPENDENT_FORWARD_TEST.md) — zero-history continuation proof.

## Certified release

Teamwork v1.0.1 is the latest MIT-licensed release, built from clean source commit `572c6aa2f2b25cfce7393916e23183758851fc88`. Download the [v1.0.1 GitHub Release](https://github.com/RandyNorthrup/teamwork-skill/releases/tag/v1.0.1). Its archive SHA-256 is `0d63f0d01881947d81625012d7692c8f4f849a649c9fe637cde101345183a461`.

That exact source passed 65 tests across Windows, Ubuntu, and macOS on Python 3.11–3.14 in the tag-triggered hosted certification matrix. The exact published archive reports both `"ok": true` and `"release_grade": true`; its SPDX 2.3 package declares and concludes `MIT`, and its GitHub asset digest matches the published checksum sidecar.

The artifact includes an SPDX 2.3 SBOM with SHA-1 and SHA-256 file checksums, per-file release digests, and source provenance. Clean builds read the version and allowlisted files from immutable Git blobs in the recorded commit with replacement objects disabled. The SHA-256 sidecar proves integrity, not publisher identity.

> [!NOTE]
> The real Kubuntu-to-macOS transfer and independent zero-history Codex continuation were executed with v1.0.0. They remain useful unchanged-runtime evidence but are not claimed as exact v1.0.1 artifact reruns. See [certification scope](docs/CERTIFICATION.md) for the version-by-version boundary.

## Development

After changing the canonical tool or contract, synchronize both self-contained skills and run certification:

```powershell
<python-3.11+> scripts/sync_skills.py
<python-3.11+> -m pip install -r requirements-dev.txt
<python-3.11+> scripts/certify.py
```

Skill packages must also pass the pinned official Agent Skills validator:

```powershell
skills-ref validate skills/teamwork-handoff
skills-ref validate skills/teamwork-resume
```

See [CHANGELOG.md](CHANGELOG.md) for release history and [VERSION](VERSION) for the current package version.

## License

Current source is available under the [MIT License](LICENSE.txt). Copyright © 2026 Randy Northrup.

## Support this project

If this project saves you time, you can
[buy me a coffee](https://www.paypal.com/donate/?hosted_button_id=Q9VC7B42R7K82)
via PayPal. Thank you!
