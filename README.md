# Teamwork skills

Teamwork provides two agent-agnostic project continuity skills:

- `teamwork-handoff`: creates or refreshes secure `.teamwork/` payload in repository root, then seals it for transfer.
- `teamwork-resume`: verifies payload, relocates project from payload parent, rebuilds context, and continues first safe action.

Harnesses may expose skills as `/teamwork-handoff` and `/teamwork-resume`, or `$teamwork-handoff` and `$teamwork-resume`. Each folder under `skills/` conforms to the open Agent Skills format, is self-contained, and uses Python 3.11+ standard library only.

## Install

Build creates a release archive; it does not install anything. Select an explicit Python 3.11+ interpreter (`python3`, `py -3.11`, or an absolute interpreter path):

```text
<python-3.11+> scripts/build_release.py
```

Verify the `.zip.sha256`, extract to a staging directory, and run `<python-3.11+> verify_release.py .`. Install only when verification reports both `ok:true` and `release_grade:true`, then use the two-directory transaction in `INSTALL.md`. Keep folder names unchanged. For current Codex project installs use `<repo-root>/.agents/skills/`; for user installs use `<home>/.agents/skills/`.

See [INSTALL.md](INSTALL.md) for exact install, upgrade, project-transfer, and uninstall procedures. No third-party Python dependency is required at runtime. Git 2.22+ is required to certify payload remains untracked.

## Contract

Handoff payload always lives at `<repo-root>/.teamwork/` by default. Stable Markdown documents carry curated project knowledge; JSON files carry schema, discovery provenance, and SHA-256 integrity metadata. Handoff refreshes same files. Resume fails closed on drafts, tampering, incompatible schemas, likely secrets, or tracked payloads.

See [payload contract](docs/PAYLOAD_CONTRACT.md), [security model](docs/SECURITY.md), and [certification scope](docs/CERTIFICATION.md).
See [harness compatibility](docs/COMPATIBILITY.md) for Codex, Claude Code, Gemini CLI, and generic Agent Skills installation paths and tested claim boundaries.
See [independent forward-test evidence](docs/INDEPENDENT_FORWARD_TEST.md) for zero-history prompt controls, artifact hashes, unchanged-test proof, and claim limits.

The release includes an SPDX 2.3 software bill of materials with SHA-1 and SHA-256 file checksums, per-file release digests, source commit/dirty provenance, and a conservative all-rights-reserved license notice. Clean releases read the version and allowlisted files from immutable Git blobs in the recorded commit with replacement objects disabled, so checkout filters and local replacement refs cannot change artifact bytes. Certification validates the SBOM with the official SPDX Python tools. The SHA-256 sidecar provides integrity, not publisher authentication.

## Develop and certify

After changing canonical tool or contract, synchronize both self-contained skills:

```powershell
<python-3.11+> scripts/sync_skills.py
<python-3.11+> -m pip install -r requirements-dev.txt
<python-3.11+> scripts/certify.py
```

Skill packages must also pass the pinned official Agent Skills reference validator:

```powershell
skills-ref validate skills/teamwork-handoff
skills-ref validate skills/teamwork-resume
```
