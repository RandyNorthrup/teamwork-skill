# Certification

## Claim levels

- `CodeValidated`: static compilation, strict schema/metadata checks, deterministic packaging, and unit tests pass.
- `LocalE2ECertified`: disposable Git repository proves prepare, curate, seal, verify, relocate, discover, and resume behavior on one OS/runtime.
- `CrossPlatformCertified`: same full suite passes on actual Windows, Linux, and macOS systems.
- `CrossMachineTransferCertified`: sealed payload produced on one machine/OS verifies and resumes on another machine/OS with producer/consumer provenance preserved.
- `OpenFormatValidated`: both packages pass the official Agent Skills reference validator and at least one non-authoring harness installs and discovers them.
- `IndependentAgentForwardTested`: fresh unrelated agent follows installed skill without hidden expected-answer context.

Do not claim higher level from documentation, simulated operating-system paths, declared agent labels, or unexecuted CI configuration.

## Current result

Teamwork v1.0.0 achieved all six claim levels above for this exact release:

- Release source commit: `d74b55d74956ce304ee495747729d502d15936d7`
- Archive: `teamwork-skills-1.0.0.zip`
- Archive SHA-256: `d00ea706fb58455635d64c560acadcdbe16ae0910c4828fb425bf9d6c51bee34`
- Source state: clean, committed, SHA-1 Git object format
- Release verifier: `ok:true`, `release_grade:true`, 14 payload files plus release manifest

The evidence and documentation commit follows the release source commit and does not alter the certified ZIP. A local `v1.0.0` tag identifies the release source commit.

### Executed platform and Python matrix

| Environment | Python | Tests | Expected skips | Branch coverage | Result |
| --- | --- | ---: | ---: | ---: | --- |
| Windows 11 host | 3.11.9 | 65 | 1 | 81.5867% | Pass |
| Windows 11 host | 3.12.10 | 65 | 1 | 81.5867% | Pass |
| Windows 11 host | 3.13.7 | 65 | 1 | 81.5867% | Pass |
| Windows 11 host | 3.14.0 | 65 | 1 | 81.5867% | Pass |
| Separate Windows 11 VM | 3.14.6 | 65 | 0 | 81.6846% | Pass |
| Kubuntu VM | 3.14.4 | 65 | 2 | 80.9500% | Pass |
| macOS VM | 3.14.7 | 65 | 2 | 80.9500% | Pass |

The four host-Windows runs skipped only directory-symlink creation because that token lacked `SeCreateSymbolicLinkPrivilege`; real Windows junction/reparse fail-closed and alias-lock tests passed. The separate Windows 11 VM had the needed capability and ran all 65 without a skip. Linux and macOS skipped only the two Windows-junction tests.

### Additional exact-artifact evidence

- Both skills pass Codex `quick_validate.py` and official `skills-ref` at pinned Agent Skills reference commit `69ef37e9424c0a7ea9dd2293b559e43ec8176379`.
- The release manifest and SPDX 2.3 SBOM pass the bundled verifier and official SPDX Python tools; every file digest is bound to the manifest.
- Gemini CLI 0.55.1 discovers both exact packages as enabled from `.agents/skills/` in a trusted disposable workspace.
- A zero-history Codex agent completed a real pending task, passed five unchanged acceptance tests, and refreshed a ready payload from revision 1 to 2.
- A Kubuntu producer payload transferred with its Git repository to a distinct macOS path, resumed with a different agent identity, completed and committed the safe action, and resealed the same payload ID from revision 1 to 2.
- Independent security, operability, and release audits found no unresolved blocking issue after the macOS and cross-platform typing fixes.

Machine-readable evidence is under `certification-results/`; `index.json` binds each report by SHA-256. Detailed forward-agent evidence is in [INDEPENDENT_FORWARD_TEST.md](INDEPENDENT_FORWARD_TEST.md), and transfer evidence is in [CROSS_MACHINE_TRANSFER.md](CROSS_MACHINE_TRANSFER.md).

## Required gates

1. Both skill packages pass the pinned official Agent Skills reference validator; local Codex `quick_validate.py` is an additional compatibility check when available.
2. Canonical and embedded scripts, contract, and schema are byte-identical.
3. Manifest validates against bundled strict JSON Schema Draft 2020-12 and runtime invariants.
4. Payload preparation is idempotent and preserves curated content.
5. Git local exclusion works and tracked payload is rejected.
6. Required placeholders, likely secrets, `creds.md`, sensitive worktree names, extra entries, unsafe names/metadata, oversized payloads, and symlinks fail closed.
7. Seal produces ready revision and canonical checksums.
8. Tampering blocks resume even if an attacker recomputes one checksum entry but violates schema.
9. Relocated payload derives the new repository root and preserves the first action.
10. Agent/harness source discovery is bounded, metadata-only, and reports changed/missing/new provenance on resume.
11. Unicode and spaces in repository paths work across CLI JSON output.
12. Bounded search rejects ambiguity and active lock rejects concurrent update.
13. Read-only synchronization check detects embedded-resource drift.
14. Release ZIP is deterministic, self-verifying, and runs after extraction.
15. Full suite passes across Python 3.11–3.14 and actual Windows, Linux, and macOS systems.
16. Real sealed payload transfers between Git repositories on different machines and resumes under different producer/consumer identities without manual ignore setup.
17. A non-authoring harness installs and discovers both open-format packages.
18. SPDX 2.3 SBOM passes the official SPDX Python validator and its SHA-256 inventory exactly matches the release manifest.
19. Case-variant tracked payloads, multiple custom payload names, terminal controls, generic private-key markers, and Windows junction/reparse write redirection fail closed.
20. A fresh unrelated agent receives no hidden expected answer, resumes a sealed fixture through the released skill, completes real pending work, passes unchanged acceptance tests, and refreshes a verified ready payload.

## Claim boundaries

- The checked-in GitHub Actions workflow declares the full three-OS by four-Python hosted matrix, but no hosted run is claimed because this repository has no configured remote. The table above is executed local/VM evidence.
- Cross-machine certification covers one Kubuntu-to-macOS route and one payload, not every transport or filesystem.
- Independent-agent evidence covers one fresh Codex agent. Gemini model behavior, Claude Code model behavior, and other clients remain unclaimed.
- Gemini evidence proves local discovery, not model execution.
- One missing producer-home source after cross-machine relocation was reported honestly; repository instructions remained present and unchanged.
- The SHA-256 sidecar proves integrity only. No publisher signature or public release publication is claimed.

Run `<python-3.11+> scripts/certify.py --require-clean --output <report.json>` from a clean committed checkout for a new candidate. Repeat VM, transfer, discovery, and fresh-agent evidence after any material runtime, package, or workflow change.
