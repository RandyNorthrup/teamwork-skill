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

The live release candidate is `LocalE2ECertified` on Windows as of 2026-08-17 UTC. The pre-commit gate ran 51 tests, passed 50, and skipped one symbolic-link test because the local Windows token lacks symbolic-link privilege; the separate real Windows junction/reparse test passed. Branch coverage is 82.39%, above the enforced 80% threshold. Ruff, formatting, mypy, Draft 2020-12 schema validation, deterministic packaging, extracted release verification, and official SPDX validation passed.

Both skills also pass the current Codex `quick_validate.py` and `agentskills/skills-ref` pinned at commit `69ef37e9424c0a7ea9dd2293b559e43ec8176379`.

The candidate is not yet called `CrossPlatformCertified`, `CrossMachineTransferCertified`, or `IndependentAgentForwardTested`. Earlier evidence covered materially older bytes and is superseded. Final claims require one clean committed source identity, a rebuilt archive, Windows/Linux/macOS reruns, cross-machine transfer, and a new isolated forward-agent run against that exact archive.

## Required gates

1. Both skill packages pass Codex `quick_validate.py` and the official Agent Skills reference validator.
2. Canonical and embedded scripts, contract, and schema are byte-identical.
3. Manifest validates against bundled strict JSON Schema Draft 2020-12 and runtime invariants.
4. Payload preparation is idempotent and preserves curated content.
5. Git local exclusion works and tracked payload is rejected.
6. Required placeholders, likely secrets, `creds.md`, sensitive worktree names, extra entries, unsafe names/metadata, oversized payloads, and symlinks fail closed.
7. Seal produces ready revision and canonical checksums.
8. Tampering blocks resume even if attacker recomputes one checksum entry but violates schema.
9. Relocated payload derives new repository root and preserves first action.
10. Agent/harness source discovery is bounded, metadata-only, and reports changed/missing/new provenance on resume.
11. Unicode and spaces in repository paths work across CLI JSON output.
12. Bounded search rejects ambiguity and active lock rejects concurrent update.
13. Read-only synchronization check detects embedded-resource drift.
14. Release ZIP is deterministic, self-verifying, and runs after extraction.
15. Full suite passes on supported Python 3.11–3.14 and on Windows, Linux, and macOS.
16. Real sealed payload transfers between Git repositories on different machines and resumes under different producer/consumer harness identities without manual ignore setup.
17. A non-authoring harness installs and discovers both open-format packages.
18. SPDX 2.3 SBOM passes the official SPDX Python validator and its SHA-256 inventory exactly matches the release manifest.
19. Case-variant tracked payloads, multiple custom payload names, terminal controls, generic private-key markers, and Windows junction/reparse write redirection fail closed.
20. A fresh unrelated agent receives no hidden expected answer, resumes a sealed fixture through the released skill, completes real pending work, passes unchanged acceptance tests, and refreshes a verified ready payload.

Run `python scripts/certify.py`; use remote VM evidence or hosted CI for cross-platform claims. Repeat isolated fresh-agent forward testing after material resume-workflow changes.
