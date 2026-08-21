# Changelog

All notable changes use Semantic Versioning and are recorded here.

## Unreleased

## 1.0.1 - 2026-08-21

- Relicensed the repository under the MIT License and updated release SBOM generation and verification to bind the standard SPDX `MIT` identifier.
- Redesigned the README around the two-skill workflow, quick start, compatibility, security model, certification evidence, and clear release-license scope.
- Published repository with `main` as default branch and preserved `v1.0.0` tag on exact certified source.
- Fixed GitHub Actions pip-cache discovery for `requirements-dev.txt` and normalized Windows short/long temporary-path test aliases.
- Updated artifact upload to pinned `actions/upload-artifact` v7.0.1 for native Node.js 24 execution.
- Proved hosted 3-OS by 4-Python certification, open-format validation, and deterministic packaging in GitHub Actions run `32037272973`.
- Published stable/latest GitHub Release `v1.0.0` with exact certified ZIP and checksum sidecar; GitHub asset digest matches recorded archive SHA-256.

## 1.0.0 - 2026-08-17

- Initial production release of `teamwork-handoff` and `teamwork-resume`.
- Added canonical, untracked payload lifecycle; bounded agent-memory discovery; schema and checksum verification; relocation; source provenance; and transactional prepare/seal rollback.
- Added canonical repository and Git-exclude advisory locking, multi-payload ignore merging, verification that every canonical payload file is ignored, case-insensitive tracked-path rejection, bounded pre-mutation snapshots, active Git output limits, and Windows reparse-point defenses.
- Added strict runtime/schema parity, canonical UUID and Semantic Version checks, terminal-control rejection, and expanded private-key/token filtering.
- Added bounded `scandir` source/search traversal with honest incomplete-discovery signaling and non-Git operation even when an old Git is present.
- Added deterministic allowlisted release packaging from immutable Git blobs and committed VERSION with replacement objects disabled for clean cross-platform builds, double-captured development version/source provenance, recoverable ZIP/sidecar publication, exact installed-byte verification, fully bound SPDX 2.3 SBOM verification and official validation, and transactional install/upgrade/transfer/uninstall guidance.
- Added pinned multi-OS Python 3.11-3.14 CI, cross-platform certification tooling, and independent forward-test protocol.
- Added pinned JSON Schema typing stubs and portable Windows process-probe typing so the same strict mypy gate runs on Windows, Linux, and macOS.
- Accepted only the fixed macOS `/var` and `/tmp` compatibility aliases for release output while retaining fail-closed rejection of arbitrary linked output parents.
- Certified exact release bytes across Windows, Kubuntu, macOS, Python 3.11-3.14, official format/SBOM validation, Gemini discovery, cross-machine transfer, and a zero-history Codex forward test.
