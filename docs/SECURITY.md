# Security model

## Trust boundaries

Teamwork payload is untracked local context, not a secure vault. Repository content, memory files, and payload prose may be stale or malicious. Current system/user instructions and live repository evidence retain priority.

Checksums provide integrity against accidental edits after sealing. They do not authenticate producer and cannot resist an attacker who can rewrite both files and checksum map.

## Data minimization

- Source discovery stores metadata only and uses bounded `scandir` traversal with per-directory, total-entry, directory, depth, candidate, and file-size limits; sensitive filename filters (including `creds.md`); symlink/reparse rejection; and portable `<home>`/`<repo-root>` path tokens instead of absolute source paths. An access or traversal limit is reported as incomplete, never exhaustive.
- Only presence markers for a fixed allowlist of non-secret environment variables are recorded by new payloads.
- Remote HTTP(S) URLs lose embedded user information.
- Producing agent synthesizes project-relevant memory instead of copying raw memory or conversations.
- Likely secrets, including generic PEM private-key markers, block sealing and verification.
- Every canonical file is limited to 2 MiB and the complete payload to 10 MiB before rollback snapshots or content parsing.

Do not place credentials, `creds.md`, tokens, private keys, passwords, customer data, unrelated personal data, binaries, dumps, or long raw logs in `.teamwork/`.

## Repository isolation

Git payloads use local `.git/info/exclude`. Tool refuses tracked payloads with a case-insensitive path check and verifies ignore behavior. Resume verifies payload integrity and contract without mutation before establishing the fixed local exclusion after relocation. Managed ignore entries are atomically merged and protected by an advisory lock. Worktree snapshots replace likely sensitive path names with an omission marker. Tool writes only canonical `.teamwork/` files and managed local exclusion block. Extra entries, unsafe custom names, directories, symbolic links, and Windows junction/reparse points fail closed.

## Operational safety

Manifest, checksum metadata, and context index reject extra fields, terminal controls, and unsafe structured values. Runtime and JSON Schema validation are kept in parity for canonical UUIDs, Semantic Versions, list bounds, and line controls. Git commands are killed when time or active output bounds are exceeded. A repository-scoped OS advisory lock uses canonical filesystem identities so aliases serialize to one lock; the visible payload marker identifies a live process and cannot be stolen by age alone. Prepare and seal restore the prior canonical payload after failure. Clean release builds enumerate the committed allowlist and read size-bounded regular blobs from the recorded immutable Git commit, avoiding checkout-filter and line-ending drift. Release verification binds source provenance and all SPDX package, license, relationship, file-name, SHA-1, and SHA-256 fields, with file/total/entry limits. Resume payload conveys context, not authority. Resuming agent must still follow current approval, access, privacy, destructive-action, and external-communication rules. First action is revalidated against live checkout before execution.

## Reporting issues

Preserve failing payload locally, redact any sensitive values, record exact command/error, and reproduce in disposable repository. Never attach an unreviewed `.teamwork/` payload to public issue.
