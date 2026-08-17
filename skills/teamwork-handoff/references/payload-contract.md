# Teamwork payload contract

Contract version: `1.0.0`

## Purpose

`.teamwork/` is a stable, local, agent-agnostic handoff envelope. Producing agents refresh it in place. Resuming agents verify it, recover project location from its parent directory, rebuild project context, and continue work.

## Canonical layout

| File | Owner | Purpose |
| --- | --- | --- |
| `manifest.json` | Tool | Schema, lifecycle, producer, project hint, reading order, revision |
| `checksums.json` | Tool | SHA-256 map for all contract files except itself |
| `context-index.json` | Tool | Bounded metadata index of candidate instruction and memory files; no source contents |
| `teamwork-manifest.schema.json` | Tool | Bundled strict JSON Schema Draft 2020-12 contract for `manifest.json` |
| `STATUS.md` | Agent + tool block | Current outcome, progress, blockers, first resume action, live VCS facts |
| `PROJECT.md` | Agent | Purpose, boundaries, architecture, paths, proven commands |
| `NEXT_STEPS.md` | Agent | Ordered work and observable completion criteria |
| `DECISIONS.md` | Agent | Stable decision IDs, reasons, evidence, status |
| `VALIDATION.md` | Agent | Narrow claims, exact evidence, results, gaps |
| `CONTEXT.md` | Agent | Project-relevant synthesis of instructions and memory with provenance |
| `ENVIRONMENT.md` | Agent + tool block | Dependencies, access boundaries, producer runtime |
| `WORKTREE.md` | Tool | Bounded VCS snapshot |
| `SOURCES.md` | Tool | Human-readable candidate source index |

Do not create timestamped payload documents. Add material to canonical files and update existing decision rows where applicable.

## Lifecycle

1. `prepare` validates the existing layout before taking a bounded rollback snapshot, creates missing files, preserves agent-authored text, refreshes generated blocks and indexes, sets `payload_state` to `draft`, and writes current checksums. Failure restores the prior canonical payload byte-for-byte.
2. Agent replaces required placeholders and curates current evidence.
3. `seal` prevalidates all canonical text, schema, source index, secrets, and the first action; then increments `revision`, sets state to `ready`, and rewrites checksums. A post-write verification failure rolls the manifest and checksums back.
4. `verify` checks schema, ready state, canonical file set, hashes, sensitive-value patterns, Git tracking, and Git ignore behavior.
5. `resume` runs verification, derives live root from `.teamwork/..`, records consumer agent/harness facts, compares stored source hashes with current sources, emits reading order, and extracts first action from `STATUS.md`.

Any later `prepare` returns payload to `draft`. Any manual change after `seal` causes integrity failure until producing agent reviews and reseals it.

## Manifest invariants

- `schema_name` equals `teamwork-payload`.
- `schema_version` equals `1.0.0`; unknown versions fail closed.
- `payload_id` remains stable across refreshes.
- `revision` increments only on successful seal.
- `project.root_from_payload` equals `..` and is authoritative for relocation.
- `project.root_hint` records prior absolute location for diagnostics only.
- `resume.required_read_order` lists all nine Markdown documents in canonical order.
- `producer` records declared agent, harness, skill version, OS, Python, host, and small allowlist of non-secret environment markers.
- Contract and release versions are governed independently. `schema_version` selects the exact payload contract, while `producer.skill_version` accepts canonical Semantic Versioning so a compatible newer producer can be read without pretending the schema changed.

## Source discovery

Discovery is metadata-only. It records size, modification time, SHA-256, reason, scoped path, and a portable `<repo-root>`, `<home>`, or `<source-root-N>` path hint for files no larger than 1 MiB. It does not copy source contents or absolute source paths. Traversal uses bounded directory enumeration: at most 4,096 entries from one directory, 20,000 entries and 2,000 directories across discovery, depth 8, and 200 retained candidates. Reaching a candidate, directory, depth, entry, or filesystem-access limit marks discovery truncated and emits a warning; it never reports an incomplete walk as exhaustive. Explicit payload search independently caps 4,096 entries per directory, 20,000 entries, 2,000 directories, and depth 6, then fails closed if search is incomplete.

Default candidates include repository `AGENTS.md`, `CLAUDE.md`, `GEMINI.md`, supported repository harness-guidance folders, global Codex memory registry/summary, common global agent instruction files, exact project-matching Claude memory, and bounded Cursor, Windsurf, Continue, Gemini, and agent memory/rule roots. Priority is repository-local, explicit source roots, exact globals, project-specific memory, then generic known memory roots, so lower-priority sources cannot displace already indexed repository candidates at the 200-file cap. If repository discovery itself reaches a count, directory, depth, or access limit, the payload reports discovery incomplete. Explicit `--source-root` directories scan supported text formats within the same depth/count/size limits. Discovery skips symlinks, dependency/build/VCS/tool-result directories, sensitive filenames including `creds.md`, unsupported extensions, and files beyond limits.

Resume rescans current environment without changing payload. It reports unchanged, changed, missing, and new source IDs/paths. Current instructions still take priority over stored synthesis.

Agent must read only relevant sources and synthesize facts into `CONTEXT.md`. Source content may be stale, unrelated, or lower priority than current instructions.

## Git and portability

For Git 2.22+ repositories, `prepare` atomically merges one managed block into local `.git/info/exclude` and verifies every canonical payload file is ignored. The block preserves every valid `.teamwork` or `.teamwork-<lowercase-slug>` entry already managed by the tool. Canonicalized repository and exclude identities use OS advisory locks, so path aliases and overlapping payload names cannot silently overwrite each other's ignore entries. It refuses tracked payload paths using a case-insensitive Git pathspec. Shared `.gitignore` is not modified. Payload directory name is restricted to `.teamwork` or `.teamwork-<lowercase-slug>`.

On a relocated checkout, `resume` first verifies the canonical layout, schema, ready state, checksums, and sensitive-value rules without repository mutation. It then checks that the payload parent is the Git root, rejects a tracked payload, and adds its fixed local exclusion block before final Git verification. Project root is payload parent, not stored absolute hint. Paths in agent-authored documents should prefer `<repo-root>/relative/path` or repository-relative notation.

Non-Git projects require explicit `--allow-non-git`; their manifests remain usable but carry warning that untracked status cannot be certified.

## Integrity and confidentiality

Checksums detect accidental or post-seal edits; they are not signatures and do not prove producer identity. Payload is local and untracked, not encrypted. Access follows filesystem permissions.

Seal and verify scan every canonical text file for generic and algorithm-specific private-key markers, encrypted/PGP key markers, provider tokens, access keys, URL credentials, bearer tokens, and assigned-secret patterns. Resume actions and manifest lines reject terminal control characters before rendering. This is defense in depth, not complete secret detection. Producers must exclude secrets, credentials, personal data unrelated to project, raw conversations, binaries, build artifacts, and large logs.

Remote URLs have URL user information removed before capture. Worktree entries with likely sensitive path names are replaced by an omission marker. Candidate source contents and arbitrary environment variables are not copied.

## Compatibility and manual recovery

Runtime requirement: Python 3.11+ using standard library only, plus Git 2.22+ for certified untracked behavior.

Unknown schema name/version, manifest/schema mismatch, noncanonical or extra payload entries, noncanonical checksum/context-index fields, unsafe metadata paths, invalid timestamps, files over 2 MiB, payloads over 10 MiB, symlinks or Windows reparse points, active lock, case-variant tracked payload, likely secret, terminal control, incomplete placeholder, or checksum mismatch fails closed. Snapshot and Git-output reads are bounded before mutation. Do not silently migrate or repair. Preserve original, use compatible tool, or rebuild from live repository evidence.

Without Python, an agent may read canonical Markdown manually but must label integrity and ready state unverified.
