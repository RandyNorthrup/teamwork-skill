---
name: teamwork-handoff
description: Build or refresh a secure, untracked, agent-agnostic project handoff payload in the repository root. Use when pausing work, changing agents or harnesses, transferring a project, preserving current implementation status, or invoking /teamwork-handoff or $teamwork-handoff. Capture live repository evidence, applicable project instructions, relevant agent memory provenance, decisions, blockers, validation, and one concrete resume action without copying secrets.
---

# Teamwork handoff

Create or update the canonical `.teamwork/` payload. Keep filenames stable. Treat live repository evidence as authoritative and memory as potentially stale.

## Workflow

1. Resolve repository root and read all applicable project instructions before changing files.
2. Identify current agent and harness. Use explicit, honest names; use `unknown` when unavailable.
3. Define `<skill-dir>` as the directory containing this `SKILL.md`. Select a Python 3.11+ executable (`python3`, `py -3.11`, or an absolute interpreter path). Run the bundled script from any working directory and request structured output:

```text
<python-3.11+> "<skill-dir>/scripts/teamwork_payload.py" prepare --repo "<repo-root>" --agent "<agent>" --harness "<harness>" --json
```

4. Read `.teamwork/SOURCES.md`. Inspect only candidates relevant to this project. Also inspect live code, repository docs, VCS status, and test artifacts needed to establish current truth.
5. Update existing payload documents in place:
   - `STATUS.md`: exact outcome, completed/in-progress work, blockers, and one concrete safe resume action.
   - `PROJECT.md`: purpose, boundaries, architecture, important paths, and proven commands.
   - `NEXT_STEPS.md`: ordered actions and observable done criteria.
   - `DECISIONS.md`: stable decision IDs, reasons, and evidence.
   - `VALIDATION.md`: narrow claims, exact commands/artifacts, results, times, and gaps.
   - `CONTEXT.md`: project-relevant synthesis from instructions and memory with source IDs and freshness caveats.
   - `ENVIRONMENT.md`: dependencies, services, permissions, and approval boundaries. Preserve generated markers.
6. Never add session-numbered duplicates. Preserve useful existing content and revise stale facts. Let preparation regenerate `WORKTREE.md`, `SOURCES.md`, `context-index.json`, `teamwork-manifest.schema.json`, generated Markdown blocks, and manifest facts.
7. Exclude credentials, `creds.md`, secrets, tokens, private keys, unrelated personal data, raw conversations, binaries, build output, and large logs. Never stage or commit `.teamwork/`.
8. Seal only after replacing every required placeholder:

```text
<python-3.11+> "<skill-dir>/scripts/teamwork_payload.py" seal --repo "<repo-root>" --json
<python-3.11+> "<skill-dir>/scripts/teamwork_payload.py" verify --repo "<repo-root>" --json
```

9. Report payload path, ready revision, validation scope, and any blockers. If sealing or verification fails, report payload as draft—not resumable.

## Rules

- Use repository parent of `.teamwork/` as project location; keep stored absolute root only as same-host hint.
- Use `.git/info/exclude` managed by script so payload remains local and untracked without changing shared repository ignore policy.
- Do not overclaim tests or certification. Record unverified platforms and external systems explicitly.
- Do not edit `manifest.json`, `checksums.json`, `context-index.json`, `teamwork-manifest.schema.json`, `WORKTREE.md`, or `SOURCES.md` manually.
- Use `--source-root <path>` only for an explicit additional instruction or memory directory within user-authorized scope.
- Require Python 3.11+ and Git 2.22+ for certified untracked behavior.
- Use `--allow-non-git` only when project is intentionally not a Git repository; state that untracked status cannot be certified.
- Treat any command failure as non-destructive: the tool restores the prior canonical payload. Do not delete a lock with a live or unknown owner.

Read [references/payload-contract.md](references/payload-contract.md) when diagnosing schema, compatibility, integrity, discovery, or manual-recovery issues.
