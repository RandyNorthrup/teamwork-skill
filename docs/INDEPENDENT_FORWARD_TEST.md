# Independent forward-test evidence

## Result

The earlier Teamwork v1.0.0 release candidate passed one isolated zero-history Codex forward test on 2026-08-17 UTC. Material security, locking, schema, and release-verification changes were made afterward, so this result is historical protocol evidence only and does not certify the current candidate. A new run against the final clean-commit archive is required before restoring the `IndependentAgentForwardTested` claim.

Superseded release under test:

- Archive: `teamwork-skills-1.0.0.zip`
- SHA-256: `cdbcebc73d0c47150c1d5379beb617b33a230555ea7af5802a1b8829075718ff`
- Fixture baseline commit: `41ad455592f758aba1b79c71fdf2a839217b1b93`
- Acceptance-test Git blob: `fbf751920ccae84d9e26b73b40bd0d448320dfa2`
- Input payload: ready revision 3
- Output payload: ready revision 4

## Isolation controls

- Agent thread used no forked conversation turns.
- Agent received no intended implementation, expected test values, diagnosis, or prior conclusions.
- No follow-up guidance, correction, or coaching was sent while it worked.
- Released skills were extracted into a disposable installation directory.
- Fixture was a separate Git repository with a clean committed baseline.
- Pending implementation existed only in live fixture files and sealed payload documents.
- Paths below use `<isolated-root>` in place of the disposable absolute directory.

Agent request:

```text
Use the `teamwork-resume` skill at `<isolated-root>/installed-skills/teamwork-resume/SKILL.md` to resume and continue the project at `<isolated-root>/project`. Work until the handoff's next safe action is completed and the project is left in a verified resumable state. Treat live project instructions as authoritative.
```

## Observed behavior

The fresh agent:

1. Invoked the released resume tool and verified the ready payload.
2. Read the emitted payload documents and live project instructions.
3. Recovered the pending `normalize_project_name` implementation task without task details in its request.
4. Implemented the source function using Python standard library only.
5. Added accurate behavior documentation to the fixture README.
6. Left the acceptance tests unchanged and passed all five.
7. Invoked the released sibling handoff tool, updated stable payload documents, sealed revision 4, and verified it.
8. Reported the two uncommitted project files, ignored/untracked payload state, no blocker, and an accurate next action.

## Independent audit

Root agent independently verified:

- `python -m unittest discover -s tests -v`: 5/5 passed.
- Working-tree test blob equaled baseline blob `fbf751920ccae84d9e26b73b40bd0d448320dfa2`.
- Diff contained only `src/project_identity.py` and `README.md`.
- Released `teamwork-resume` recovered ready revision 4 and the accurate review/commit-if-requested action.
- Released handoff verifier accepted revision 4 with no warnings.
- `git ls-files -- .teamwork` returned no tracked files.
- `git check-ignore .teamwork/manifest.json` confirmed local exclusion.
- Payload source provenance reported 200 unchanged entries and no changed, missing, or new entries.

## Claim boundary

This evidence satisfies this repository's `IndependentAgentForwardTested` definition for one fresh Codex agent. It does not prove independent model behavior in Claude Code, Gemini CLI, Cursor, or every Agent Skills client. Repeat this test after material changes to resume instructions, payload reading order, first-action extraction, or handoff refresh behavior.
