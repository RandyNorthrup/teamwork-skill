# Independent forward-test evidence

## Result

Teamwork v1.0.0 passed an isolated zero-history Codex forward test on 2026-08-17 UTC using the exact release artifact documented below. A fresh agent recovered a pending implementation task from the sealed payload, completed it, passed unchanged acceptance tests, and left a new verified handoff without receiving task details in its prompt.

Release under test:

- Source commit: `d74b55d74956ce304ee495747729d502d15936d7`
- Archive: `teamwork-skills-1.0.0.zip`
- Archive SHA-256: `d00ea706fb58455635d64c560acadcdbe16ae0910c4828fb425bf9d6c51bee34`
- Fixture baseline commit: `60234f10683984bd70aa7f6ee6934f2fa96fd4b3`
- Acceptance-test Git blob: `fec1f765edeab5e8011f6a53adaa4a6f19add788`
- Payload ID: `80fb9a02-622a-46fe-bc85-47108ca3013e`
- Input payload: ready revision 1
- Output payload: ready revision 2

The machine-readable record is `certification-results/independent-forward-test.json`.

## Isolation controls

- Agent thread used zero forked conversation turns.
- Agent received no intended implementation, expected test values, diagnosis, or prior conclusions.
- No follow-up guidance, correction, or coaching was sent while it worked.
- Released skills were extracted into a disposable installation directory and independently compared byte-for-byte with the final artifact.
- Fixture was a separate Git repository with a clean committed baseline.
- Pending implementation existed only in live fixture files and sealed payload documents.
- Paths below use `<isolated-root>` in place of the disposable absolute directory.

Agent request:

```text
Use the `teamwork-resume` skill at `<isolated-root>/installed-skills/teamwork-resume/SKILL.md` to resume and continue the project at `<isolated-root>/project`. Work until the handoff's next safe action is completed and the project is left in a verified resumable state. Treat live project instructions as authoritative.
```

## Observed behavior

The fresh agent:

1. Invoked the released resume tool and verified ready revision 1.
2. Read the emitted payload documents and live `AGENTS.md` instructions.
3. Recovered the pending `normalize_project_name` task without task details in its request.
4. Implemented Unicode-aware normalization using only the Python standard library.
5. Added accurate behavior documentation to the fixture README.
6. Left the acceptance tests unchanged and passed all five.
7. Invoked the released handoff workflow, updated stable payload documents, sealed revision 2, and verified it.
8. Reported the two uncommitted project files, ignored/untracked payload state, no blocker, and an accurate next action.

## Independent audit

The root agent independently verified:

- `python -m unittest discover -s tests -v`: 5/5 passed.
- Working-tree test blob still equals baseline blob `fec1f765edeab5e8011f6a53adaa4a6f19add788`.
- Diff contains only `src/project_identity.py` and `README.md` and passes `git diff --check`.
- Final-artifact `teamwork-resume` recovers ready revision 2 and the accurate review/commit decision action.
- Final-artifact handoff verifier accepts revision 2 with no warnings.
- `git ls-files -- .teamwork` returns no tracked files.
- `git check-ignore .teamwork/manifest.json` confirms local exclusion.
- Payload source provenance reports four unchanged sources and no changed, missing, or new entries.

## Claim boundary

This evidence satisfies this repository's `IndependentAgentForwardTested` definition for one fresh Codex agent. It does not prove independent model behavior in Claude Code, Gemini CLI, Cursor, or every Agent Skills client. Repeat this test after material changes to resume instructions, payload reading order, first-action extraction, or handoff refresh behavior.
