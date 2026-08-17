# Harness compatibility

Both Teamwork folders implement the [open Agent Skills specification](https://agentskills.io/specification): one `SKILL.md` entrypoint plus optional `scripts/` and `references/`. Vendor metadata under `agents/` is optional and does not change the portable workflow.

## Installation

Copy both directories without renaming them:

| Harness | User installation root | Direct invocation | Exact v1.0.0 evidence |
| --- | --- | --- | --- |
| Codex | `<repo-root>/.agents/skills/` or `<home>/.agents/skills/` | `$teamwork-handoff`, `$teamwork-resume` | Both packages pass Codex structural validation; one zero-history agent completed and resealed a real fixture |
| Claude Code | `<home>/.claude/skills/` | `/teamwork-handoff`, `/teamwork-resume` | Layout-compatible; independent Claude model execution is not claimed |
| Gemini CLI 0.55.1 | `<home>/.gemini/skills/` or `<home>/.agents/skills/` | Ask Gemini to use the named skill; activation requires consent | `gemini skills list` discovered both exact artifact packages as enabled in a trusted disposable workspace |
| Other Agent Skills client | Client's documented skills root | Client-defined | Both packages pass the pinned official Agent Skills reference validator |

Project-scoped roots are harness-specific. Claude Code uses `.claude/skills/`; Gemini CLI uses `.gemini/skills/` or `.agents/skills/`. Keep payload at project root as `.teamwork/` regardless of skill installation location.

For reusable Codex distribution across teams, a plugin can package these two skills; the standalone ZIP remains the agent-agnostic distribution. See [installation procedures](../INSTALL.md).

## Exact artifact evidence

- Release source: `d74b55d74956ce304ee495747729d502d15936d7`
- Release SHA-256: `d00ea706fb58455635d64c560acadcdbe16ae0910c4828fb425bf9d6c51bee34`
- Official Agent Skills reference commit: `69ef37e9424c0a7ea9dd2293b559e43ec8176379`
- Gemini discovery report: `certification-results/gemini-cli-0.55.1-discovery.json`
- Fresh Codex evidence: `certification-results/independent-forward-test.json`

## Claim boundaries

- Format compatibility means the official parser accepts both skill packages and the harness documents the same open layout.
- Execution compatibility means the bundled Python CLI completes handoff/resume on that operating system.
- Discovery compatibility means the harness lists the installed package; it does not prove a model will follow every instruction correctly.
- Independent-agent compatibility requires a fresh agent to invoke the installed skill and follow it without hidden expected-answer context.

The current release proves open-format validation, Codex independent-agent execution, Gemini CLI discovery, and cross-platform CLI execution. Independent behavior under Claude Code, Gemini CLI models, and other clients remains unclaimed.
