# Harness compatibility

Both Teamwork folders implement the [open Agent Skills specification](https://agentskills.io/specification): one `SKILL.md` entrypoint plus optional `scripts/` and `references/`. Vendor metadata under `agents/` is optional and does not change the portable workflow.

## Installation

Copy both directories without renaming them:

| Harness | User installation root | Direct invocation | Status |
| --- | --- | --- | --- |
| Codex | `<repo-root>/.agents/skills/` or `<home>/.agents/skills/` | `$teamwork-handoff`, `$teamwork-resume` | Current structure validated; fresh-agent rerun pending for final bytes |
| Claude Code | `~/.claude/skills/` | `/teamwork-handoff`, `/teamwork-resume` | Official layout-compatible; independent model run pending |
| Gemini CLI | `~/.gemini/skills/` or `~/.agents/skills/` | Ask Gemini to use named skill; activation requires consent | Prior workspace discovery passed; final-byte rerun pending |
| Other Agent Skills client | Client's documented skills root | Client-defined | Open-standard structure validated |

Project-scoped roots are harness-specific. Claude Code uses `.claude/skills/`; Gemini CLI uses `.gemini/skills/` or `.agents/skills/`. Keep payload at project root as `.teamwork/` regardless of skill installation location.

For reusable Codex distribution across teams, a plugin can package these two skills; the standalone ZIP remains the agent-agnostic distribution. See [installation procedures](../INSTALL.md).

## Claim boundaries

- Format compatibility means the official parser accepts both skill packages and the harness documents the same open layout.
- Execution compatibility means the bundled Python CLI completes handoff/resume on that operating system.
- Independent-agent compatibility requires a fresh agent to discover or invoke the installed skill and follow it without hidden expected-answer context.

The current candidate proves both packages pass Codex's local structural validator and the pinned official Agent Skills reference validator. Prior candidate bytes passed Gemini workspace discovery, cross-platform CLI execution, cross-machine transfer, current-session Codex dogfood, and a fresh zero-history Codex forward test, but material changes supersede those results until rerun. Independent behavior under Claude Code, Gemini CLI, and other clients remains unclaimed.
