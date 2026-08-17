# Install, upgrade, transfer, and uninstall

Teamwork requires Python 3.11 or newer. Git is required for the certified untracked-payload guarantee.

## Verify and extract a release

1. Compare the downloaded ZIP SHA-256 with its `.zip.sha256` sidecar (`Get-FileHash` on PowerShell or `sha256sum` on Unix).
2. Extract into a new staging directory. Do not merge an unverified archive directly into a live skills directory.
3. From the staging directory, run `<python-3.11+> verify_release.py .`. Continue only when it reports `"ok": true`.

The checksum detects corruption; it is not a publisher signature. Obtain the checksum through a trusted channel when authenticity matters.

## Install both skills

Copy the complete `teamwork-handoff` and `teamwork-resume` directories from staging into one supported skills root. Keep both names unchanged.

These copy/install instructions apply only to recipients authorized by the copyright holder or another applicable agreement; see `LICENSE.txt`.

- Codex project: `<repo-root>/.agents/skills/`
- Codex user: `<home>/.agents/skills/`
- Claude Code user: `<home>/.claude/skills/`
- Gemini CLI user: `<home>/.gemini/skills/` or `<home>/.agents/skills/`
- Other harness: its documented Agent Skills root

Restart or refresh the harness so it discovers the skills. Invoke the names shown by that harness (`$teamwork-handoff`/`$teamwork-resume` or slash equivalents).

- Codex: restart the session and confirm both `$teamwork-handoff` and `$teamwork-resume` are available.
- Claude Code: restart the session and confirm both slash commands are available.
- Gemini CLI: run `/skills reload`, then `/skills list`; workspace installs may require `/trust` and a restart.

## Upgrade

Verify and extract the new release into a fresh staging directory. Stop active Teamwork operations, back up both existing skill directories outside the skills root, then replace both installed skill directories as one operation. Never mix files from different versions. Verify the installed bytes against staging:

```text
<python-3.11+> "<staging>/verify_release.py" "<staging>" --installed-skills-root "<skills-root>"
```

If verification or harness discovery fails, remove both new directories and restore both backups together.

Existing `.teamwork/` payloads remain repository-local. Verify them with the upgraded resume skill before trusting them.

## Transfer a project handoff

Transfer the project working tree together with its untracked `.teamwork/` directory. Normal Git clone/push does not include `.teamwork/`. Use an approved encrypted file-transfer channel and preserve filenames and bytes. On the destination, run resume with `--json`; it verifies integrity before adding the fixed local Git exclude block.

Do not transfer credential files, private keys, or unrelated agent logs with the payload.

## Uninstall

Stop active Teamwork operations, then remove both installed skill directories. This does not remove repository `.teamwork/` payloads or managed blocks in `.git/info/exclude`; retain those for later resume, or review and remove them separately when no handoff is needed. Deletion is intentionally not automated.
