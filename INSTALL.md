# Install, upgrade, transfer, and uninstall

Teamwork requires Python 3.11 or newer and Git 2.22 or newer for the certified untracked-payload guarantee. In commands below, `<python-3.11+>` means an explicitly verified interpreter such as `python3`, `py -3.11`, or an absolute interpreter path; confirm it with `<python-3.11+> --version` first.

## Verify and extract a release

Download v1.0.0 ZIP and checksum from the [official GitHub Release](https://github.com/RandyNorthrup/teamwork-skill/releases/tag/v1.0.0). Confirm filenames are `teamwork-skills-1.0.0.zip` and `teamwork-skills-1.0.0.zip.sha256`.

1. Compare the downloaded ZIP SHA-256 with its `.zip.sha256` sidecar: use `Get-FileHash <archive> -Algorithm SHA256` on PowerShell, `sha256sum <archive>` on Linux, or `shasum -a 256 <archive>` on stock macOS.
2. Extract into a new staging directory. Do not merge an unverified archive directly into a live skills directory.
3. Call the extracted directory `<release-root>`. From it, run `<python-3.11+> verify_release.py .`. Install only when it reports both `"ok": true` and `"release_grade": true`. A valid development build with dirty or unavailable source provenance can report `ok:true` but is not a release-grade installation artifact.

The checksum detects corruption; it is not a publisher signature. Obtain the checksum through a trusted channel when authenticity matters.

## Install both skills

Preflight the destination before copying. If either `teamwork-handoff` or `teamwork-resume` already exists, stop and follow the upgrade procedure; never overlay an initial install. Stop active Teamwork operations and exit or pause any harness that automatically reloads the skills root. On the same filesystem as the skills root, create a unique `<install-transaction-root>` that is a sibling of or otherwise outside every live harness discovery root. Copy both complete directories from `<release-root>` beneath it with their final names, then verify before making either directory live:

```text
<python-3.11+> "<release-root>/verify_release.py" "<release-root>" --installed-skills-root "<install-transaction-root>"
```

Rename both verified directories into the skills root. If either rename fails, move any already-renamed directory back into `<install-transaction-root>` and leave no partial live install. Verify the live pair with the same command, replacing the last argument with `<skills-root>`, before restarting harness discovery. Keep both final names unchanged. Never stage beneath a recursively scanned skills root.

Teamwork is distributed under the MIT License. Keep the copyright and permission notice with copies or substantial portions of the software; see `LICENSE.txt`.

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

Verify and extract the new release as `<release-root>`. Stop active Teamwork operations and exit or pause automatic harness discovery. On the same filesystem as the skills root, create unique `<install-transaction-root>` and `<backup-root>` directories outside every live harness discovery root. Copy both new skill directories into `<install-transaction-root>` and verify them before changing the live installation:

```text
<python-3.11+> "<release-root>/verify_release.py" "<release-root>" --installed-skills-root "<install-transaction-root>"
```

Move each current skill directory into `<backup-root>`. If either old-live-to-backup rename fails, restore any directory already moved and do not start installation. Rename both verified new directories from `<install-transaction-root>` into the skills root. If either new-to-live rename fails, move any new live directory back out of the discovery root and restore both old directories. Verify the live pair by rerunning the command with `<skills-root>` as the last argument, then restart the harness and confirm discovery. If byte verification or discovery fails, remove both new directories from the live root and restore both backups together. Do not delete transaction or backup directories until both new skills are verified and discoverable. Each same-filesystem directory rename is atomic; explicit rollback keeps the two-skill release coherent across the multi-rename transaction.

Existing `.teamwork/` payloads remain repository-local. Verify them with the upgraded resume skill before trusting them.

## Transfer a project handoff

Transfer the project working tree together with its untracked `.teamwork/` directory. Normal Git clone/push does not include `.teamwork/`. Use an approved encrypted file-transfer channel and preserve filenames and bytes. On the destination, run resume with `--json`; it verifies integrity before adding the fixed local Git exclude block.

Do not transfer credential files, private keys, or unrelated agent logs with the payload.

## Uninstall

Stop active Teamwork operations, then remove both installed skill directories. This does not remove repository `.teamwork/` payloads or managed blocks in `.git/info/exclude`; retain those for later resume, or review and remove them separately when no handoff is needed. Deletion is intentionally not automated.
