from __future__ import annotations

import argparse
import gc
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker


ROOT = Path(__file__).resolve().parents[1]
CANONICAL = ROOT / "src" / "teamwork_payload.py"
PLACEHOLDER_RE = re.compile(r"\[Required:[^\]]+\]", re.IGNORECASE)
sys.path.insert(0, str((ROOT / "src").resolve()))
sys.path.insert(0, str((ROOT / "scripts").resolve()))
import build_release  # noqa: E402
import teamwork_payload as teamwork  # noqa: E402


class ContractUtilityTests(unittest.TestCase):
    def test_git_version_floor_and_alias_lock_identity(self) -> None:
        with mock.patch.object(
            teamwork,
            "run_git",
            return_value=subprocess.CompletedProcess(
                ["git", "--version"], 0, "git version 2.21.9\n", ""
            ),
        ):
            with self.assertRaises(teamwork.TeamworkError) as raised:
                teamwork.ensure_git_version(ROOT)
        self.assertIn("requires Git 2.22+", str(raised.exception))

        alias = ROOT / "src" / ".."
        self.assertEqual(
            teamwork.canonical_lock_identity("repository", ROOT),
            teamwork.canonical_lock_identity("repository", alias),
        )

        with tempfile.TemporaryDirectory() as temporary:
            non_git = Path(temporary)
            with (
                mock.patch.object(teamwork.shutil, "which", return_value="git"),
                mock.patch.object(
                    teamwork,
                    "run_git",
                    return_value=subprocess.CompletedProcess(
                        ["git", "rev-parse"], 128, "", "not a repository"
                    ),
                ) as run_git,
            ):
                root, is_git = teamwork.find_repo_root(non_git, allow_non_git=True)
            self.assertEqual(non_git.resolve(), root)
            self.assertFalse(is_git)
            self.assertEqual(
                mock.call(non_git.resolve(), "rev-parse", "--show-toplevel"),
                run_git.call_args,
            )
            with (
                mock.patch.object(teamwork.shutil, "which", return_value="git"),
                mock.patch.object(
                    teamwork,
                    "run_git",
                    return_value=subprocess.CompletedProcess(
                        ["git", "rev-parse"], 128, "", "not a repository"
                    ),
                ) as run_git,
            ):
                warnings_found = teamwork.verify_git_excluded(non_git, ".teamwork")
            self.assertIn("not a Git repository", warnings_found[0])
            self.assertEqual(1, run_git.call_count)

    def test_strict_metadata_timestamp_and_url_helpers(self) -> None:
        self.assertEqual(
            "2026-08-16T12:34:56Z",
            teamwork.strict_utc_timestamp("2026-08-16T12:34:56Z", "fixture").strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            ),
        )
        for invalid in (None, "2026-08-16 12:34:56Z", "2026-02-31T00:00:00Z"):
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.strict_utc_timestamp(invalid, "fixture")
        self.assertEqual(
            "", teamwork.validate_single_line("", "fixture", allow_empty=True)
        )
        for invalid in (
            None,
            "",
            "line\nbreak",
            "x" * 1025,
            "delete\x7f",
            "escape\x1b[31m",
            "c1\x9b31m",
        ):
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.validate_single_line(invalid, "fixture")
        self.assertIn(
            "github-fine-grained-token",
            teamwork.sensitive_rules("github_pat_abcdefghijklmnopqrstuvwxyz123456"),
        )
        self.assertEqual(
            "ssh:<local-or-opaque-remote-omitted>",
            teamwork.sanitize_url("ssh:/local/path"),
        )
        self.assertEqual("host:org/repo", teamwork.sanitize_url("user@host:org/repo"))
        self.assertEqual(
            "<sensitive remote omitted>",
            teamwork.sanitize_url("github_pat_abcdefghijklmnopqrstuvwxyz123456"),
        )
        self.assertEqual("plain-local-path", teamwork.sanitize_url("plain-local-path"))

    def test_render_parsing_and_controlled_error_helpers(self) -> None:
        generated = teamwork.replace_generated(
            f"before\n{teamwork.GENERATED_BEGIN}\nold\n{teamwork.GENERATED_END}\nafter\n",
            "new",
        )
        self.assertIn("\nnew\n", generated)
        for invalid in ("no block", f"{teamwork.GENERATED_BEGIN}\nnever closed"):
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.replace_generated(invalid, "new")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "STATUS.md"
            status.write_text("# Status\n", encoding="utf-8")
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.extract_resume_instruction(status)
            status.write_text("## Resume instruction\n\n## Next\n", encoding="utf-8")
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.extract_resume_instruction(status)
            status.write_text(
                "## Resume instruction\n" + ("x" * 8193) + "\n", encoding="utf-8"
            )
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.extract_resume_instruction(status)
            status.write_text(
                "## Resume instruction\nRun safe action.\x1b[31m\n", encoding="utf-8"
            )
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.extract_resume_instruction(status)
            invalid_json = root / "invalid.json"
            invalid_json.write_text("[]\n", encoding="utf-8")
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.load_json(invalid_json)
            payload_file = root / ".teamwork"
            payload_file.write_text("not a directory", encoding="utf-8")
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.payload_for(root, ".teamwork")
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.write_checksums(root)

    def test_context_index_rejects_noncanonical_metadata(self) -> None:
        invalid = {
            "candidates": [
                {
                    "id": "bad",
                    "scope": "unknown",
                    "path": "unknown:../escape\n",
                    "path_hint": "absolute-path",
                    "reason": "",
                    "size": True,
                    "modified_at": "yesterday",
                    "sha256": "bad",
                }
            ],
            "content_copied": True,
            "generated_at": "yesterday",
            "roots_scanned": ["absolute", "absolute"],
            "schema_version": "0",
            "truncated": "yes",
            "unexpected": True,
        }
        with self.assertRaises(teamwork.TeamworkError) as raised:
            teamwork.validate_context_index(invalid)
        message = str(raised.exception)
        self.assertIn("canonical context index", message)
        self.assertIn("invalid scope", message)
        self.assertIn("invalid SHA-256", message)

    def test_git_output_and_snapshot_reads_are_actively_bounded(self) -> None:
        previous = teamwork.MAX_GIT_OUTPUT_CHARS
        teamwork.MAX_GIT_OUTPUT_CHARS = 8
        try:
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always", ResourceWarning)
                with self.assertRaises(teamwork.TeamworkError) as raised:
                    teamwork.run_git(ROOT, "--version")
                gc.collect()
            self.assertFalse(
                [item for item in caught if item.category is ResourceWarning]
            )
            self.assertIn("output exceeds", str(raised.exception))
        finally:
            teamwork.MAX_GIT_OUTPUT_CHARS = previous

        with tempfile.TemporaryDirectory() as temporary:
            payload = Path(temporary) / ".teamwork"
            payload.mkdir()
            (payload / "STATUS.md").write_bytes(b"x" * 2_097_153)
            with self.assertRaises(teamwork.TeamworkError) as raised:
                teamwork.snapshot_payload(payload)
            self.assertIn("exceeds 2097152 bytes", str(raised.exception))

    def test_guidance_walk_reports_directory_and_depth_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "a" / "nested").mkdir(parents=True)
            (root / "b").mkdir()
            previous_dirs = teamwork.MAX_WALK_DIRS
            previous_depth = teamwork.MAX_SOURCE_DEPTH
            try:
                teamwork.MAX_WALK_DIRS = 1
                state = [False]
                list(teamwork.walk_guidance(root, truncation=state))
                self.assertTrue(state[0])

                teamwork.MAX_WALK_DIRS = previous_dirs
                teamwork.MAX_SOURCE_DEPTH = 0
                state = [False]
                list(teamwork.walk_guidance(root, truncation=state))
                self.assertTrue(state[0])
            finally:
                teamwork.MAX_WALK_DIRS = previous_dirs
                teamwork.MAX_SOURCE_DEPTH = previous_depth

    def test_unreadable_source_candidate_marks_discovery_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            guidance = root / "AGENTS.md"
            guidance.write_text("fixture\n", encoding="utf-8")
            incomplete = [False]
            with mock.patch.object(
                teamwork,
                "sha256_file",
                side_effect=teamwork.TeamworkError("fixture read denial"),
            ):
                self.assertIsNone(
                    teamwork.source_candidate(
                        guidance,
                        "repo",
                        root,
                        "fixture",
                        incomplete,
                    )
                )
            self.assertTrue(incomplete[0])

    def test_explicit_search_is_bounded_and_never_walks_ancestors(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / ".teamwork").mkdir()
            (root / ".teamwork" / "manifest.json").write_text("{}\n", encoding="utf-8")
            search = root / "child"
            (search / "one").mkdir(parents=True)
            args = argparse.Namespace(
                payload=None,
                payload_dir=".teamwork",
                repo=None,
                search_root=str(search),
            )
            with self.assertRaises(teamwork.TeamworkError) as raised:
                teamwork.locate_payload(args)
            self.assertIn("No .teamwork/manifest.json found", str(raised.exception))

            previous = teamwork.MAX_SEARCH_DIRS
            teamwork.MAX_SEARCH_DIRS = 1
            try:
                with self.assertRaises(teamwork.TeamworkError) as raised:
                    teamwork.locate_payload(args)
                self.assertIn("search exceeded", str(raised.exception))
            finally:
                teamwork.MAX_SEARCH_DIRS = previous

    def test_single_directory_entry_limits_bound_discovery_and_search(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index in range(3):
                (root / f"guide-{index}.md").write_text("fixture\n", encoding="utf-8")
            previous = teamwork.MAX_DIRECTORY_ENTRIES
            teamwork.MAX_DIRECTORY_ENTRIES = 2
            try:
                incomplete = [False]
                self.assertEqual(
                    [], list(teamwork.walk_guidance(root, truncation=incomplete))
                )
                self.assertTrue(incomplete[0])

                args = argparse.Namespace(
                    payload=None,
                    payload_dir=".teamwork",
                    repo=None,
                    search_root=str(root),
                )
                with self.assertRaises(teamwork.TeamworkError) as raised:
                    teamwork.locate_payload(args)
                self.assertIn("filesystem entry or access limit", str(raised.exception))
            finally:
                teamwork.MAX_DIRECTORY_ENTRIES = previous

    def test_candidate_cap_stops_lower_priority_discovery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repo"
            extra = Path(temporary) / "extra"
            root.mkdir()
            extra.mkdir()
            for index in range(5):
                (extra / f"guide-{index}.md").write_text("fixture\n", encoding="utf-8")
            previous = teamwork.MAX_SOURCES
            teamwork.MAX_SOURCES = 2
            try:
                candidates, truncated, _roots = teamwork.discover_sources(root, [extra])
            finally:
                teamwork.MAX_SOURCES = previous
            self.assertEqual(2, len(candidates))
            self.assertTrue(truncated)
            self.assertTrue(all(item["scope"] == "extra-1" for item in candidates))

    def test_release_pair_failure_restores_previous_files(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            output = root / "release.zip"
            sidecar = root / "release.zip.sha256"
            output.write_bytes(b"old archive")
            sidecar.write_bytes(b"old checksum")
            archive_temp = root / "new.zip"
            sidecar_temp = root / "new.sha256"
            archive_temp.write_bytes(b"new archive")
            sidecar_temp.write_bytes(b"new checksum")
            real_replace = build_release.os.replace
            failed_once = False

            def fail_sidecar_once(source: object, destination: object) -> None:
                nonlocal failed_once
                if Path(destination) == sidecar and not failed_once:
                    failed_once = True
                    raise OSError("fixture sidecar failure")
                real_replace(source, destination)

            with mock.patch.object(
                build_release.os, "replace", side_effect=fail_sidecar_once
            ):
                with self.assertRaises(RuntimeError):
                    build_release.commit_release_pair(
                        archive_temp, output, sidecar_temp, sidecar
                    )
            self.assertEqual(b"old archive", output.read_bytes())
            self.assertEqual(b"old checksum", sidecar.read_bytes())


class TeamworkPayloadE2E(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.base = Path(self.temp.name)
        self.home = self.base / "home"
        self.home.mkdir()
        self.repo = self.make_repo(self.base / "project Ω space")
        self.env = os.environ.copy()
        self.env["HOME"] = str(self.home)
        self.env["USERPROFILE"] = str(self.home)
        self.env["TEAMWORK_AGENT"] = "test-agent"
        self.env["TEAMWORK_HARNESS"] = "test-harness"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_repo(self, path: Path) -> Path:
        path.mkdir(parents=True)
        self.git(path, "init")
        self.git(path, "config", "user.email", "teamwork@example.invalid")
        self.git(path, "config", "user.name", "Teamwork Test")
        (path / "README.md").write_text("# Fixture\n", encoding="utf-8")
        self.git(path, "add", "README.md")
        self.git(path, "commit", "-m", "fixture")
        return path

    def git(self, repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["git", "-C", str(repo), *args],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            self.fail(f"git {' '.join(args)} failed:\n{result.stdout}\n{result.stderr}")
        return result

    def cli(
        self, *args: str, expected: int = 0, script: Path = CANONICAL
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [sys.executable, str(script), *args],
            cwd=self.repo,
            env=self.env,
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            expected,
            result.returncode,
            f"CLI returned {result.returncode}, expected {expected}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        return result

    @property
    def payload(self) -> Path:
        return self.repo / ".teamwork"

    def prepare(self, *extra_args: str) -> dict:
        result = self.cli("prepare", "--repo", str(self.repo), *extra_args, "--json")
        return json.loads(result.stdout)

    def complete_documents(self, payload: Path | None = None) -> None:
        payload = payload or self.payload
        for path in payload.glob("*.md"):
            text = path.read_text(encoding="utf-8")
            text = PLACEHOLDER_RE.sub("Verified fixture content", text)
            if path.name == "STATUS.md":
                text = text.replace(
                    "Verified fixture content", "Run the next safe fixture action.", 1
                )
            path.write_text(text, encoding="utf-8")

    def seal(self) -> dict:
        result = self.cli("seal", "--repo", str(self.repo), "--json")
        return json.loads(result.stdout)

    def test_prepare_is_idempotent_and_untracked(self) -> None:
        first = self.prepare()
        self.assertEqual("draft", first["state"])
        expected = {
            "STATUS.md",
            "PROJECT.md",
            "NEXT_STEPS.md",
            "DECISIONS.md",
            "VALIDATION.md",
            "CONTEXT.md",
            "ENVIRONMENT.md",
            "WORKTREE.md",
            "SOURCES.md",
            "manifest.json",
            "checksums.json",
            "context-index.json",
            "teamwork-manifest.schema.json",
        }
        self.assertEqual(expected, {path.name for path in self.payload.iterdir()})
        project = self.payload / "PROJECT.md"
        project.write_text(
            project.read_text(encoding="utf-8") + "\nPreserve me.\n", encoding="utf-8"
        )
        second = self.prepare()
        self.assertEqual(self.payload.resolve(), Path(second["payload"]).resolve())
        self.assertIn("Preserve me.", project.read_text(encoding="utf-8"))
        manifest = json.loads(
            (self.payload / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual(0, manifest["revision"])
        schema = json.loads(
            (self.payload / "teamwork-manifest.schema.json").read_text(encoding="utf-8")
        )
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(manifest)
        ignored = subprocess.run(
            [
                "git",
                "-C",
                str(self.repo),
                "check-ignore",
                "-q",
                ".teamwork/manifest.json",
            ],
            check=False,
        )
        self.assertEqual(0, ignored.returncode)
        status = self.git(
            self.repo, "status", "--short", "--untracked-files=all"
        ).stdout
        self.assertNotIn(".teamwork", status)

    def test_multiple_payload_names_remain_ignored(self) -> None:
        for name in (".teamwork-alpha", ".teamwork-beta"):
            prepared = self.cli(
                "prepare",
                "--repo",
                str(self.repo),
                "--payload-dir",
                name,
                "--json",
            )
            self.assertEqual("draft", json.loads(prepared.stdout)["state"])
        exclude = self.git(self.repo, "rev-parse", "--git-path", "info/exclude")
        exclude_path = Path(exclude.stdout.strip())
        if not exclude_path.is_absolute():
            exclude_path = self.repo / exclude_path
        exclude_text = exclude_path.read_text(encoding="utf-8")
        self.assertIn("/.teamwork-alpha/", exclude_text)
        self.assertIn("/.teamwork-beta/", exclude_text)
        for name in (".teamwork-alpha", ".teamwork-beta"):
            ignored = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo),
                    "check-ignore",
                    "-q",
                    f"{name}/manifest.json",
                ],
                check=False,
            )
            self.assertEqual(0, ignored.returncode)

    def test_explicit_custom_payload_infers_name_without_redundant_option(self) -> None:
        name = ".teamwork-custom"
        self.cli("prepare", "--repo", str(self.repo), "--payload-dir", name)
        custom = self.repo / name
        self.complete_documents(custom)
        self.cli("seal", "--payload", str(custom))
        verified = self.cli("verify", "--payload", str(custom), "--json")
        self.assertEqual("ready", json.loads(verified.stdout)["state"])

    def test_selectively_unignored_canonical_file_fails_verification(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        exclude_result = self.git(self.repo, "rev-parse", "--git-path", "info/exclude")
        exclude = Path(exclude_result.stdout.strip())
        if not exclude.is_absolute():
            exclude = self.repo / exclude
        exclude.write_text(
            "/.teamwork/*\n!/.teamwork/STATUS.md\n",
            encoding="utf-8",
        )
        failed = self.cli("verify", "--repo", str(self.repo), expected=2)
        self.assertIn(".teamwork/STATUS.md", failed.stderr)

    def test_seal_rejects_incomplete_payload(self) -> None:
        self.prepare()
        result = self.cli("seal", "--repo", str(self.repo), "--json", expected=2)
        error = json.loads(result.stderr)
        self.assertIn("Required payload content is incomplete", error["error"])
        manifest = json.loads(
            (self.payload / "manifest.json").read_text(encoding="utf-8")
        )
        self.assertEqual("draft", manifest["payload_state"])

    def test_seal_rejects_likely_secret(self) -> None:
        self.prepare()
        self.complete_documents()
        context = self.payload / "CONTEXT.md"
        context.write_text(
            context.read_text(encoding="utf-8") + "\npassword=abcdefghijklmnop\n",
            encoding="utf-8",
        )
        result = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("Likely sensitive values", result.stderr)

    def test_handoff_resume_and_tamper_detection(self) -> None:
        self.prepare()
        self.complete_documents()
        sealed = self.seal()
        self.assertEqual("ready", sealed["state"])
        self.assertEqual(1, sealed["revision"])
        result = self.cli("resume", "--repo", str(self.repo), "--json")
        resumed = json.loads(result.stdout)
        self.assertEqual(str(self.repo.resolve()), resumed["project_root"])
        self.assertEqual("Run the next safe fixture action.", resumed["first_action"])
        self.assertFalse(resumed["relocated"])
        self.assertEqual("test-agent", resumed["consumer"]["agent"])
        with (self.payload / "STATUS.md").open("a", encoding="utf-8") as handle:
            handle.write("\nTampered.\n")
        failed = self.cli("resume", "--repo", str(self.repo), expected=2)
        self.assertIn("SHA-256 mismatch", failed.stderr)

    def test_manifest_contract_tamper_fails_even_with_updated_hash(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        manifest_path = self.payload / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["unexpected"] = True
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksums_path = self.payload / "checksums.json"
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        checksums["files"]["manifest.json"] = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        checksums_path.write_text(
            json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        failed = self.cli("resume", "--repo", str(self.repo), expected=2)
        self.assertIn("Manifest contract validation failed", failed.stderr)

    def test_ready_manifest_requires_valid_sealed_timestamp(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        manifest_path = self.payload / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["sealed_at"] = "not-a-timestamp"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksums_path = self.payload / "checksums.json"
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        checksums["files"]["manifest.json"] = hashlib.sha256(
            manifest_path.read_bytes()
        ).hexdigest()
        checksums_path.write_text(
            json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        failed = self.cli("resume", "--repo", str(self.repo), expected=2)
        self.assertIn("sealed_at must be a UTC RFC 3339 timestamp", failed.stderr)

    def test_manifest_manual_and_schema_validation_stay_in_parity(self) -> None:
        self.prepare()
        manifest = json.loads(
            (self.payload / "manifest.json").read_text(encoding="utf-8")
        )
        schema = json.loads(
            (self.payload / "teamwork-manifest.schema.json").read_text(encoding="utf-8")
        )
        validator = Draft202012Validator(schema, format_checker=FormatChecker())

        compatible = json.loads(json.dumps(manifest))
        compatible["producer"]["skill_version"] = "1.0.1+build.5"
        teamwork.validate_existing_manifest(compatible)
        self.assertEqual([], list(validator.iter_errors(compatible)))

        for version in ("1.0.0-01", "1.0"):
            candidate = json.loads(json.dumps(manifest))
            candidate["producer"]["skill_version"] = version
            with self.assertRaises(teamwork.TeamworkError):
                teamwork.validate_existing_manifest(candidate)
            self.assertTrue(list(validator.iter_errors(candidate)))

        too_many_remotes = json.loads(json.dumps(manifest))
        too_many_remotes["project"]["vcs"]["remotes"] = [
            f"remote-{index}" for index in range(101)
        ]
        with self.assertRaises(teamwork.TeamworkError):
            teamwork.validate_existing_manifest(too_many_remotes)
        self.assertTrue(list(validator.iter_errors(too_many_remotes)))

        braced_uuid = json.loads(json.dumps(manifest))
        braced_uuid["payload_id"] = "{" + braced_uuid["payload_id"] + "}"
        with self.assertRaises(teamwork.TeamworkError):
            teamwork.validate_existing_manifest(braced_uuid)
        self.assertTrue(list(validator.iter_errors(braced_uuid)))

        future_uuid = json.loads(json.dumps(manifest))
        future_uuid["payload_id"] = "12345678-1234-7234-9234-123456789abc"
        with self.assertRaises(teamwork.TeamworkError):
            teamwork.validate_existing_manifest(future_uuid)
        self.assertTrue(list(validator.iter_errors(future_uuid)))

        escaped_remote = json.loads(json.dumps(manifest))
        escaped_remote["project"]["vcs"]["remotes"] = ["origin\x1b[31m"]
        with self.assertRaises(teamwork.TeamworkError):
            teamwork.validate_existing_manifest(escaped_remote)
        self.assertTrue(list(validator.iter_errors(escaped_remote)))

    def test_context_index_rejects_traversal_even_with_updated_checksum(self) -> None:
        (self.repo / "AGENTS.md").write_text("fixture instructions\n", encoding="utf-8")
        self.prepare()
        self.complete_documents()
        self.seal()
        index_path = self.payload / "context-index.json"
        index = json.loads(index_path.read_text(encoding="utf-8"))
        candidate = index["candidates"][0]
        candidate["path"] = "repo:../escape.md"
        candidate["path_hint"] = "<repo-root>/../escape.md"
        candidate["id"] = hashlib.sha256(candidate["path"].encode("utf-8")).hexdigest()[
            :12
        ]
        index_path.write_text(
            json.dumps(index, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        checksums_path = self.payload / "checksums.json"
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        checksums["files"]["context-index.json"] = hashlib.sha256(
            index_path.read_bytes()
        ).hexdigest()
        checksums_path.write_text(
            json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        failed = self.cli("resume", "--repo", str(self.repo), expected=2)
        self.assertIn("unsafe scoped path", failed.stderr)

    def test_checksum_metadata_rejects_extra_fields(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        checksums_path = self.payload / "checksums.json"
        checksums = json.loads(checksums_path.read_text(encoding="utf-8"))
        checksums["unexpected"] = True
        checksums_path.write_text(
            json.dumps(checksums, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        failed = self.cli("resume", "--repo", str(self.repo), expected=2)
        self.assertIn("Checksum metadata fields", failed.stderr)

    def test_payload_file_size_limit_fails_closed(self) -> None:
        self.prepare()
        (self.payload / "PROJECT.md").write_text("x" * 2_097_153, encoding="utf-8")
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("Payload file exceeds 2097152 bytes", failed.stderr)

    def test_resume_accepts_path_inside_repository(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        nested = self.repo / "src" / "nested"
        nested.mkdir(parents=True)
        result = self.cli("resume", "--repo", str(nested), "--json")
        resumed = json.loads(result.stdout)
        self.assertEqual(str(self.repo.resolve()), resumed["project_root"])

    def test_resume_revalidates_source_provenance_and_consumer(self) -> None:
        codex_memory = self.home / ".codex" / "memories"
        codex_memory.mkdir(parents=True)
        memory = codex_memory / "MEMORY.md"
        memory.write_text("initial memory\n", encoding="utf-8")
        self.prepare()
        self.complete_documents()
        self.seal()
        memory.write_text("changed memory\n", encoding="utf-8")
        (self.repo / "AGENTS.md").write_text("new repo guidance\n", encoding="utf-8")
        result = self.cli(
            "resume",
            "--repo",
            str(self.repo),
            "--agent",
            "new-agent",
            "--harness",
            "new-harness",
            "--json",
        )
        resumed = json.loads(result.stdout)
        self.assertEqual("new-agent", resumed["consumer"]["agent"])
        self.assertEqual("new-harness", resumed["consumer"]["harness"])
        provenance = resumed["source_provenance"]
        self.assertEqual(1, provenance["changed_count"])
        self.assertEqual(1, provenance["new_count"])
        self.assertEqual(0, provenance["missing_count"])

    def test_relocated_payload_uses_new_parent_and_bounded_search(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        destination = self.make_repo(self.base / "workspace" / "relocated")
        shutil.copytree(self.payload, destination / ".teamwork")
        unprotected = self.cli(
            "verify", "--payload", str(destination / ".teamwork"), expected=2
        )
        self.assertIn(
            "does not ignore every canonical payload file", unprotected.stderr
        )
        exclude_result = self.git(
            destination, "rev-parse", "--git-path", "info/exclude"
        )
        exclude = Path(exclude_result.stdout.strip())
        if not exclude.is_absolute():
            exclude = destination / exclude
        exclude_before = exclude.read_bytes()
        rejected_consumer = self.cli(
            "resume",
            "--payload",
            str(destination / ".teamwork"),
            "--agent",
            "github_pat_abcdefghijklmnopqrstuvwxyz123456",
            expected=2,
        )
        self.assertIn("resembles a secret", rejected_consumer.stderr)
        self.assertEqual(exclude_before, exclude.read_bytes())
        result = self.cli(
            "resume", "--search-root", str(self.base / "workspace"), "--json"
        )
        resumed = json.loads(result.stdout)
        self.assertEqual(str(destination.resolve()), resumed["project_root"])
        self.assertTrue(resumed["relocated"])
        ignored = subprocess.run(
            [
                "git",
                "-C",
                str(destination),
                "check-ignore",
                "-q",
                ".teamwork/manifest.json",
            ],
            check=False,
        )
        self.assertEqual(0, ignored.returncode)

    def test_bounded_search_rejects_multiple_payloads(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        workspace = self.base / "many"
        for name in ("one", "two"):
            destination = self.make_repo(workspace / name)
            shutil.copytree(self.payload, destination / ".teamwork")
            exclude_result = subprocess.run(
                [
                    "git",
                    "-C",
                    str(destination),
                    "rev-parse",
                    "--git-path",
                    "info/exclude",
                ],
                text=True,
                capture_output=True,
                check=True,
            )
            exclude = Path(exclude_result.stdout.strip())
            if not exclude.is_absolute():
                exclude = destination / exclude
            with exclude.open("a", encoding="utf-8") as handle:
                handle.write("\n/.teamwork/\n")
        failed = self.cli("resume", "--search-root", str(workspace), expected=2)
        self.assertIn("Multiple payloads found", failed.stderr)

    def test_discovery_is_metadata_only_and_filters_sensitive_names(self) -> None:
        codex_memory = self.home / ".codex" / "memories"
        codex_memory.mkdir(parents=True)
        (codex_memory / "MEMORY.md").write_text(
            "project fixture memory\n", encoding="utf-8"
        )
        claude = self.repo / ".claude"
        claude.mkdir()
        (claude / "guide.md").write_text("project guidance\n", encoding="utf-8")
        (claude / "token.md").write_text("must never be indexed\n", encoding="utf-8")
        (claude / "creds.md").write_text("must never be indexed\n", encoding="utf-8")
        self.prepare()
        index = json.loads(
            (self.payload / "context-index.json").read_text(encoding="utf-8")
        )
        paths = {item["path"] for item in index["candidates"]}
        self.assertIn("home:.codex/memories/MEMORY.md", paths)
        self.assertIn("repo:.claude/guide.md", paths)
        self.assertNotIn("repo:.claude/token.md", paths)
        self.assertNotIn("repo:.claude/creds.md", paths)
        self.assertFalse(index["content_copied"])
        serialized = json.dumps(index)
        self.assertNotIn("project fixture memory", serialized)
        self.assertNotIn(str(self.home), serialized)
        self.assertIn("<home>/.codex/memories/MEMORY.md", serialized)

    def test_explicit_harness_root_scans_generic_guidance_but_not_credentials(
        self,
    ) -> None:
        harness = self.base / "custom harness"
        harness.mkdir()
        (harness / "project-notes.md").write_text("useful context\n", encoding="utf-8")
        (harness / "creds.md").write_text(
            "password=not-for-payload\n", encoding="utf-8"
        )
        self.prepare("--source-root", str(harness))
        index = json.loads(
            (self.payload / "context-index.json").read_text(encoding="utf-8")
        )
        paths = {item["path"] for item in index["candidates"]}
        self.assertIn("extra-1:project-notes.md", paths)
        self.assertNotIn("extra-1:creds.md", paths)
        self.assertNotIn(str(harness), json.dumps(index))
        self.assertIn("<source-root-1>/project-notes.md", json.dumps(index))

    def test_worktree_snapshot_omits_sensitive_path_names(self) -> None:
        (self.repo / "customer credentials.txt").write_text(
            "not payload content\n", encoding="utf-8"
        )
        (self.repo / "api-token.env").write_text(
            "not payload content\n", encoding="utf-8"
        )
        self.prepare()
        manifest_text = (self.payload / "manifest.json").read_text(encoding="utf-8")
        worktree_text = (self.payload / "WORKTREE.md").read_text(encoding="utf-8")
        for sensitive_name in ("customer credentials.txt", "api-token.env"):
            self.assertNotIn(sensitive_name, manifest_text)
            self.assertNotIn(sensitive_name, worktree_text)
        self.assertIn("<sensitive path omitted>", manifest_text)
        self.assertIn("<sensitive path omitted>", worktree_text)

    def test_git_remote_credentials_are_redacted(self) -> None:
        self.git(
            self.repo,
            "remote",
            "add",
            "origin",
            "https://agent:fake-password@example.invalid/org/repo.git",
        )
        self.git(
            self.repo, "remote", "add", "mirror", "agent@example.invalid:org/repo.git"
        )
        self.git(
            self.repo,
            "remote",
            "add",
            "ipv6",
            "https://agent:fake-password@[2001:db8::1]:8443/org/repo.git?token=secret",
        )
        self.git(self.repo, "remote", "add", "malformed", "https://[invalid")
        self.prepare()
        manifest_text = (self.payload / "manifest.json").read_text(encoding="utf-8")
        self.assertIn("https://example.invalid/org/repo.git", manifest_text)
        self.assertIn("example.invalid:org/repo.git", manifest_text)
        self.assertIn("https://[2001:db8::1]:8443/org/repo.git", manifest_text)
        self.assertIn("<malformed remote omitted>", manifest_text)
        self.assertNotIn("fake-password", manifest_text)
        self.assertNotIn("agent@", manifest_text)
        self.assertNotIn("token=secret", manifest_text)

    def test_git_index_failure_does_not_modify_exclude(self) -> None:
        exclude_result = self.git(self.repo, "rev-parse", "--git-path", "info/exclude")
        exclude = Path(exclude_result.stdout.strip())
        if not exclude.is_absolute():
            exclude = self.repo / exclude
        before = exclude.read_bytes()
        git_dir = Path(self.git(self.repo, "rev-parse", "--git-dir").stdout.strip())
        if not git_dir.is_absolute():
            git_dir = self.repo / git_dir
        (git_dir / "index").write_bytes(b"corrupt index")
        failed = self.cli("prepare", "--repo", str(self.repo), expected=2)
        self.assertIn("Cannot verify Git tracking state", failed.stderr)
        self.assertEqual(before, exclude.read_bytes())

    def test_fresh_lock_and_path_traversal_fail_closed(self) -> None:
        self.prepare()
        lock = self.payload / ".lock"
        lock.write_text(
            f"pid={os.getpid()} token={'a' * 32} created=2026-01-01T00:00:00Z\n",
            encoding="utf-8",
        )
        locked = self.cli("prepare", "--repo", str(self.repo), expected=2)
        self.assertIn("already in progress", locked.stderr)
        lock.unlink()
        escaped = self.cli(
            "prepare",
            "--repo",
            str(self.repo),
            "--payload-dir",
            "../escape",
            expected=2,
        )
        self.assertIn("must be .teamwork", escaped.stderr)
        self.assertFalse((self.repo.parent / "escape").exists())

    def test_dead_lock_is_recovered_but_unknown_lock_fails_closed(self) -> None:
        self.prepare()
        lock = self.payload / ".lock"
        lock.write_text(
            f"pid=2147483647 token={'b' * 32} created=2026-01-01T00:00:00Z\n",
            encoding="utf-8",
        )
        recovered = self.cli("prepare", "--repo", str(self.repo), "--json")
        self.assertEqual("draft", json.loads(recovered.stdout)["state"])
        lock.write_text("unknown owner\n", encoding="utf-8")
        failed = self.cli("prepare", "--repo", str(self.repo), expected=2)
        self.assertIn("unknown owner", failed.stderr)

    def test_live_concurrent_process_holds_payload_lock(self) -> None:
        self.prepare()
        code = (
            "import sys,time; "
            f"sys.path.insert(0, {str((ROOT / 'src').resolve())!r}); "
            "import teamwork_payload as t; "
            f"p=t.Path({str(self.payload)!r}); "
            "cm=t.payload_lock(p); cm.__enter__(); "
            "print('LOCKED', flush=True); time.sleep(2); cm.__exit__(None,None,None)"
        )
        holder = subprocess.Popen(
            [sys.executable, "-c", code],
            text=True,
            encoding="utf-8",
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            assert holder.stdout is not None
            self.assertEqual("LOCKED", holder.stdout.readline().strip())
            failed = self.cli("prepare", "--repo", str(self.repo), expected=2)
            self.assertIn("already in progress", failed.stderr)
        finally:
            stdout, stderr = holder.communicate(timeout=5)
            self.assertEqual(0, holder.returncode, stdout + stderr)

    def test_invalid_explicit_payload_cannot_mutate_git_exclude(self) -> None:
        source = self.repo / "src"
        source.mkdir()
        (source / "module.py").write_text("value = 1\n", encoding="utf-8")
        exclude_result = self.git(self.repo, "rev-parse", "--git-path", "info/exclude")
        exclude = Path(exclude_result.stdout.strip())
        if not exclude.is_absolute():
            exclude = self.repo / exclude
        before = exclude.read_bytes()
        failed = self.cli("resume", "--payload", str(source), expected=2)
        self.assertIn("Payload directory must be", failed.stderr)
        self.assertEqual(before, exclude.read_bytes())
        self.assertIn("?? src/", self.git(self.repo, "status", "--short").stdout)

    def test_failed_prepare_restores_ready_payload_byte_for_byte(self) -> None:
        self.prepare()
        self.complete_documents()
        self.seal()
        before = {path.name: path.read_bytes() for path in self.payload.iterdir()}
        failed = self.cli(
            "prepare",
            "--repo",
            str(self.repo),
            "--agent",
            "github_pat_abcdefghijklmnopqrstuvwxyz123456",
            expected=2,
        )
        self.assertIn("resembles a secret", failed.stderr)
        after = {path.name: path.read_bytes() for path in self.payload.iterdir()}
        self.assertEqual(before, after)
        self.assertEqual(
            "ready",
            json.loads((self.payload / "manifest.json").read_text())["payload_state"],
        )

    def test_failed_first_prepare_restores_git_exclude(self) -> None:
        exclude_result = self.git(self.repo, "rev-parse", "--git-path", "info/exclude")
        exclude = Path(exclude_result.stdout.strip())
        if not exclude.is_absolute():
            exclude = self.repo / exclude
        before = exclude.read_bytes()
        failed = self.cli(
            "prepare",
            "--repo",
            str(self.repo),
            "--agent",
            "github_pat_abcdefghijklmnopqrstuvwxyz123456",
            expected=2,
        )
        self.assertIn("resembles a secret", failed.stderr)
        self.assertEqual(before, exclude.read_bytes())
        self.assertFalse(self.payload.exists())

    def test_failed_postwrite_seal_restores_draft_manifest_and_checksums(self) -> None:
        self.prepare()
        self.complete_documents()
        before_manifest = (self.payload / "manifest.json").read_bytes()
        before_checksums = (self.payload / "checksums.json").read_bytes()
        exclude_result = self.git(self.repo, "rev-parse", "--git-path", "info/exclude")
        exclude = Path(exclude_result.stdout.strip())
        if not exclude.is_absolute():
            exclude = self.repo / exclude
        exclude.write_text("", encoding="utf-8")
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("does not ignore every canonical payload file", failed.stderr)
        self.assertEqual(before_manifest, (self.payload / "manifest.json").read_bytes())
        self.assertEqual(
            before_checksums, (self.payload / "checksums.json").read_bytes()
        )

    def test_invalid_utf8_and_non_markdown_secrets_fail_closed(self) -> None:
        self.prepare()
        self.complete_documents()
        status_before = (self.payload / "STATUS.md").read_bytes()
        (self.payload / "STATUS.md").write_bytes(b"\xff\xfe")
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("strict UTF-8", failed.stderr)
        self.assertEqual(b"\xff\xfe", (self.payload / "STATUS.md").read_bytes())
        (self.payload / "STATUS.md").write_bytes(status_before)
        manifest_path = self.payload / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["producer"]["agent"] = "github_pat_abcdefghijklmnopqrstuvwxyz123456"
        manifest_path.write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("resembles a secret", failed.stderr)

    def test_encrypted_private_key_marker_is_rejected(self) -> None:
        self.prepare()
        self.complete_documents()
        context = self.payload / "CONTEXT.md"
        context.write_text(
            context.read_text(encoding="utf-8")
            + "\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nfixture\n",
            encoding="utf-8",
        )
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("private-key", failed.stderr)

        context.write_text(
            context.read_text(encoding="utf-8").replace(
                "-----BEGIN ENCRYPTED PRIVATE KEY-----",
                "-----BEGIN PRIVATE KEY-----",
            ),
            encoding="utf-8",
        )
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("private-key", failed.stderr)

    def test_repo_sources_win_truncation_and_claude_matching_is_exact(self) -> None:
        (self.repo / "AGENTS.md").write_text("important repo rules\n", encoding="utf-8")
        generic = self.home / ".agents" / "memories"
        generic.mkdir(parents=True)
        for index in range(210):
            (generic / f"memory-{index:03}.md").write_text(
                "generic\n", encoding="utf-8"
            )
        claude_projects = self.home / ".claude" / "projects"
        unrelated = claude_projects / "unrelated-project"
        unrelated.mkdir(parents=True)
        (unrelated / "notes.md").write_text("unrelated\n", encoding="utf-8")
        tool_results = self.repo / ".claude" / "tool-results"
        tool_results.mkdir(parents=True)
        (tool_results / "raw.md").write_text("raw transcript\n", encoding="utf-8")
        self.prepare()
        index = json.loads(
            (self.payload / "context-index.json").read_text(encoding="utf-8")
        )
        paths = {item["path"] for item in index["candidates"]}
        self.assertIn("repo:AGENTS.md", paths)
        self.assertNotIn("home:.claude/projects/unrelated-project/notes.md", paths)
        self.assertNotIn("repo:.claude/tool-results/raw.md", paths)
        self.assertTrue(index["truncated"])
        self.assertEqual(200, len(index["candidates"]))

    def test_plain_resume_output_contains_order_and_provenance_details(self) -> None:
        (self.repo / "AGENTS.md").write_text("first\n", encoding="utf-8")
        self.prepare()
        self.complete_documents()
        self.seal()
        (self.repo / "AGENTS.md").write_text("changed\n", encoding="utf-8")
        result = self.cli("resume", "--repo", str(self.repo))
        self.assertIn("Reading order:", result.stdout)
        self.assertIn(str((self.payload / "STATUS.md").resolve()), result.stdout)
        self.assertIn("- changed:", result.stdout)

    def test_unexpected_payload_file_and_symlink_path_fail_closed(self) -> None:
        self.prepare()
        (self.payload / "extra.md").write_text("not canonical\n", encoding="utf-8")
        failed = self.cli("seal", "--repo", str(self.repo), expected=2)
        self.assertIn("Unexpected file", failed.stderr)
        (self.payload / "extra.md").unlink()
        link = self.base / ".teamwork-link"
        try:
            os.symlink(self.payload, link, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"directory symlink unavailable: {exc}")
        failed = self.cli("verify", "--payload", str(link), "--allow-draft", expected=2)
        self.assertIn("not found or unsafe", failed.stderr)

    def test_non_git_payload_is_explicit_and_warned(self) -> None:
        plain = self.base / "plain project"
        plain.mkdir()
        result = self.cli("prepare", "--repo", str(plain), "--allow-non-git", "--json")
        prepared = json.loads(result.stdout)
        self.assertEqual("draft", prepared["state"])
        self.assertTrue(prepared["warnings"])
        payload = plain / ".teamwork"
        self.complete_documents(payload)
        sealed_result = self.cli("seal", "--payload", str(payload), "--json")
        sealed = json.loads(sealed_result.stdout)
        self.assertEqual("ready", sealed["state"])
        self.assertTrue(sealed["warnings"])

    def test_prepare_refuses_tracked_payload(self) -> None:
        self.payload.mkdir()
        (self.payload / "STATUS.md").write_text("tracked\n", encoding="utf-8")
        self.git(self.repo, "add", "-f", ".teamwork/STATUS.md")
        result = self.cli("prepare", "--repo", str(self.repo), expected=2)
        self.assertIn("already tracked", result.stderr)

    def test_prepare_refuses_case_variant_tracked_payload(self) -> None:
        variant = self.repo / ".TeamWork"
        variant.mkdir()
        (variant / "STATUS.md").write_text("tracked\n", encoding="utf-8")
        self.git(self.repo, "add", "-f", ".TeamWork/STATUS.md")
        result = self.cli("prepare", "--repo", str(self.repo), expected=2)
        self.assertIn("case-insensitive check", result.stderr)

    @unittest.skipUnless(os.name == "nt", "Windows junction-specific test")
    def test_windows_junction_alias_shares_operation_lock(self) -> None:
        target = self.base / "lock-target"
        target.mkdir()
        alias = self.base / "lock-alias"
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(alias), str(target)],
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest(f"junction unavailable: {created.stderr or created.stdout}")
        try:
            target_identity = teamwork.canonical_lock_identity("repository", target)
            alias_identity = teamwork.canonical_lock_identity("repository", alias)
            self.assertEqual(target_identity, alias_identity)
            with teamwork.advisory_operation_lock(target_identity):
                with self.assertRaises(teamwork.TeamworkError):
                    with teamwork.advisory_operation_lock(alias_identity):
                        self.fail("alias acquired a second operation lock")
        finally:
            os.rmdir(alias)

    @unittest.skipUnless(os.name == "nt", "Windows junction-specific test")
    def test_windows_junction_payload_and_git_info_fail_closed(self) -> None:
        junction_target = self.base / "junction-target"
        junction_target.mkdir()
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(self.payload), str(junction_target)],
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest(f"junction unavailable: {created.stderr or created.stdout}")
        try:
            failed = self.cli("prepare", "--repo", str(self.repo), expected=2)
            self.assertIn("real directory", failed.stderr)
            self.assertEqual([], list(junction_target.iterdir()))
        finally:
            os.rmdir(self.payload)

        git_info = self.repo / ".git" / "info"
        shutil.rmtree(git_info)
        outside_info = self.base / "outside-info"
        outside_info.mkdir()
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(git_info), str(outside_info)],
            text=True,
            capture_output=True,
            check=False,
        )
        if created.returncode != 0:
            self.skipTest(
                f"Git info junction unavailable: {created.stderr or created.stdout}"
            )
        try:
            failed = self.cli("prepare", "--repo", str(self.repo), expected=2)
            self.assertIn("unsafe Git common/exclude path", failed.stderr)
            self.assertEqual([], list(outside_info.iterdir()))
        finally:
            os.rmdir(git_info)

    def test_linked_git_worktree_handoff_and_resume(self) -> None:
        linked = self.base / "linked-worktree"
        self.git(self.repo, "worktree", "add", "-b", "linked-fixture", str(linked))
        prepared = self.cli("prepare", "--repo", str(linked), "--json")
        self.assertEqual("draft", json.loads(prepared.stdout)["state"])
        linked_payload = linked / ".teamwork"
        self.complete_documents(linked_payload)
        sealed = self.cli("seal", "--repo", str(linked), "--json")
        self.assertEqual("ready", json.loads(sealed.stdout)["state"])
        resumed = self.cli("resume", "--repo", str(linked), "--json")
        self.assertEqual(
            str(linked.resolve()), json.loads(resumed.stdout)["project_root"]
        )
        ignored = subprocess.run(
            ["git", "-C", str(linked), "check-ignore", "-q", ".teamwork/manifest.json"],
            check=False,
        )
        self.assertEqual(0, ignored.returncode)


class PackagingTests(unittest.TestCase):
    def test_clean_release_reads_commit_canonical_git_blobs(self) -> None:
        commit = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            text=True,
            encoding="utf-8",
            capture_output=True,
            check=True,
        ).stdout.strip()
        version_bytes, files = build_release.git_release_capture(commit)
        expected = subprocess.run(
            [
                "git",
                "-C",
                str(ROOT),
                "show",
                f"{commit}:skills/teamwork-handoff/SKILL.md",
            ],
            capture_output=True,
            check=True,
        ).stdout
        self.assertEqual(expected, files["teamwork-handoff/SKILL.md"])
        expected_version = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{commit}:VERSION"],
            capture_output=True,
            check=True,
        ).stdout
        self.assertEqual(expected_version, version_bytes)
        self.assertEqual(
            expected_version.decode("utf-8").strip(),
            build_release.parse_version(version_bytes),
        )
        self.assertEqual(
            files["teamwork-handoff/scripts/teamwork_payload.py"],
            files["teamwork-resume/scripts/teamwork_payload.py"],
        )

    def test_git_object_reads_ignore_local_replace_refs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary) / "replace-fixture"
            repo.mkdir()

            def git(*args: str) -> str:
                return subprocess.run(
                    ["git", "-C", str(repo), *args],
                    text=True,
                    encoding="utf-8",
                    capture_output=True,
                    check=True,
                ).stdout.strip()

            git("init")
            git("config", "user.email", "replace@example.invalid")
            git("config", "user.name", "Replace Fixture")
            probe = repo / "probe.txt"
            probe.write_text("original\n", encoding="utf-8")
            git("add", "probe.txt")
            git("commit", "-m", "original")
            original = git("rev-parse", "HEAD")
            probe.write_text("replacement\n", encoding="utf-8")
            git("commit", "-am", "replacement")
            replacement = git("rev-parse", "HEAD")
            git("checkout", "--detach", original)
            git("replace", original, replacement)
            self.assertEqual("replacement", git("show", "HEAD:probe.txt"))
            with mock.patch.object(build_release, "ROOT", repo):
                captured = build_release.git_capture_bytes(
                    128, "show", "HEAD:probe.txt"
                )
                provenance = build_release.git_provenance(require_clean=True)
            self.assertEqual(b"original\n", captured)
            self.assertEqual(original, provenance["commit"])
            self.assertFalse(provenance["dirty"])

            archive_repo = Path(temporary) / "archive-fixture"
            subprocess.run(
                [
                    "git",
                    "clone",
                    "--quiet",
                    "--no-local",
                    str(ROOT),
                    str(archive_repo),
                ],
                capture_output=True,
                check=True,
            )

            def archive_git(*args: str) -> str:
                return subprocess.run(
                    ["git", "-C", str(archive_repo), *args],
                    text=True,
                    encoding="utf-8",
                    capture_output=True,
                    check=True,
                ).stdout.strip()

            archive_git("config", "user.email", "replace@example.invalid")
            archive_git("config", "user.name", "Replace Fixture")
            archive_original = archive_git("rev-parse", "HEAD")
            archive_version = archive_git("show", f"{archive_original}:VERSION")
            (archive_repo / "VERSION").write_text("9.9.9\n", encoding="utf-8")
            archive_git("commit", "-am", "replacement version")
            archive_replacement = archive_git("rev-parse", "HEAD")
            archive_git("checkout", "--detach", archive_original)
            archive_git("replace", archive_original, archive_replacement)
            replaced_archive = Path(temporary) / "replace-proof.zip"
            with mock.patch.object(build_release, "ROOT", archive_repo):
                result = build_release.build(replaced_archive, require_clean=True)
            self.assertEqual(archive_version, result["version"])
            with zipfile.ZipFile(replaced_archive) as archive:
                manifest = json.loads(archive.read("release-manifest.json"))
            self.assertEqual(archive_version, manifest["version"])
            self.assertEqual(archive_original, manifest["source"]["commit"])

            archive_git("replace", "-d", archive_original)
            (archive_repo / "VERSION").write_text("8.8.8\n", encoding="utf-8")
            archive_git("update-index", "--assume-unchanged", "VERSION")
            self.assertEqual("", archive_git("status", "--porcelain"))
            filtered_archive = Path(temporary) / "working-filter-proof.zip"
            with mock.patch.object(build_release, "ROOT", archive_repo):
                result = build_release.build(filtered_archive, require_clean=True)
            self.assertEqual(archive_version, result["version"])
            with zipfile.ZipFile(filtered_archive) as archive:
                manifest = json.loads(archive.read("release-manifest.json"))
            self.assertEqual(archive_version, manifest["version"])
            self.assertEqual(archive_original, manifest["source"]["commit"])
            with (
                mock.patch.object(build_release, "ROOT", archive_repo),
                mock.patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                return_code = build_release.main(["--require-clean", "--json"])
            self.assertEqual(0, return_code, output.getvalue())
            default_result = json.loads(output.getvalue())
            self.assertEqual(archive_version, default_result["version"])
            self.assertEqual(
                (
                    archive_repo / "dist" / f"teamwork-skills-{archive_version}.zip"
                ).resolve(),
                Path(default_result["archive"]).resolve(),
            )
            self.assertFalse(
                (archive_repo / "dist" / "teamwork-skills-8.8.8.zip").exists()
            )

    def test_dirty_capture_rejects_version_or_source_race(self) -> None:
        provenance = {
            "available": True,
            "commit": "a" * 40,
            "created_at": "2026-08-17T00:00:00Z",
            "dirty": True,
            "object_format": "sha1",
        }
        with (
            tempfile.TemporaryDirectory() as temporary,
            mock.patch.object(build_release, "git_provenance", return_value=provenance),
            mock.patch.object(
                build_release,
                "working_release_capture",
                side_effect=[(b"1.0.0\n", {}), (b"1.0.1\n", {})],
            ),
        ):
            with self.assertRaises(RuntimeError) as raised:
                build_release.build(Path(temporary) / "release.zip")
        self.assertIn("changed while being captured", str(raised.exception))

    def test_sync_check_is_read_only_and_detects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            fixture = Path(temporary)
            canonical_paths = (
                "src/teamwork_payload.py",
                "docs/PAYLOAD_CONTRACT.md",
                "schemas/teamwork-manifest.schema.json",
            )
            for relative in canonical_paths:
                target = fixture / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(ROOT / relative, target)
            for skill in ("teamwork-handoff", "teamwork-resume"):
                (fixture / "skills" / skill).mkdir(parents=True)
            check_command = [
                sys.executable,
                str(ROOT / "scripts" / "sync_skills.py"),
                "--root",
                str(fixture),
                "--check",
            ]
            drift = subprocess.run(
                check_command, text=True, capture_output=True, check=False
            )
            self.assertEqual(2, drift.returncode)
            self.assertIn("out of sync", drift.stdout)
            self.assertFalse(
                (fixture / "skills" / "teamwork-handoff" / "scripts").exists()
            )
            synchronized = subprocess.run(
                check_command[:-1], text=True, capture_output=True, check=False
            )
            self.assertEqual(
                0, synchronized.returncode, synchronized.stdout + synchronized.stderr
            )
            clean = subprocess.run(
                check_command, text=True, capture_output=True, check=False
            )
            self.assertEqual(0, clean.returncode, clean.stdout + clean.stderr)
            self.assertIn("are synchronized", clean.stdout)

    def test_embedded_scripts_match_canonical(self) -> None:
        expected = hashlib.sha256(CANONICAL.read_bytes()).hexdigest()
        for skill in ("teamwork-handoff", "teamwork-resume"):
            embedded = ROOT / "skills" / skill / "scripts" / "teamwork_payload.py"
            self.assertTrue(embedded.is_file(), f"Missing {embedded}")
            self.assertEqual(
                expected, hashlib.sha256(embedded.read_bytes()).hexdigest()
            )

    def test_skill_metadata_and_contract_are_complete(self) -> None:
        for skill in ("teamwork-handoff", "teamwork-resume"):
            skill_root = ROOT / "skills" / skill
            text = (skill_root / "SKILL.md").read_text(encoding="utf-8")
            self.assertTrue(text.startswith("---\nname: "))
            self.assertIn(f"name: {skill}\n", text)
            self.assertIn("description:", text)
            self.assertNotIn("TODO", text)
            self.assertLess(len(text.splitlines()), 500)
            reference = skill_root / "references" / "payload-contract.md"
            self.assertTrue(reference.is_file())
            self.assertEqual(
                (ROOT / "docs" / "PAYLOAD_CONTRACT.md").read_bytes(),
                reference.read_bytes(),
            )
            schema = skill_root / "references" / "teamwork-manifest.schema.json"
            self.assertEqual(
                (ROOT / "schemas" / "teamwork-manifest.schema.json").read_bytes(),
                schema.read_bytes(),
            )

    def test_openai_interface_metadata_mentions_skill(self) -> None:
        for skill in ("teamwork-handoff", "teamwork-resume"):
            text = (ROOT / "skills" / skill / "agents" / "openai.yaml").read_text(
                encoding="utf-8"
            )
            self.assertIn("interface:", text)
            self.assertIn(f"${skill}", text)
            match = re.search(r'short_description: "([^"]+)"', text)
            self.assertIsNotNone(match)
            self.assertGreaterEqual(len(match.group(1)), 25)
            self.assertLessEqual(len(match.group(1)), 64)

    def test_manifest_schema_declares_strict_current_dialect(self) -> None:
        schema = json.loads(
            (ROOT / "schemas" / "teamwork-manifest.schema.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertEqual(
            "https://json-schema.org/draft/2020-12/schema", schema["$schema"]
        )
        self.assertEqual("urn:teamwork:manifest:1.0.0", schema["$id"])
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(
            "1.0.1", (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        )

    def test_release_archive_is_reproducible_and_self_verifying(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "first.zip"
            second = Path(temporary) / "second.zip"
            for output in (first, second):
                result = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "build_release.py"),
                        "--output",
                        str(output),
                        "--json",
                    ],
                    cwd=ROOT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertTrue(Path(str(output) + ".sha256").is_file())
            self.assertEqual(first.read_bytes(), second.read_bytes())
            with zipfile.ZipFile(first) as archive:
                names = archive.namelist()
                self.assertEqual(sorted(names), names)
                self.assertIn("teamwork-handoff/SKILL.md", names)
                self.assertIn("teamwork-resume/SKILL.md", names)
                self.assertIn("INSTALL.md", names)
                self.assertIn("LICENSE.txt", names)
                self.assertIn("SBOM.spdx.json", names)
                self.assertIn("verify_release.py", names)
                self.assertTrue(
                    archive.read("LICENSE.txt")
                    .decode("utf-8")
                    .startswith("MIT License")
                )
                sbom = json.loads(archive.read("SBOM.spdx.json"))
                self.assertEqual("MIT", sbom["packages"][0]["licenseDeclared"])
                self.assertEqual("MIT", sbom["packages"][0]["licenseConcluded"])
                self.assertEqual([], sbom["hasExtractedLicensingInfos"])
                manifest = json.loads(archive.read("release-manifest.json"))
                self.assertEqual(
                    "https://agentskills.io/specification",
                    manifest["format_specification"],
                )
                self.assertEqual("3.11", manifest["minimum_python"])
                for name, digest in manifest["files"].items():
                    self.assertEqual(
                        digest, hashlib.sha256(archive.read(name)).hexdigest()
                    )

                installed = Path(temporary) / "installed"
                archive.extractall(installed)

            verified_release = subprocess.run(
                [sys.executable, str(installed / "verify_release.py"), str(installed)],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0,
                verified_release.returncode,
                verified_release.stdout + verified_release.stderr,
            )
            verification = json.loads(verified_release.stdout)
            self.assertTrue(verification["ok"])
            self.assertIn("release_grade", verification)
            self.assertIn("object_format", verification["source"])
            official_sbom = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "validate_sbom.py"),
                    str(installed / "SBOM.spdx.json"),
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0,
                official_sbom.returncode,
                official_sbom.stdout + official_sbom.stderr,
            )

            project = Path(temporary) / "installed-project"
            project.mkdir()
            handoff_cli = (
                installed / "teamwork-handoff" / "scripts" / "teamwork_payload.py"
            )
            resume_cli = (
                installed / "teamwork-resume" / "scripts" / "teamwork_payload.py"
            )
            prepared = subprocess.run(
                [
                    sys.executable,
                    str(handoff_cli),
                    "prepare",
                    "--repo",
                    str(project),
                    "--allow-non-git",
                    "--agent",
                    "archive-producer",
                    "--harness",
                    "archive-test",
                    "--json",
                ],
                cwd=project,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, prepared.returncode, prepared.stdout + prepared.stderr)
            payload = project / ".teamwork"
            for path in payload.glob("*.md"):
                content = PLACEHOLDER_RE.sub(
                    "Installed archive fixture", path.read_text(encoding="utf-8")
                )
                if path.name == "STATUS.md":
                    content = content.replace(
                        "Installed archive fixture", "Resume from installed archive.", 1
                    )
                path.write_text(content, encoding="utf-8")
            sealed = subprocess.run(
                [
                    sys.executable,
                    str(handoff_cli),
                    "seal",
                    "--payload",
                    str(payload),
                    "--json",
                ],
                cwd=project,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, sealed.returncode, sealed.stdout + sealed.stderr)
            resumed = subprocess.run(
                [
                    sys.executable,
                    str(resume_cli),
                    "resume",
                    "--payload",
                    str(payload),
                    "--agent",
                    "archive-consumer",
                    "--harness",
                    "archive-test",
                    "--json",
                ],
                cwd=project,
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, resumed.returncode, resumed.stdout + resumed.stderr)
            resume_result = json.loads(resumed.stdout)
            self.assertEqual(
                "Resume from installed archive.", resume_result["first_action"]
            )
            self.assertEqual("archive-consumer", resume_result["consumer"]["agent"])

            def initialize_git(repo: Path) -> None:
                repo.mkdir()
                subprocess.run(
                    ["git", "-C", str(repo), "init"], check=True, capture_output=True
                )
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(repo),
                        "config",
                        "user.email",
                        "archive@example.invalid",
                    ],
                    check=True,
                )
                subprocess.run(
                    ["git", "-C", str(repo), "config", "user.name", "Archive Test"],
                    check=True,
                )
                (repo / "README.md").write_text(
                    "# Installed Git fixture\n", encoding="utf-8"
                )
                subprocess.run(["git", "-C", str(repo), "add", "README.md"], check=True)
                subprocess.run(
                    ["git", "-C", str(repo), "commit", "-m", "fixture"],
                    check=True,
                    capture_output=True,
                )

            source_repo = Path(temporary) / "git-source"
            destination_repo = Path(temporary) / "git-destination"
            initialize_git(source_repo)
            initialize_git(destination_repo)
            git_prepared = subprocess.run(
                [
                    sys.executable,
                    str(handoff_cli),
                    "prepare",
                    "--repo",
                    str(source_repo),
                    "--json",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0, git_prepared.returncode, git_prepared.stdout + git_prepared.stderr
            )
            source_payload = source_repo / ".teamwork"
            for path in source_payload.glob("*.md"):
                content = PLACEHOLDER_RE.sub(
                    "Installed Git fixture", path.read_text(encoding="utf-8")
                )
                if path.name == "STATUS.md":
                    content = content.replace(
                        "Installed Git fixture", "Resume installed Git fixture.", 1
                    )
                path.write_text(content, encoding="utf-8")
            git_sealed = subprocess.run(
                [
                    sys.executable,
                    str(handoff_cli),
                    "seal",
                    "--repo",
                    str(source_repo),
                    "--json",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0, git_sealed.returncode, git_sealed.stdout + git_sealed.stderr
            )
            shutil.copytree(source_payload, destination_repo / ".teamwork")
            git_resumed = subprocess.run(
                [
                    sys.executable,
                    str(resume_cli),
                    "resume",
                    "--repo",
                    str(destination_repo),
                    "--json",
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0, git_resumed.returncode, git_resumed.stdout + git_resumed.stderr
            )
            self.assertTrue(json.loads(git_resumed.stdout)["relocated"])
            self.assertEqual(
                0,
                subprocess.run(
                    [
                        "git",
                        "-C",
                        str(destination_repo),
                        "check-ignore",
                        "-q",
                        ".teamwork/manifest.json",
                    ],
                    check=False,
                ).returncode,
            )

            harness_root = Path(temporary) / "harness-skills"
            for skill in ("teamwork-handoff", "teamwork-resume"):
                shutil.copytree(installed / skill, harness_root / skill)
            verified_install = subprocess.run(
                [
                    sys.executable,
                    str(installed / "verify_release.py"),
                    str(installed),
                    "--installed-skills-root",
                    str(harness_root),
                ],
                text=True,
                encoding="utf-8",
                errors="replace",
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                0,
                verified_install.returncode,
                verified_install.stdout + verified_install.stderr,
            )
            self.assertTrue(json.loads(verified_install.stdout)["installed_verified"])
            installed_version = subprocess.run(
                [
                    sys.executable,
                    str(
                        harness_root
                        / "teamwork-handoff"
                        / "scripts"
                        / "teamwork_payload.py"
                    ),
                    "--version",
                ],
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual("1.0.1", installed_version.stdout.strip())
            for skill in ("teamwork-handoff", "teamwork-resume"):
                shutil.rmtree(harness_root / skill)
            self.assertEqual([], list(harness_root.iterdir()))

    def test_release_verifier_rejects_semantic_manifest_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            archive_path = Path(temporary) / "release.zip"
            built = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "build_release.py"),
                    "--output",
                    str(archive_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, built.returncode, built.stdout + built.stderr)
            extracted = Path(temporary) / "extracted"
            with zipfile.ZipFile(archive_path) as archive:
                archive.extractall(extracted)
            manifest_path = extracted / "release-manifest.json"
            original = json.loads(manifest_path.read_text(encoding="utf-8"))
            mutations = (
                ("version", "not-semver"),
                ("format_specification", "https://example.invalid/spec"),
                ("skills", ["teamwork-resume", "teamwork-handoff"]),
            )
            for key, value in mutations:
                tampered = json.loads(json.dumps(original))
                tampered[key] = value
                manifest_path.write_text(
                    json.dumps(tampered, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                verified = subprocess.run(
                    [
                        sys.executable,
                        str(extracted / "verify_release.py"),
                        str(extracted),
                    ],
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(2, verified.returncode, key)

    def test_release_verifier_binds_provenance_and_every_sbom_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            archive_path = root / "release.zip"
            built = subprocess.run(
                [
                    sys.executable,
                    str(ROOT / "scripts" / "build_release.py"),
                    "--output",
                    str(archive_path),
                ],
                cwd=ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(0, built.returncode, built.stdout + built.stderr)
            extracted = root / "extracted"
            with zipfile.ZipFile(archive_path) as archive:
                archive.extractall(extracted)
            manifest_path = extracted / "release-manifest.json"
            sbom_path = extracted / "SBOM.spdx.json"
            original_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            original_sbom = json.loads(sbom_path.read_text(encoding="utf-8"))

            def run_verifier(label: str) -> None:
                verified = subprocess.run(
                    [
                        sys.executable,
                        str(extracted / "verify_release.py"),
                        str(extracted),
                    ],
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(
                    2,
                    verified.returncode,
                    f"{label}: {verified.stdout}{verified.stderr}",
                )

            provenance_mutations = (
                ("impossible timestamp", "created_at", "2026-02-31T00:00:00Z"),
                ("hash format mismatch", "object_format", "sha256"),
            )
            for label, key, value in provenance_mutations:
                manifest = json.loads(json.dumps(original_manifest))
                manifest["source"][key] = value
                manifest_path.write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                sbom_path.write_text(
                    json.dumps(original_sbom, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                run_verifier(label)

            def mutate_namespace(sbom: dict) -> None:
                sbom["documentNamespace"] = "urn:teamwork:spdx:tampered"

            def mutate_creation(sbom: dict) -> None:
                sbom["creationInfo"]["created"] = "1980-01-01T00:00:00Z"

            def mutate_package(sbom: dict) -> None:
                sbom["packages"][0]["versionInfo"] = "9.9.9"

            def mutate_license(sbom: dict) -> None:
                sbom["packages"][0]["licenseDeclared"] = "NOASSERTION"

            def mutate_relationship(sbom: dict) -> None:
                sbom["relationships"] = list(reversed(sbom["relationships"]))

            def mutate_sha1(sbom: dict) -> None:
                sbom["files"][0]["checksums"][0]["checksumValue"] = "0" * 40

            def mutate_file_name(sbom: dict) -> None:
                sbom["files"][0]["fileName"] = "./../outside"

            sbom_mutations = (
                ("namespace", mutate_namespace),
                ("creation", mutate_creation),
                ("package", mutate_package),
                ("license", mutate_license),
                ("relationship", mutate_relationship),
                ("sha1", mutate_sha1),
                ("file name", mutate_file_name),
            )
            for label, mutate in sbom_mutations:
                manifest = json.loads(json.dumps(original_manifest))
                sbom = json.loads(json.dumps(original_sbom))
                mutate(sbom)
                sbom_bytes = (json.dumps(sbom, indent=2, sort_keys=True) + "\n").encode(
                    "utf-8"
                )
                sbom_path.write_bytes(sbom_bytes)
                manifest["files"]["SBOM.spdx.json"] = hashlib.sha256(
                    sbom_bytes
                ).hexdigest()
                manifest_path.write_text(
                    json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                run_verifier(label)

    def test_cli_version_matches_release_version(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CANONICAL), "--version"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode)
        self.assertEqual(
            (ROOT / "VERSION").read_text(encoding="utf-8").strip(),
            result.stdout.strip(),
        )
        self.assertIn("MIN_PYTHON = (3, 11)", CANONICAL.read_text(encoding="utf-8"))

    def test_version_governance_and_release_output_safety(self) -> None:
        version_check = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "check_version.py")],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            0, version_check.returncode, version_check.stdout + version_check.stderr
        )
        forbidden = ROOT / "skills" / "teamwork-handoff" / "forbidden.zip"
        failed = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "build_release.py"),
                "--output",
                str(forbidden),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(2, failed.returncode)
        self.assertIn("cannot be written inside", failed.stdout)
        self.assertFalse(forbidden.exists())

        if os.name == "nt":
            with tempfile.TemporaryDirectory() as temporary:
                temporary_root = Path(temporary)
                target = temporary_root / "target"
                target.mkdir()
                junction = temporary_root / "junction"
                created = subprocess.run(
                    ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
                    text=True,
                    capture_output=True,
                    check=False,
                )
                if created.returncode == 0:
                    try:
                        junction_output = junction / "release.zip"
                        failed = subprocess.run(
                            [
                                sys.executable,
                                str(ROOT / "scripts" / "build_release.py"),
                                "--output",
                                str(junction_output),
                            ],
                            cwd=ROOT,
                            text=True,
                            capture_output=True,
                            check=False,
                        )
                        self.assertEqual(2, failed.returncode)
                        self.assertIn("reparse point", failed.stdout)
                        self.assertFalse((target / "release.zip").exists())
                    finally:
                        os.rmdir(junction)
        else:
            with tempfile.TemporaryDirectory() as temporary:
                temporary_root = Path(temporary).resolve()
                target = temporary_root / "target"
                target.mkdir()
                linked_parent = temporary_root / "linked-parent"
                linked_parent.symlink_to(target, target_is_directory=True)
                linked_output = linked_parent / "release.zip"
                failed = subprocess.run(
                    [
                        sys.executable,
                        str(ROOT / "scripts" / "build_release.py"),
                        "--output",
                        str(linked_output),
                    ],
                    cwd=ROOT,
                    text=True,
                    capture_output=True,
                    check=False,
                )
                self.assertEqual(2, failed.returncode)
                self.assertIn("link or reparse point", failed.stdout)
                self.assertFalse((target / "release.zip").exists())

    def test_compatibility_document_covers_supported_harnesses(self) -> None:
        text = (ROOT / "docs" / "COMPATIBILITY.md").read_text(encoding="utf-8")
        for value in (
            "Agent Skills specification",
            "Codex",
            "Claude Code",
            "Gemini CLI",
        ):
            self.assertIn(value, text)
        self.assertIn("Independent-agent compatibility", text)


if __name__ == "__main__":
    unittest.main()
