#!/usr/bin/env python3
"""Create, seal, verify, and resume agent-agnostic Teamwork payloads."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Iterator, Sequence
from urllib.parse import urlsplit, urlunsplit


SCHEMA_NAME = "teamwork-payload"
SCHEMA_VERSION = "1.0.0"
SKILL_VERSION = "1.0.0"
MIN_PYTHON = (3, 11)
MIN_GIT = (2, 22)
DEFAULT_PAYLOAD_DIR = ".teamwork"
MAX_SOURCE_BYTES = 1_048_576
MAX_SOURCES = 200
MAX_WORKTREE_LINES = 500
MAX_WALK_DIRS = 2_000
MAX_SOURCE_DEPTH = 8
MAX_DIRECTORY_ENTRIES = 4_096
MAX_WALK_ENTRIES = 20_000
MAX_SEARCH_DIRS = 2_000
MAX_SEARCH_DEPTH = 6
MAX_SEARCH_ENTRIES = 20_000
MAX_PAYLOAD_FILE_BYTES = 2_097_152
MAX_PAYLOAD_TOTAL_BYTES = 10_485_760
MAX_GIT_OUTPUT_CHARS = 2_097_152
GIT_TIMEOUT_SECONDS = 30
MAX_RESUME_ACTION_CHARS = 8_192
MAX_METADATA_CHARS = 1_024
MAX_WARNINGS = 100
MAX_REMOTES = 100
MANIFEST_SCHEMA_FILE = "teamwork-manifest.schema.json"
SAFE_ENVIRONMENT_KEYS = ("CI", "TERM_PROGRAM", "SHELL", "COMSPEC")
SEMVER_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*))"
    r"(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"
)

DOCUMENTS = (
    "STATUS.md",
    "PROJECT.md",
    "NEXT_STEPS.md",
    "DECISIONS.md",
    "VALIDATION.md",
    "CONTEXT.md",
    "ENVIRONMENT.md",
    "WORKTREE.md",
    "SOURCES.md",
)
HASHED_FILES = (*DOCUMENTS, "context-index.json", MANIFEST_SCHEMA_FILE, "manifest.json")
READ_ORDER = list(DOCUMENTS)

GENERATED_BEGIN = "<!-- TEAMWORK:BEGIN GENERATED -->"
GENERATED_END = "<!-- TEAMWORK:END GENERATED -->"
PLACEHOLDER_RE = re.compile(r"\[Required:[^\]]+\]", re.IGNORECASE)
SENSITIVE_PATTERNS = (
    (
        "private-key",
        re.compile(
            r"-----BEGIN (?:(?:RSA|EC|OPENSSH|DSA|ENCRYPTED) PRIVATE KEY|PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----"
        ),
    ),
    ("openai-key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    ("github-token", re.compile(r"\bgh[opusr]_[A-Za-z0-9]{20,}\b")),
    ("github-fine-grained-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}\b")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("bearer-token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}")),
    ("url-userinfo", re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^/@\s:]+:[^/@\s]+@")),
    ("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    (
        "assigned-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password)"
            r"['\"]?\s*[:=]\s*['\"]?[A-Za-z0-9_./+@=-]{12,}"
        ),
    ),
)
SENSITIVE_NAME_RE = re.compile(
    r"(?i)(?:^|[._\s-])(?:secret|secrets|credential|credentials|creds|token|tokens|password|passwd|"
    r"api[-_]?key|private[-_]?key|\.env)(?:$|[._\s-])"
)
SOURCE_SUFFIXES = {".md", ".mdc", ".txt"}
SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".teamwork",
    "node_modules",
    "vendor",
    "dist",
    "build",
    "target",
    "tool-results",
    "__pycache__",
    ".venv",
    "venv",
}


TEMPLATES = {
    "STATUS.md": """# Status

## Resume instruction

[Required: state one concrete, safe first action for the next agent]

## Current outcome

[Required: describe current working result and active objective]

## Completed

- [Required: list completed work with file or command evidence]

## In progress

- [Required: describe partially completed work, or write None]

## Blockers

- None known.

## Live repository snapshot

<!-- TEAMWORK:BEGIN GENERATED -->
Prepared automatically.
<!-- TEAMWORK:END GENERATED -->
""",
    "PROJECT.md": """# Project

## Purpose

[Required: explain what this project does and who or what uses it]

## Goals and boundaries

- [Required: list active goals, non-goals, and safety boundaries]

## Architecture

[Required: summarize components and their relationships]

## Important paths

| Path | Purpose |
| --- | --- |
| `<repo-root>` | [Required: describe repository root] |

## Working commands

| Task | Command | Preconditions |
| --- | --- | --- |
| [Required: task] | `[Required: exact command]` | [Required: prerequisites] |
""",
    "NEXT_STEPS.md": """# Next steps

## Ordered actions

1. [Required: give the highest-priority action with exact file or command context]

## Done criteria

- [Required: state observable acceptance criteria]

## Deferred work

- None.
""",
    "DECISIONS.md": """# Decisions

Keep IDs stable. Update an existing row when a decision changes; add a row only for a new decision.

| ID | Decision | Reason | Evidence | Status |
| --- | --- | --- | --- | --- |
| TW-0001 | [Required: record a consequential project decision] | [Required: rationale] | [Required: path, issue, or command] | Active |
""",
    "VALIDATION.md": """# Validation

## Verified claims

| Claim | Evidence | Result | Verified at |
| --- | --- | --- | --- |
| [Required: narrow claim] | `[Required: exact command or artifact]` | [Required: pass or fail] | [Required: UTC time] |

## Commands run

```text
[Required: exact commands and concise outcomes]
```

## Unverified claims and risks

- [Required: list remaining validation gaps, or write None]
""",
    "CONTEXT.md": """# Context

## Project-specific instructions and memory

- [Required: synthesize only project-relevant facts from applicable instruction and memory sources]

## Source synthesis

| Source ID | Relevant facts | Freshness or caveat |
| --- | --- | --- |
| [Required: use an ID from SOURCES.md, or repo-live] | [Required: concise fact] | [Required: current, stale, or unverified] |

## Information intentionally excluded

- Secrets, credentials, unrelated personal data, raw conversation logs, and large generated artifacts.
""",
    "ENVIRONMENT.md": """# Environment

## Required dependencies

- [Required: list runtimes, tools, services, and versions needed to continue]

## Access and approval boundaries

- [Required: state permissions or external systems needed, or write None]

## Generated producer facts

<!-- TEAMWORK:BEGIN GENERATED -->
Prepared automatically.
<!-- TEAMWORK:END GENERATED -->
""",
}


class TeamworkError(RuntimeError):
    """Expected validation or environment failure."""


def utc_now() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131_072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sensitive_rules(value: str) -> list[str]:
    return [rule for rule, pattern in SENSITIVE_PATTERNS if pattern.search(value)]


def strict_utc_timestamp(value: Any, label: str) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", value
    ):
        raise TeamworkError(f"{label} must be a UTC RFC 3339 timestamp")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as exc:
        raise TeamworkError(f"{label} must be a UTC RFC 3339 timestamp") from exc


def validate_single_line(value: Any, label: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or (not allow_empty and not value):
        raise TeamworkError(
            f"{label} must be {'a string' if allow_empty else 'a non-empty string'}"
        )
    if len(value) > MAX_METADATA_CHARS or contains_terminal_controls(value):
        raise TeamworkError(
            f"{label} contains control characters or exceeds {MAX_METADATA_CHARS} characters"
        )
    return value


def contains_terminal_controls(value: str) -> bool:
    """Reject C0, DEL, and C1 controls before rendering untrusted text."""
    return any(
        ord(character) < 32 or 127 <= ord(character) <= 159 for character in value
    )


def read_bytes_bounded(path: Path, maximum: int, label: str) -> bytes:
    """Read at most *maximum* bytes and fail if the file grows past the bound."""
    if is_unsafe_link(path) or not path.is_file():
        raise TeamworkError(f"{label} is not a regular file: {path}")
    try:
        with path.open("rb") as handle:
            value = handle.read(maximum + 1)
    except OSError as exc:
        raise TeamworkError(f"Cannot read {label} from {path}: {exc}") from exc
    if len(value) > maximum:
        raise TeamworkError(f"{label} exceeds {maximum} bytes: {path}")
    return value


def read_text_strict(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise TeamworkError(
            f"Cannot read strict UTF-8 text from {path}: {exc}"
        ) from exc


def is_unsafe_link(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise TeamworkError(
            f"Cannot inspect filesystem link safety for {path}: {exc}"
        ) from exc
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def atomic_write_bytes(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if is_unsafe_link(path.parent):
        raise TeamworkError(f"Refusing to write through unsafe parent: {path.parent}")
    if path.exists() and (is_unsafe_link(path) or not path.is_file()):
        raise TeamworkError(f"Refusing to replace non-regular file: {path}")
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, delete=False
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        os.replace(temp_path, path)
        temp_path = None
    except OSError as exc:
        raise TeamworkError(f"Cannot atomically write {path}: {exc}") from exc
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str) -> None:
    atomic_write_bytes(path, text.replace("\r\n", "\n").encode("utf-8"))


def atomic_write_json(path: Path, value: Any) -> None:
    atomic_write_text(
        path, json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    )


def manifest_schema_text() -> str:
    root = Path(__file__).resolve().parents[1]
    candidates = (
        root / "references" / MANIFEST_SCHEMA_FILE,
        root / "schemas" / MANIFEST_SCHEMA_FILE,
    )
    for candidate in candidates:
        if candidate.is_file() and not is_unsafe_link(candidate):
            text = read_text_strict(candidate)
            try:
                schema = json.loads(text)
            except json.JSONDecodeError as exc:
                raise TeamworkError(
                    f"Bundled manifest schema is invalid JSON: {candidate}: {exc}"
                ) from exc
            if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
                raise TeamworkError(
                    f"Bundled manifest schema has unsupported dialect: {candidate}"
                )
            return (
                json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
            )
    raise TeamworkError(
        f"Bundled manifest schema not found beside skill or source tree: {MANIFEST_SCHEMA_FILE}"
    )


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_text_strict(path))
    except (TeamworkError, json.JSONDecodeError) as exc:
        raise TeamworkError(f"Cannot read valid JSON from {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise TeamworkError(f"Expected JSON object in {path}")
    return value


def run_git(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    for key in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
    ):
        environment.pop(key, None)
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    command = ["git", "-C", str(root), *args]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        output_lock = threading.Lock()
        exceeded = threading.Event()
        output: dict[str, list[bytes]] = {"stdout": [], "stderr": []}
        total_bytes = 0

        def drain(name: str, stream: Any) -> None:
            nonlocal total_bytes
            while True:
                chunk = stream.read(65_536)
                if not chunk:
                    return
                with output_lock:
                    total_bytes += len(chunk)
                    if total_bytes > MAX_GIT_OUTPUT_CHARS:
                        exceeded.set()
                        return
                    output[name].append(chunk)

        assert process.stdout is not None and process.stderr is not None
        readers = [
            threading.Thread(
                target=drain, args=("stdout", process.stdout), daemon=True
            ),
            threading.Thread(
                target=drain, args=("stderr", process.stderr), daemon=True
            ),
        ]
        for reader in readers:
            reader.start()
        deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
        failure: str | None = None
        while process.poll() is None:
            if exceeded.is_set():
                failure = (
                    f"Git command output exceeds {MAX_GIT_OUTPUT_CHARS} bytes: "
                    f"git {' '.join(args)}"
                )
                break
            if time.monotonic() >= deadline:
                failure = (
                    f"Git command exceeded {GIT_TIMEOUT_SECONDS} seconds: "
                    f"git {' '.join(args)}"
                )
                break
            time.sleep(0.01)
        if failure is not None:
            process.kill()
            process.wait()
            for reader in readers:
                reader.join(timeout=1)
            process.stdout.close()
            process.stderr.close()
            raise TeamworkError(failure)
        for reader in readers:
            reader.join(timeout=1)
        readers_alive = any(reader.is_alive() for reader in readers)
        process.stdout.close()
        process.stderr.close()
        if exceeded.is_set() or readers_alive:
            raise TeamworkError(
                f"Git command output exceeds {MAX_GIT_OUTPUT_CHARS} bytes: git {' '.join(args)}"
            )
        stdout = b"".join(output["stdout"]).decode("utf-8", errors="replace")
        stderr = b"".join(output["stderr"]).decode("utf-8", errors="replace")
        return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
    except TeamworkError:
        raise
    except (OSError, subprocess.SubprocessError) as exc:
        raise TeamworkError(
            f"Git command failed to execute safely: git {' '.join(args)}: {exc}"
        ) from exc


def ensure_git_version(root: Path) -> None:
    result = run_git(root, "--version")
    match = re.search(r"\bgit version (\d+)\.(\d+)(?:\.(\d+))?", result.stdout)
    if result.returncode != 0 or not match:
        raise TeamworkError("Cannot determine Git version; Teamwork requires Git 2.22+")
    version = (int(match.group(1)), int(match.group(2)))
    if version < MIN_GIT:
        raise TeamworkError(
            f"Git {version[0]}.{version[1]} is unsupported; Teamwork requires Git 2.22+"
        )


def find_repo_root(start: Path, allow_non_git: bool = False) -> tuple[Path, bool]:
    start = start.expanduser().resolve()
    if start.is_file():
        start = start.parent
    if not start.exists() or not start.is_dir():
        raise TeamworkError(f"Repository start path is not a directory: {start}")
    if shutil.which("git"):
        result = run_git(start, "rev-parse", "--show-toplevel")
        if result.returncode == 0 and result.stdout.strip():
            ensure_git_version(start)
            return Path(result.stdout.strip()).resolve(), True
    current = start
    while True:
        if (current / ".git").exists():
            raise TeamworkError(
                f"Git metadata is present but repository discovery failed: {current / '.git'}"
            )
        if current.parent == current:
            break
        current = current.parent
    if allow_non_git:
        return start, False
    raise TeamworkError(
        "No Git repository found. Use --allow-non-git only when untracked status is not applicable."
    )


def validate_payload_name(name: str) -> str:
    if not re.fullmatch(r"\.teamwork(?:-[a-z0-9][a-z0-9-]{0,31})?", name):
        raise TeamworkError(
            "Payload directory must be .teamwork or .teamwork-<lowercase-slug>"
        )
    return name


def payload_for(root: Path, name: str) -> Path:
    name = validate_payload_name(name)
    payload = root / name
    if payload.exists() and (is_unsafe_link(payload) or not payload.is_dir()):
        raise TeamworkError(f"Payload path must be a real directory: {payload}")
    return payload


def validate_payload_layout(payload: Path, allow_lock: bool = False) -> None:
    allowed = set(HASHED_FILES) | {"checksums.json"}
    if allow_lock:
        allowed.add(".lock")
    total_bytes = 0
    for child in payload.iterdir():
        if child.name not in allowed:
            raise TeamworkError(f"Unexpected file in canonical payload: {child.name}")
        if child.name == ".lock" and allow_lock:
            continue
        if is_unsafe_link(child) or not child.is_file():
            raise TeamworkError(f"Payload entries must be regular files: {child}")
        size = child.stat().st_size
        if size > MAX_PAYLOAD_FILE_BYTES:
            raise TeamworkError(
                f"Payload file exceeds {MAX_PAYLOAD_FILE_BYTES} bytes: {child.name}"
            )
        total_bytes += size
    if total_bytes > MAX_PAYLOAD_TOTAL_BYTES:
        raise TeamworkError(f"Payload exceeds {MAX_PAYLOAD_TOTAL_BYTES} total bytes")


def process_is_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if pid == os.getpid():
        return True
    if os.name == "nt":
        try:
            import ctypes

            # ``windll`` and ``get_last_error`` exist only on Windows, so the
            # cross-platform ctypes stubs intentionally omit them. Resolve the
            # platform API dynamically after the runtime guard.
            windll = getattr(ctypes, "windll")
            get_last_error = getattr(ctypes, "get_last_error")
            process = windll.kernel32.OpenProcess(0x1000, False, pid)
            if not process:
                return get_last_error() == 5
            windll.kernel32.CloseHandle(process)
            return True
        except (AttributeError, OSError):
            return True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


@contextlib.contextmanager
def advisory_operation_lock(identity: str) -> Iterator[None]:
    lock_root = Path(tempfile.gettempdir()) / "teamwork-operation-locks"
    lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if is_unsafe_link(lock_root):
        raise TeamworkError(f"Operation lock root is unsafe: {lock_root}")
    lock_path = (
        lock_root / f"{hashlib.sha256(identity.encode('utf-8')).hexdigest()}.lock"
    )
    if is_unsafe_link(lock_path):
        raise TeamworkError(f"Operation lock path is unsafe: {lock_path}")
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(lock_path, flags, 0o600)
    acquired = False
    try:
        if os.name == "nt":
            import importlib

            locker: Any = importlib.import_module("msvcrt")

            if os.fstat(descriptor).st_size == 0:
                os.write(descriptor, b"0")
                os.fsync(descriptor)
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                locker.locking(descriptor, locker.LK_NBLCK, 1)
            except OSError as exc:
                raise TeamworkError(
                    "Another Teamwork operation is already in progress"
                ) from exc
        else:
            import importlib

            locker = importlib.import_module("fcntl")

            try:
                locker.flock(descriptor, locker.LOCK_EX | locker.LOCK_NB)
            except OSError as exc:
                raise TeamworkError(
                    "Another Teamwork operation is already in progress"
                ) from exc
        acquired = True
        yield
    finally:
        try:
            if acquired:
                if os.name == "nt":
                    import importlib

                    locker = importlib.import_module("msvcrt")

                    os.lseek(descriptor, 0, os.SEEK_SET)
                    locker.locking(descriptor, locker.LK_UNLCK, 1)
                else:
                    import importlib

                    locker = importlib.import_module("fcntl")

                    locker.flock(descriptor, locker.LOCK_UN)
        finally:
            os.close(descriptor)


def canonical_lock_identity(kind: str, path: Path) -> str:
    """Normalize aliases so one filesystem target always maps to one lock."""
    canonical = path.expanduser().absolute().resolve(strict=False)
    return f"{kind}:{os.path.normcase(str(canonical))}"


@contextlib.contextmanager
def _payload_marker_lock(payload: Path) -> Iterator[None]:
    created_payload = not payload.exists()
    payload.mkdir(parents=True, exist_ok=True)
    lock = payload / ".lock"
    token = uuid.uuid4().hex
    descriptor: int | None = None
    for _attempt in range(2):
        if lock.exists() and (is_unsafe_link(lock) or not lock.is_file()):
            raise TeamworkError(f"Payload lock path is unsafe: {lock}")
        try:
            descriptor = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            break
        except FileExistsError as exc:
            try:
                existing = read_text_strict(lock)
            except TeamworkError:
                raise TeamworkError(
                    f"Payload lock exists but cannot be validated; remove it only after confirming no update is active: {lock}"
                ) from exc
            pid_match = re.search(r"(?:^|\s)pid=(\d+)(?:\s|$)", existing)
            token_match = re.search(r"(?:^|\s)token=([0-9a-f]{32})(?:\s|$)", existing)
            if not pid_match or not token_match:
                raise TeamworkError(
                    f"Payload lock exists with unknown owner; remove it only after confirming no update is active: {lock}"
                ) from exc
            if process_is_running(int(pid_match.group(1))):
                raise TeamworkError(
                    f"Payload update already in progress: {lock}"
                ) from exc
            try:
                lock.unlink()
            except OSError as unlink_error:
                raise TeamworkError(
                    f"Cannot remove stale payload lock {lock}: {unlink_error}"
                ) from unlink_error
    if descriptor is None:
        raise TeamworkError(f"Cannot acquire payload lock: {lock}")
    try:
        os.write(
            descriptor,
            f"pid={os.getpid()} token={token} created={utc_now()}\n".encode("utf-8"),
        )
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        yield
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            if (
                lock.is_file()
                and not is_unsafe_link(lock)
                and f"token={token}" in read_text_strict(lock)
            ):
                lock.unlink()
        except (OSError, TeamworkError):
            pass
        if created_payload:
            try:
                payload.rmdir()
            except OSError:
                pass


@contextlib.contextmanager
def payload_lock(payload: Path) -> Iterator[None]:
    identity = canonical_lock_identity("repository", payload.parent)
    with advisory_operation_lock(identity):
        with _payload_marker_lock(payload):
            yield


def _restore_git_exclude_locked(
    change: tuple[Path, bytes | None, bytes] | None,
) -> None:
    if change is None:
        return
    path, original, written = change
    if (
        is_unsafe_link(path)
        or not path.is_file()
        or read_bytes_bounded(path, MAX_PAYLOAD_FILE_BYTES, "Git exclude") != written
    ):
        raise TeamworkError(
            f"Git exclude changed concurrently; refusing rollback: {path}"
        )
    if original is None:
        path.unlink()
    else:
        atomic_write_bytes(path, original)


def restore_git_exclude(change: tuple[Path, bytes | None, bytes] | None) -> None:
    if change is None:
        return
    with advisory_operation_lock(canonical_lock_identity("git-exclude", change[0])):
        _restore_git_exclude_locked(change)


def tracked_payload_paths(root: Path, payload_name: str) -> str:
    """Return tracked payload entries using a case-insensitive pathspec."""
    tracked = run_git(
        root,
        "ls-files",
        "-z",
        "--",
        f":(icase,glob){payload_name}/**",
    )
    if tracked.returncode != 0:
        raise TeamworkError(
            f"Cannot verify Git tracking state: {tracked.stderr.strip() or tracked.stdout.strip()}"
        )
    return "\n".join(item for item in tracked.stdout.split("\0") if item)


def verify_payload_files_ignored(root: Path, payload_name: str) -> None:
    """Require every canonical payload file to be ignored, not only the manifest."""
    relative_paths = [
        f"{payload_name}/{name}" for name in (*HASHED_FILES, "checksums.json")
    ]
    ignored = run_git(
        root,
        "check-ignore",
        "--no-index",
        "--",
        *relative_paths,
    )
    if ignored.returncode not in {0, 1}:
        raise TeamworkError(
            f"Cannot verify Git ignore state: {ignored.stderr.strip() or ignored.stdout.strip()}"
        )
    ignored_paths = {item.replace("\\", "/") for item in ignored.stdout.splitlines()}
    missing = [path for path in relative_paths if path not in ignored_paths]
    if missing:
        raise TeamworkError(
            "Git does not ignore every canonical payload file:\n" + "\n".join(missing)
        )


def ensure_git_excluded(
    root: Path, payload_name: str, is_git: bool
) -> tuple[list[str], tuple[Path, bytes | None, bytes] | None]:
    payload_name = validate_payload_name(payload_name)
    if not is_git:
        return ["Non-Git project: payload cannot be certified as untracked."], None
    ensure_git_version(root)
    tracked = tracked_payload_paths(root, payload_name)
    if tracked:
        raise TeamworkError(
            f"Payload is already tracked by Git (case-insensitive check):\n{tracked}"
        )
    git_path = run_git(root, "rev-parse", "--git-path", "info/exclude")
    if git_path.returncode != 0 or not git_path.stdout.strip():
        raise TeamworkError(
            f"Cannot resolve Git exclude file: {git_path.stderr.strip()}"
        )
    common_result = run_git(root, "rev-parse", "--git-common-dir")
    if common_result.returncode != 0 or not common_result.stdout.strip():
        raise TeamworkError(
            f"Cannot resolve Git common directory: {common_result.stderr.strip()}"
        )
    exclude = Path(git_path.stdout.strip())
    if not exclude.is_absolute():
        exclude = root / exclude
    common = Path(common_result.stdout.strip())
    if not common.is_absolute():
        common = root / common
    if (
        is_unsafe_link(common)
        or is_unsafe_link(common / "info")
        or is_unsafe_link(exclude)
    ):
        raise TeamworkError(f"Refusing unsafe Git common/exclude path: {exclude}")
    expected_exclude = (common.resolve() / "info" / "exclude").resolve()
    if exclude.resolve() != expected_exclude:
        raise TeamworkError(f"Git exclude path escaped common directory: {exclude}")
    if exclude.exists() and not exclude.is_file():
        raise TeamworkError(f"Git exclude path is not a regular file: {exclude}")
    with advisory_operation_lock(canonical_lock_identity("git-exclude", exclude)):
        original = (
            read_bytes_bounded(exclude, MAX_PAYLOAD_FILE_BYTES, "Git exclude")
            if exclude.exists()
            else None
        )
        try:
            existing = original.decode("utf-8") if original is not None else ""
        except UnicodeError as exc:
            raise TeamworkError(
                f"Git exclude is not strict UTF-8: {exclude}: {exc}"
            ) from exc
        begin = "# BEGIN teamwork payload (managed)"
        end = "# END teamwork payload (managed)"
        block_re = re.compile(re.escape(begin) + r".*?" + re.escape(end), re.DOTALL)
        matches = list(block_re.finditer(existing))
        if len(matches) > 1:
            raise TeamworkError(
                f"Git exclude contains multiple Teamwork managed blocks: {exclude}"
            )
        managed_names = {payload_name}
        if matches:
            managed_lines = matches[0].group(0).splitlines()[1:-1]
            for line in managed_lines:
                match = re.fullmatch(
                    r"/(\.teamwork(?:-[a-z0-9][a-z0-9-]{0,31})?)/", line
                )
                if not match:
                    raise TeamworkError(
                        f"Git exclude Teamwork block contains an unsafe entry: {line!r}"
                    )
                managed_names.add(match.group(1))
        block = "\n".join(
            [begin, *(f"/{name}/" for name in sorted(managed_names)), end]
        )
        if matches:
            updated = block_re.sub(block, existing)
        else:
            updated = (
                existing.rstrip() + ("\n\n" if existing.strip() else "") + block + "\n"
            )
        change = None
        if updated != existing:
            atomic_write_text(exclude, updated)
            written = updated.replace("\r\n", "\n").encode("utf-8")
            change = (exclude, original, written)
        try:
            verify_payload_files_ignored(root, payload_name)
        except BaseException:
            _restore_git_exclude_locked(change)
            raise
    return [], change


def verify_git_excluded(root: Path, payload_name: str) -> list[str]:
    payload_name = validate_payload_name(payload_name)
    if not shutil.which("git"):
        return ["Git executable unavailable; untracked status not verified."]
    probe = run_git(root, "rev-parse", "--show-toplevel")
    if probe.returncode != 0:
        if (root / ".git").exists():
            raise TeamworkError(
                f"Git repository metadata is present but unreadable: {probe.stderr.strip()}"
            )
        return [
            "Current payload parent is not a Git repository; untracked status not verified."
        ]
    ensure_git_version(root)
    top_level = Path(probe.stdout.strip()).resolve()
    if top_level != root.resolve():
        raise TeamworkError(
            f"Payload parent must be the Git repository root: {root} (Git root: {top_level})"
        )
    tracked = tracked_payload_paths(root, payload_name)
    if tracked:
        raise TeamworkError(
            f"Payload is tracked by Git (case-insensitive check):\n{tracked}"
        )
    verify_payload_files_ignored(root, payload_name)
    return []


def git_snapshot(root: Path, is_git: bool) -> dict[str, Any]:
    if not is_git:
        return {
            "type": "none",
            "branch": None,
            "head": None,
            "remotes": [],
            "worktree": [],
            "worktree_truncated": False,
        }
    branch_result = run_git(root, "branch", "--show-current")
    head_result = run_git(root, "rev-parse", "HEAD")
    remote_result = run_git(root, "remote", "-v")
    status_result = run_git(root, "status", "--short", "--untracked-files=all")
    for label, result in (
        ("branch", branch_result),
        ("remotes", remote_result),
        ("status", status_result),
    ):
        if result.returncode != 0:
            raise TeamworkError(
                f"Cannot capture Git {label}: {result.stderr.strip() or result.stdout.strip()}"
            )
    raw_worktree = status_result.stdout.splitlines()
    worktree = sanitize_worktree_lines(raw_worktree[:MAX_WORKTREE_LINES])
    return {
        "type": "git",
        "branch": branch_result.stdout.strip() or None,
        "head": head_result.stdout.strip() if head_result.returncode == 0 else None,
        "remotes": sanitize_remote_lines(remote_result.stdout.splitlines()),
        "worktree": worktree,
        "worktree_truncated": len(raw_worktree) > MAX_WORKTREE_LINES,
    }


def sanitize_worktree_lines(lines: Sequence[str]) -> list[str]:
    sanitized: list[str] = []
    for line in lines:
        path_text = line[3:] if len(line) > 3 else line
        path_parts = re.split(r"[\\/]|\s+->\s+", path_text)
        if any(SENSITIVE_NAME_RE.search(part.strip('"')) for part in path_parts):
            status = line[:2] if len(line) >= 2 else "??"
            sanitized.append(f"{status} <sensitive path omitted>")
        else:
            sanitized.append(line)
    return sanitized


def sanitize_remote_lines(lines: Sequence[str]) -> list[str]:
    sanitized: list[str] = []
    for line in lines:
        fields = line.split()
        if len(fields) >= 2:
            fields[1] = sanitize_url(fields[1])
        sanitized.append(" ".join(fields))
    return sanitized


def sanitize_url(value: str) -> str:
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError:
        return "<malformed remote omitted>"
    if parsed.scheme and parsed.hostname:
        host = f"[{hostname}]" if hostname and ":" in hostname else str(hostname)
        if port:
            host += f":{port}"
        return urlunsplit((parsed.scheme, host, parsed.path, "", ""))
    if parsed.scheme:
        return f"{parsed.scheme}:<local-or-opaque-remote-omitted>"
    scp_style = re.fullmatch(r"[^/@\s]+@([^:\s]+:.+)", value)
    if scp_style:
        return scp_style.group(1)
    if sensitive_rules(value):
        return "<sensitive remote omitted>"
    return value


def replace_generated(text: str, generated: str) -> str:
    block = f"{GENERATED_BEGIN}\n{generated.rstrip()}\n{GENERATED_END}"
    pattern = re.compile(
        re.escape(GENERATED_BEGIN) + r".*?" + re.escape(GENERATED_END), re.DOTALL
    )
    matches = list(pattern.finditer(text))
    if len(matches) != 1:
        raise TeamworkError(
            "Existing document must contain exactly one Teamwork generated block"
        )
    return pattern.sub(lambda _match: block, text, count=1)


def runtime_facts(agent: str | None, harness: str | None) -> dict[str, Any]:
    detected_harness = harness or os.environ.get("TEAMWORK_HARNESS")
    if not detected_harness:
        if os.environ.get("CODEX_HOME") or os.environ.get("CODEX_THREAD_ID"):
            detected_harness = "codex"
        elif os.environ.get("CLAUDE_CONFIG_DIR") or os.environ.get("CLAUDE_CODE"):
            detected_harness = "claude-code"
        elif os.environ.get("GEMINI_CLI"):
            detected_harness = "gemini-cli"
        else:
            detected_harness = "unknown"
    agent_name = validate_single_line(
        agent or os.environ.get("TEAMWORK_AGENT") or "unknown", "producer agent"
    )
    harness_name = validate_single_line(detected_harness, "producer harness")
    for label, value in (
        ("producer agent", agent_name),
        ("producer harness", harness_name),
    ):
        if sensitive_rules(value):
            raise TeamworkError(f"{label} resembles a secret and cannot be recorded")
    safe_env = {key: "present" for key in SAFE_ENVIRONMENT_KEYS if os.environ.get(key)}
    return {
        "agent": agent_name,
        "harness": harness_name,
        "hostname": validate_single_line(
            platform.node() or "unknown", "producer hostname"
        ),
        "operating_system": validate_single_line(
            platform.platform() or "unknown", "producer operating system"
        ),
        "python": validate_single_line(platform.python_version(), "producer Python"),
        "safe_environment": safe_env,
    }


def normalize_relevance(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", value.lower())


def source_candidate(
    path: Path,
    scope: str,
    base: Path,
    reason: str,
    incomplete: list[bool] | None = None,
) -> dict[str, Any] | None:
    try:
        unsafe = is_unsafe_link(path)
    except TeamworkError:
        if incomplete is not None:
            incomplete[0] = True
        return None
    if unsafe:
        return None
    try:
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.suffix.lower() not in SOURCE_SUFFIXES
        ):
            return None
        if any(SENSITIVE_NAME_RE.search(part) for part in path.parts):
            return None
        if metadata.st_size > MAX_SOURCE_BYTES:
            return None
        relative = path.resolve().relative_to(base.resolve()).as_posix()
        if scope == "repo":
            path_hint = f"<repo-root>/{relative}"
        elif scope == "home":
            path_hint = f"<home>/{relative}"
        else:
            path_hint = f"<source-root-{scope.removeprefix('extra-')}>/{relative}"
        return {
            "id": hashlib.sha256(f"{scope}:{relative}".encode("utf-8")).hexdigest()[
                :12
            ],
            "scope": scope,
            "path": f"{scope}:{relative}",
            "path_hint": path_hint,
            "reason": reason,
            "size": metadata.st_size,
            "modified_at": datetime.fromtimestamp(metadata.st_mtime, timezone.utc)
            .replace(microsecond=0)
            .isoformat()
            .replace("+00:00", "Z"),
            "sha256": sha256_file(path),
        }
    except FileNotFoundError:
        return None
    except (OSError, ValueError, TeamworkError):
        if incomplete is not None:
            incomplete[0] = True
        return None


def bounded_directory_entries(
    directory: Path,
    counters: list[int],
    max_total_entries: int,
    label: str,
) -> list[tuple[str, bool]]:
    """Return bounded, sorted safe entries as (name, is_directory)."""
    entries: list[tuple[str, bool]] = []
    local_entries = 0
    try:
        with os.scandir(directory) as iterator:
            for entry in iterator:
                local_entries += 1
                counters[1] += 1
                if (
                    local_entries > MAX_DIRECTORY_ENTRIES
                    or counters[1] > max_total_entries
                ):
                    raise TeamworkError(f"{label} exceeded its filesystem entry limit")
                path = Path(entry.path)
                if is_unsafe_link(path):
                    continue
                try:
                    is_directory = entry.is_dir(follow_symlinks=False)
                    is_file = entry.is_file(follow_symlinks=False)
                except OSError as exc:
                    raise TeamworkError(
                        f"Cannot inspect {label.lower()} entry {path}: {exc}"
                    ) from exc
                if is_directory or is_file:
                    entries.append((entry.name, is_directory))
    except TeamworkError:
        raise
    except OSError as exc:
        raise TeamworkError(
            f"Cannot scan {label.lower()} directory {directory}: {exc}"
        ) from exc
    return sorted(entries, key=lambda item: item[0])


def walk_guidance(
    root: Path,
    named_only: bool = False,
    truncation: list[bool] | None = None,
    counters: list[int] | None = None,
) -> Iterator[Path]:
    try:
        unsafe = is_unsafe_link(root)
        metadata = root.stat()
    except FileNotFoundError:
        return
    except (OSError, TeamworkError):
        if truncation is not None:
            truncation[0] = True
        return
    if unsafe or not stat.S_ISDIR(metadata.st_mode):
        return
    counters = counters if counters is not None else [0, 0]
    pending: list[tuple[Path, int]] = [(root, 0)]
    while pending:
        if counters[0] >= MAX_WALK_DIRS:
            if truncation is not None:
                truncation[0] = True
            return
        current_path, depth = pending.pop()
        counters[0] += 1
        try:
            entries = bounded_directory_entries(
                current_path, counters, MAX_WALK_ENTRIES, "Source discovery"
            )
        except TeamworkError:
            if truncation is not None:
                truncation[0] = True
            continue
        directories: list[Path] = []
        for name, is_directory in entries:
            path = current_path / name
            if is_directory:
                if name not in SKIP_DIRS:
                    directories.append(path)
            elif named_only:
                if name in {"AGENTS.md", "CLAUDE.md", "GEMINI.md"}:
                    yield path
            elif path.suffix.lower() in SOURCE_SUFFIXES:
                yield path
        if directories and depth >= MAX_SOURCE_DEPTH:
            if truncation is not None:
                truncation[0] = True
            continue
        pending.extend((path, depth + 1) for path in reversed(directories))


def discover_sources(
    root: Path, extra_roots: Sequence[Path]
) -> tuple[list[dict[str, Any]], bool, list[str]]:
    candidates: list[dict[str, Any]] = []
    seen: set[Path] = set()
    truncated = False
    walk_truncated = [False]
    walk_counters = [0, 0]
    home = Path.home().resolve()
    roots_scanned = ["<repo-root>"]

    def add(path: Path, scope: str, base: Path, reason: str) -> bool:
        nonlocal truncated
        if len(candidates) >= MAX_SOURCES:
            truncated = True
            return False
        try:
            resolved = path.resolve()
        except OSError:
            walk_truncated[0] = True
            return True
        if resolved in seen:
            return True
        item = source_candidate(path, scope, base, reason, walk_truncated)
        if item:
            seen.add(resolved)
            candidates.append(item)
            if len(candidates) >= MAX_SOURCES:
                truncated = True
                return False
        return True

    def scan(
        scan_root: Path,
        scope: str,
        base: Path,
        reason: str,
        *,
        named_only: bool = False,
    ) -> None:
        if len(candidates) >= MAX_SOURCES:
            return
        for path in walk_guidance(
            scan_root,
            named_only=named_only,
            truncation=walk_truncated,
            counters=walk_counters,
        ):
            if not add(path, scope, base, reason):
                break

    resolved_extra_roots: list[Path] = []
    for extra in extra_roots:
        resolved = extra.expanduser().resolve()
        if not resolved.exists() or not resolved.is_dir() or is_unsafe_link(resolved):
            raise TeamworkError(
                f"Extra source root is not a real directory: {resolved}"
            )
        resolved_extra_roots.append(resolved)

    # Highest priority: repository-local instructions and memory.
    scan(root, "repo", root, "Repository agent instructions", named_only=True)
    add(
        root / ".github" / "copilot-instructions.md",
        "repo",
        root,
        "Repository Copilot instructions",
    )
    repo_harness_roots = (
        root / ".cursor" / "rules",
        root / ".claude",
        root / ".codex",
        root / ".agents",
        root / ".gemini",
        root / ".windsurf",
        root / ".continue",
    )
    for harness_root in repo_harness_roots:
        scan(harness_root, "repo", root, "Repository harness guidance or memory")

    # Next priority: source roots explicitly selected by the producer.
    for index, extra in enumerate(resolved_extra_roots, start=1):
        roots_scanned.append(f"<source-root-{index}>")
        scan(extra, f"extra-{index}", extra, "Explicit extra guidance root")

    home_exact = (
        (home / ".codex" / "memories" / "memory_summary.md", "Codex memory summary"),
        (home / ".codex" / "memories" / "MEMORY.md", "Codex memory registry"),
        (home / ".codex" / "AGENTS.md", "Codex global instructions"),
        (home / ".claude" / "CLAUDE.md", "Claude global instructions"),
        (home / ".gemini" / "GEMINI.md", "Gemini global instructions"),
        (home / ".agents" / "AGENTS.md", "Agent global instructions"),
    )
    known_home_roots = (
        (home / ".agents" / "memories", "Agent memory"),
        (home / ".cursor" / "rules", "Cursor rules"),
        (home / ".cursor" / "memory", "Cursor memory"),
        (home / ".gemini" / "memory", "Gemini memory"),
        (home / ".windsurf" / "rules", "Windsurf rules"),
        (home / ".windsurf" / "memories", "Windsurf memory"),
        (home / ".continue" / "rules", "Continue rules"),
        (home / ".continue" / "prompts", "Continue prompts"),
    )
    roots_scanned.extend(
        f"<home>/{name}"
        for name in (
            ".codex",
            ".claude",
            ".gemini",
            ".agents",
            ".cursor",
            ".windsurf",
            ".continue",
        )
    )
    # Exact global instructions and registries are bounded and useful across projects.
    for path, reason in home_exact:
        add(path, "home", home, reason)

    # Claude stores project memory under an encoded absolute project path. Match only
    # a direct project directory, never the generic word "project" in the parent path.
    project_key = normalize_relevance(root.resolve().as_posix())
    claude_projects = home / ".claude" / "projects"
    claude_projects_available = False
    try:
        claude_metadata = claude_projects.stat()
        claude_projects_available = stat.S_ISDIR(
            claude_metadata.st_mode
        ) and not is_unsafe_link(claude_projects)
    except FileNotFoundError:
        pass
    except (OSError, TeamworkError):
        walk_truncated[0] = True
    if claude_projects_available and project_key and len(candidates) < MAX_SOURCES:
        try:
            project_directories = [
                claude_projects / name
                for name, is_directory in bounded_directory_entries(
                    claude_projects,
                    walk_counters,
                    MAX_WALK_ENTRIES,
                    "Source discovery",
                )
                if is_directory
            ]
        except TeamworkError:
            walk_truncated[0] = True
            project_directories = []
        matches = [
            path
            for path in project_directories
            if normalize_relevance(path.name) == project_key
        ]
        if not matches:
            suffix_key = normalize_relevance("/".join(root.resolve().parts[-3:]))
            suffix_matches = [
                path
                for path in project_directories
                if normalize_relevance(path.name).endswith(suffix_key)
            ]
            matches = suffix_matches if len(suffix_matches) == 1 else []
        for project_directory in matches:
            scan(project_directory, "home", home, "Claude project-specific memory")

    # Lowest priority: bounded, known memory/rule directories.
    for known_root, reason in known_home_roots:
        scan(known_root, "home", home, reason)

    return candidates, truncated or walk_truncated[0], roots_scanned


def validate_context_index(index: dict[str, Any]) -> None:
    errors: list[str] = []
    expected_fields = {
        "candidates",
        "content_copied",
        "generated_at",
        "roots_scanned",
        "schema_version",
        "truncated",
    }
    if set(index) != expected_fields:
        errors.append("top-level fields do not match canonical context index")
    if index.get("schema_version") != SCHEMA_VERSION:
        errors.append("schema_version mismatch")
    if index.get("content_copied") is not False:
        errors.append("content_copied must be false")
    if not isinstance(index.get("truncated"), bool):
        errors.append("truncated must be boolean")
    try:
        strict_utc_timestamp(index.get("generated_at"), "context-index.generated_at")
    except TeamworkError as exc:
        errors.append(str(exc))
    roots_scanned = index.get("roots_scanned")
    root_pattern = re.compile(
        r"(?:<(?:repo-root|home)>(?:/[A-Za-z0-9._-]+)*|<source-root-[1-9][0-9]*>)"
    )
    if not isinstance(roots_scanned, list) or any(
        not isinstance(item, str) or not root_pattern.fullmatch(item)
        for item in (roots_scanned if isinstance(roots_scanned, list) else [])
    ):
        errors.append("roots_scanned must be an array of strings")
    elif len(roots_scanned) != len(set(roots_scanned)):
        errors.append("roots_scanned must not contain duplicates")
    candidates = index.get("candidates")
    if not isinstance(candidates, list):
        errors.append("candidates must be an array")
        candidates = []
    if len(candidates) > MAX_SOURCES:
        errors.append(f"candidates exceeds limit {MAX_SOURCES}")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    required = {
        "id",
        "scope",
        "path",
        "path_hint",
        "reason",
        "size",
        "modified_at",
        "sha256",
    }
    for position, item in enumerate(candidates):
        if not isinstance(item, dict) or set(item) != required:
            errors.append(f"candidate {position} has noncanonical fields")
            continue
        if not isinstance(item["id"], str) or not re.fullmatch(
            r"[0-9a-f]{12}", item["id"]
        ):
            errors.append(f"candidate {position} has invalid id")
        elif item["id"] in seen_ids:
            errors.append(f"candidate {position} duplicates id")
        seen_ids.add(str(item["id"]))
        path_value = item.get("path")
        scope_value = item.get("scope")
        scope_text = scope_value if isinstance(scope_value, str) else ""
        valid_scope = bool(re.fullmatch(r"(?:repo|home|extra-[1-9][0-9]*)", scope_text))
        if not valid_scope:
            errors.append(f"candidate {position} has invalid scope")
        if not isinstance(path_value, str) or ":" not in path_value:
            errors.append(f"candidate {position} has invalid scoped path")
        else:
            try:
                validate_single_line(path_value, f"candidate {position} path")
            except TeamworkError as exc:
                errors.append(str(exc))
            path_scope, relative = path_value.split(":", 1)
            parts = PurePosixPath(relative).parts
            if (
                path_scope != scope_value
                or not relative
                or relative.startswith("/")
                or "\\" in relative
                or ":" in relative
                or PurePosixPath(relative).as_posix() != relative
                or any(part in {"", ".", ".."} for part in parts)
                or any(SENSITIVE_NAME_RE.search(part) for part in parts)
            ):
                errors.append(f"candidate {position} has unsafe scoped path")
            if valid_scope:
                expected_hint_root = (
                    "<repo-root>"
                    if scope_value == "repo"
                    else "<home>"
                    if scope_value == "home"
                    else f"<source-root-{scope_text.removeprefix('extra-')}>"
                )
                if item.get("path_hint") != f"{expected_hint_root}/{relative}":
                    errors.append(f"candidate {position} has nonportable path_hint")
            expected_id = hashlib.sha256(path_value.encode("utf-8")).hexdigest()[:12]
            if item.get("id") != expected_id:
                errors.append(f"candidate {position} id does not match path")
        if path_value in seen_paths:
            errors.append(f"candidate {position} duplicates path")
        seen_paths.add(str(path_value))
        if (
            isinstance(item["size"], bool)
            or not isinstance(item["size"], int)
            or not 0 <= item["size"] <= MAX_SOURCE_BYTES
        ):
            errors.append(f"candidate {position} has invalid size")
        if not isinstance(item["sha256"], str) or not re.fullmatch(
            r"[0-9a-f]{64}", item["sha256"]
        ):
            errors.append(f"candidate {position} has invalid SHA-256")
        for key in ("scope", "path_hint", "reason"):
            try:
                validate_single_line(item[key], f"candidate {position} {key}")
            except TeamworkError as exc:
                errors.append(str(exc))
        try:
            strict_utc_timestamp(
                item["modified_at"], f"candidate {position} modified_at"
            )
        except TeamworkError as exc:
            errors.append(str(exc))
    if errors:
        raise TeamworkError("Context index validation failed:\n" + "\n".join(errors))


def compare_source_provenance(
    payload: Path, root: Path, extra_roots: Sequence[Path]
) -> dict[str, Any]:
    stored_index = load_json(payload / "context-index.json")
    validate_context_index(stored_index)
    current, current_truncated, _roots = discover_sources(root, extra_roots)
    stored_by_path = {item["path"]: item for item in stored_index["candidates"]}
    current_by_path = {item["path"]: item for item in current}
    unchanged: list[dict[str, str]] = []
    changed: list[dict[str, str]] = []
    missing: list[dict[str, str]] = []
    new: list[dict[str, str]] = []
    for scoped_path, item in stored_by_path.items():
        current_item = current_by_path.get(scoped_path)
        summary = {"id": item["id"], "path": scoped_path}
        if current_item is None:
            missing.append(summary)
        elif current_item["sha256"] != item["sha256"]:
            changed.append(summary)
        else:
            unchanged.append(summary)
    for scoped_path, item in current_by_path.items():
        if scoped_path not in stored_by_path:
            new.append({"id": item["id"], "path": scoped_path})
    return {
        "changed": changed,
        "changed_count": len(changed),
        "current_count": len(current),
        "current_truncated": current_truncated,
        "missing": missing,
        "missing_count": len(missing),
        "new": new,
        "new_count": len(new),
        "stored_count": len(stored_by_path),
        "stored_truncated": bool(stored_index["truncated"]),
        "unchanged_count": len(unchanged),
    }


def markdown_escape(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_sources(candidates: Sequence[dict[str, Any]], truncated: bool) -> str:
    lines = [
        "# Sources",
        "",
        "Generated candidate index. Read only sources relevant to current project; synthesize useful facts into CONTEXT.md.",
        "Do not copy credentials, secrets, unrelated personal data, or raw conversation logs.",
        "",
        "| ID | Scope | Path | Reason | Modified | SHA-256 |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in candidates:
        lines.append(
            "| {id} | {scope} | `{path}` | {reason} | {modified} | `{digest}` |".format(
                id=markdown_escape(item["id"]),
                scope=markdown_escape(item["scope"]),
                path=markdown_escape(item["path"]),
                reason=markdown_escape(item["reason"]),
                modified=markdown_escape(item["modified_at"]),
                digest=markdown_escape(item["sha256"]),
            )
        )
    if not candidates:
        lines.append(
            "| none | none | none | No candidate instruction or memory files discovered | n/a | n/a |"
        )
    if truncated:
        lines.extend(
            [
                "",
                "> Discovery was incomplete because a source, directory, depth, count, or filesystem-access limit was reached.",
            ]
        )
    return "\n".join(lines) + "\n"


def render_worktree(snapshot: dict[str, Any]) -> str:
    lines = [
        "# Worktree",
        "",
        "Generated snapshot; refresh with teamwork-handoff before relying on it.",
        "",
    ]
    lines.extend(
        [
            f"- VCS: {snapshot['type']}",
            f"- Branch: {snapshot.get('branch') or 'unavailable'}",
            f"- HEAD: {snapshot.get('head') or 'unavailable'}",
            "",
            "## Remotes",
            "",
        ]
    )
    lines.extend(f"- `{line}`" for line in snapshot.get("remotes", []))
    if not snapshot.get("remotes"):
        lines.append("- None configured.")
    lines.extend(["", "## Status", "", "```text"])
    lines.extend(snapshot.get("worktree", []) or ["Clean or unavailable."])
    lines.append("```")
    if snapshot.get("worktree_truncated"):
        lines.extend(["", f"> Status truncated at {MAX_WORKTREE_LINES} lines."])
    return "\n".join(lines) + "\n"


def producer_markdown(facts: dict[str, Any]) -> str:
    safe_env = (
        ", ".join(f"{key}={value}" for key, value in facts["safe_environment"].items())
        or "none"
    )
    return "\n".join(
        [
            f"- Agent: {facts['agent']}",
            f"- Harness: {facts['harness']}",
            f"- Host: {facts['hostname']}",
            f"- Operating system: {facts['operating_system']}",
            f"- Python: {facts['python']}",
            f"- Safe environment markers: {safe_env}",
            f"- Refreshed at: {utc_now()}",
        ]
    )


def snapshot_markdown(snapshot: dict[str, Any]) -> str:
    changes = len(snapshot.get("worktree", []))
    return "\n".join(
        [
            f"- VCS: {snapshot['type']}",
            f"- Branch: {snapshot.get('branch') or 'unavailable'}",
            f"- HEAD: {snapshot.get('head') or 'unavailable'}",
            f"- Changed or untracked paths: {changes}{'+' if snapshot.get('worktree_truncated') else ''}",
            f"- Refreshed at: {utc_now()}",
        ]
    )


def validate_existing_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_name") != SCHEMA_NAME:
        raise TeamworkError(
            f"Unsupported payload schema: {manifest.get('schema_name')!r}"
        )
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise TeamworkError(
            f"Unsupported payload version: {manifest.get('schema_version')!r}; expected {SCHEMA_VERSION}"
        )
    errors: list[str] = []
    top_fields = {
        "created_at",
        "discovery",
        "payload_id",
        "payload_state",
        "producer",
        "project",
        "resume",
        "revision",
        "schema_name",
        "schema_version",
        "sealed_at",
        "updated_at",
        "warnings",
    }
    if set(manifest) != top_fields:
        errors.append("top-level fields do not match canonical manifest schema")
    state = manifest.get("payload_state")
    if state not in {"draft", "ready"}:
        errors.append("payload_state must be 'draft' or 'ready'")
    revision = manifest.get("revision")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        errors.append("revision must be a non-negative integer")
    payload_id = manifest.get("payload_id")
    try:
        parsed_payload_id = uuid.UUID(str(payload_id))
        if (
            not isinstance(payload_id, str)
            or str(parsed_payload_id) != payload_id
            or not UUID_RE.fullmatch(payload_id)
        ):
            raise ValueError
    except (ValueError, TypeError, AttributeError):
        errors.append("payload_id must be a UUID")
    discovery = manifest.get("discovery")
    if not isinstance(discovery, dict) or set(discovery) != {
        "candidate_count",
        "candidate_limit",
        "truncated",
    }:
        errors.append("discovery must contain only canonical fields")
    else:
        if (
            isinstance(discovery["candidate_count"], bool)
            or not isinstance(discovery["candidate_count"], int)
            or not 0 <= discovery["candidate_count"] <= MAX_SOURCES
        ):
            errors.append("discovery.candidate_count is invalid")
        if discovery["candidate_limit"] != MAX_SOURCES:
            errors.append("discovery.candidate_limit mismatch")
        if not isinstance(discovery["truncated"], bool):
            errors.append("discovery.truncated must be boolean")
    project = manifest.get("project")
    if not isinstance(project, dict) or set(project) != {
        "name",
        "root_from_payload",
        "root_hint",
        "vcs",
    }:
        errors.append("project must be an object")
    else:
        try:
            validate_single_line(project.get("name"), "project.name")
        except TeamworkError as exc:
            errors.append(str(exc))
        if project.get("root_from_payload") != "..":
            errors.append("project.root_from_payload must be '..'")
        try:
            root_hint = validate_single_line(
                project.get("root_hint"), "project.root_hint"
            )
            if len(root_hint) > MAX_RESUME_ACTION_CHARS:
                errors.append("project.root_hint exceeds path limit")
        except TeamworkError as exc:
            errors.append(str(exc))
        vcs = project.get("vcs")
        vcs_fields = {
            "branch",
            "head",
            "remotes",
            "type",
            "worktree",
            "worktree_truncated",
        }
        if not isinstance(vcs, dict) or set(vcs) != vcs_fields:
            errors.append("project.vcs must contain only canonical fields")
        else:
            if vcs["type"] not in {"git", "none"}:
                errors.append("project.vcs.type is invalid")
            for key in ("branch", "head"):
                if vcs[key] is not None:
                    try:
                        validate_single_line(vcs[key], f"project.vcs.{key}")
                    except TeamworkError as exc:
                        errors.append(str(exc))
            for key in ("remotes", "worktree"):
                if not isinstance(vcs[key], list) or any(
                    not isinstance(item, str) for item in vcs[key]
                ):
                    errors.append(f"project.vcs.{key} must be an array of strings")
                else:
                    for index, item in enumerate(vcs[key]):
                        try:
                            validate_single_line(item, f"project.vcs.{key}[{index}]")
                        except TeamworkError as exc:
                            errors.append(str(exc))
            if (
                isinstance(vcs.get("remotes"), list)
                and len(vcs["remotes"]) > MAX_REMOTES
            ):
                errors.append("project.vcs.remotes exceeds limit")
            if (
                isinstance(vcs.get("worktree"), list)
                and len(vcs["worktree"]) > MAX_WORKTREE_LINES
            ):
                errors.append("project.vcs.worktree exceeds limit")
            if not isinstance(vcs["worktree_truncated"], bool):
                errors.append("project.vcs.worktree_truncated must be boolean")
    producer = manifest.get("producer")
    producer_fields = {
        "agent",
        "harness",
        "hostname",
        "operating_system",
        "python",
        "safe_environment",
        "skill",
        "skill_version",
    }
    if not isinstance(producer, dict) or set(producer) != producer_fields:
        errors.append("producer must be an object")
    else:
        for key in (
            "agent",
            "harness",
            "hostname",
            "operating_system",
            "python",
            "skill",
            "skill_version",
        ):
            try:
                value = validate_single_line(producer.get(key), f"producer.{key}")
                if sensitive_rules(value):
                    errors.append(f"producer.{key} resembles a secret")
            except TeamworkError as exc:
                errors.append(str(exc))
        safe_environment = producer.get("safe_environment")
        if not isinstance(safe_environment, dict) or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in (
                safe_environment.items() if isinstance(safe_environment, dict) else []
            )
        ):
            errors.append("producer.safe_environment must be a string map")
        elif any(key not in SAFE_ENVIRONMENT_KEYS for key in safe_environment):
            errors.append("producer.safe_environment contains an unsupported key")
        else:
            for key, value in safe_environment.items():
                try:
                    validated = validate_single_line(
                        value, f"producer.safe_environment.{key}"
                    )
                    if sensitive_rules(validated):
                        errors.append(
                            f"producer.safe_environment.{key} resembles a secret"
                        )
                except TeamworkError as exc:
                    errors.append(str(exc))
        if producer.get("skill") != "teamwork-handoff" or not SEMVER_RE.fullmatch(
            str(producer.get("skill_version", ""))
        ):
            errors.append("producer skill identity mismatch")
    resume_value = manifest.get("resume")
    if not isinstance(resume_value, dict) or set(resume_value) != {
        "first_read",
        "required_read_order",
    }:
        errors.append("resume must be an object")
    else:
        if resume_value.get("first_read") != "STATUS.md":
            errors.append("resume.first_read must be STATUS.md")
        if resume_value.get("required_read_order") != READ_ORDER:
            errors.append("resume.required_read_order does not match canonical order")
    parsed_times: dict[str, datetime] = {}
    for key in ("created_at", "updated_at"):
        try:
            parsed_times[key] = strict_utc_timestamp(manifest.get(key), key)
        except TeamworkError as exc:
            errors.append(str(exc))
    if (
        set(parsed_times) == {"created_at", "updated_at"}
        and parsed_times["created_at"] > parsed_times["updated_at"]
    ):
        errors.append("created_at must not be later than updated_at")
    if state == "ready":
        try:
            sealed_time = strict_utc_timestamp(manifest.get("sealed_at"), "sealed_at")
            if (
                "created_at" in parsed_times
                and sealed_time < parsed_times["created_at"]
            ):
                errors.append("sealed_at must not be earlier than created_at")
        except TeamworkError:
            errors.append(
                "sealed_at must be a UTC RFC 3339 timestamp for a ready payload"
            )
    if state == "draft" and manifest.get("sealed_at") is not None:
        errors.append("sealed_at must be null for a draft payload")
    warnings = manifest.get("warnings")
    if not isinstance(warnings, list) or len(warnings) > MAX_WARNINGS:
        errors.append("warnings must be an array of strings")
    elif warnings:
        for index, item in enumerate(warnings):
            try:
                validate_single_line(item, f"warnings[{index}]")
            except TeamworkError as exc:
                errors.append(str(exc))
    if errors:
        raise TeamworkError(
            "Manifest contract validation failed:\n" + "\n".join(errors)
        )


def write_checksums(payload: Path) -> None:
    missing = [name for name in HASHED_FILES if not (payload / name).is_file()]
    if missing:
        raise TeamworkError(
            f"Cannot checksum missing payload files: {', '.join(missing)}"
        )
    value = {
        "algorithm": "sha256",
        "files": {name: sha256_file(payload / name) for name in HASHED_FILES},
        "schema_version": SCHEMA_VERSION,
    }
    atomic_write_json(payload / "checksums.json", value)


def snapshot_payload(payload: Path) -> dict[str, bytes]:
    names = set(HASHED_FILES) | {"checksums.json"}
    snapshot: dict[str, bytes] = {}
    total = 0
    for name in names:
        path = payload / name
        if path.is_file() and not is_unsafe_link(path):
            value = read_bytes_bounded(
                path, MAX_PAYLOAD_FILE_BYTES, "Payload snapshot file"
            )
            total += len(value)
            if total > MAX_PAYLOAD_TOTAL_BYTES:
                raise TeamworkError(
                    f"Payload snapshot exceeds {MAX_PAYLOAD_TOTAL_BYTES} total bytes"
                )
            snapshot[name] = value
    return snapshot


def restore_payload(payload: Path, snapshot: dict[str, bytes]) -> None:
    names = set(HASHED_FILES) | {"checksums.json"}
    failures: list[str] = []
    for name in names:
        path = payload / name
        try:
            if name in snapshot:
                atomic_write_bytes(path, snapshot[name])
            elif path.exists():
                if is_unsafe_link(path) or not path.is_file():
                    failures.append(f"unsafe rollback target: {path}")
                else:
                    path.unlink()
        except (OSError, TeamworkError) as exc:
            failures.append(f"{name}: {exc}")
    if failures:
        raise TeamworkError("Payload rollback failed:\n" + "\n".join(failures))


def rollback_prepare(
    payload: Path,
    snapshot: dict[str, bytes],
    exclude_change: tuple[Path, bytes | None, bytes] | None,
) -> None:
    failures: list[str] = []
    try:
        restore_payload(payload, snapshot)
    except (OSError, TeamworkError) as exc:
        failures.append(str(exc))
    try:
        restore_git_exclude(exclude_change)
    except (OSError, TeamworkError) as exc:
        failures.append(str(exc))
    if failures:
        raise TeamworkError("Prepare rollback failed:\n" + "\n".join(failures))


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    root, is_git = find_repo_root(Path(args.repo or Path.cwd()), args.allow_non_git)
    payload = payload_for(root, args.payload_dir)
    extra_roots: list[Path] = []
    for value in args.source_root or []:
        supplied = Path(value).expanduser()
        if is_unsafe_link(supplied) or not supplied.is_dir():
            raise TeamworkError(
                f"Extra source root is not a real directory: {supplied}"
            )
        extra_roots.append(supplied.resolve())
    with payload_lock(payload):
        validate_payload_layout(payload, allow_lock=True)
        original = snapshot_payload(payload)
        exclude_change: tuple[Path, bytes | None, bytes] | None = None
        try:
            warnings, exclude_change = ensure_git_excluded(
                root, args.payload_dir, is_git
            )
            existing_path = payload / "manifest.json"
            existing = load_json(existing_path) if existing_path.exists() else {}
            if existing:
                validate_existing_manifest(existing)

            for name, template in TEMPLATES.items():
                path = payload / name
                if not path.exists():
                    atomic_write_text(path, template)

            vcs_snapshot = git_snapshot(root, is_git)
            facts = runtime_facts(args.agent, args.harness)
            env_path = payload / "ENVIRONMENT.md"
            atomic_write_text(
                env_path,
                replace_generated(read_text_strict(env_path), producer_markdown(facts)),
            )
            status_path = payload / "STATUS.md"
            atomic_write_text(
                status_path,
                replace_generated(
                    read_text_strict(status_path), snapshot_markdown(vcs_snapshot)
                ),
            )
            atomic_write_text(payload / "WORKTREE.md", render_worktree(vcs_snapshot))

            candidates, truncated, roots_scanned = discover_sources(root, extra_roots)
            if truncated:
                warnings.append(
                    "Source discovery reached a directory or candidate safety limit; review SOURCES.md"
                )
            context_index = {
                "candidates": candidates,
                "content_copied": False,
                "generated_at": utc_now(),
                "roots_scanned": roots_scanned,
                "schema_version": SCHEMA_VERSION,
                "truncated": truncated,
            }
            validate_context_index(context_index)
            atomic_write_json(payload / "context-index.json", context_index)
            atomic_write_text(
                payload / "SOURCES.md", render_sources(candidates, truncated)
            )
            atomic_write_text(payload / MANIFEST_SCHEMA_FILE, manifest_schema_text())

            now = utc_now()
            manifest = {
                "created_at": existing.get("created_at", now),
                "discovery": {
                    "candidate_count": len(candidates),
                    "candidate_limit": MAX_SOURCES,
                    "truncated": truncated,
                },
                "payload_id": existing.get("payload_id", str(uuid.uuid4())),
                "payload_state": "draft",
                "producer": {
                    **facts,
                    "skill": "teamwork-handoff",
                    "skill_version": SKILL_VERSION,
                },
                "project": {
                    "name": root.name,
                    "root_from_payload": "..",
                    "root_hint": str(root),
                    "vcs": vcs_snapshot,
                },
                "resume": {
                    "first_read": "STATUS.md",
                    "required_read_order": READ_ORDER,
                },
                "revision": int(existing.get("revision", 0)),
                "schema_name": SCHEMA_NAME,
                "schema_version": SCHEMA_VERSION,
                "sealed_at": None,
                "updated_at": now,
                "warnings": warnings,
            }
            validate_existing_manifest(manifest)
            atomic_write_json(payload / "manifest.json", manifest)
            write_checksums(payload)
        except BaseException:
            rollback_prepare(payload, original, exclude_change)
            raise
    return {
        "candidate_count": len(candidates),
        "payload": str(payload),
        "project_root": str(root),
        "state": "draft",
        "warnings": warnings,
    }


def find_placeholders(payload: Path) -> list[str]:
    found: list[str] = []
    for name in DOCUMENTS:
        text = read_text_strict(payload / name)
        for line_number, line in enumerate(text.splitlines(), start=1):
            if PLACEHOLDER_RE.search(line):
                found.append(f"{name}:{line_number}: {line.strip()}")
    return found


def find_sensitive_values(payload: Path) -> list[str]:
    found: list[str] = []
    for name in HASHED_FILES:
        path = payload / name
        if not path.is_file():
            continue
        for line_number, line in enumerate(
            read_text_strict(path).splitlines(), start=1
        ):
            for rule, pattern in SENSITIVE_PATTERNS:
                if pattern.search(line):
                    found.append(f"{name}:{line_number}: {rule}")
    return found


def locate_payload(args: argparse.Namespace) -> Path:
    if getattr(args, "payload", None):
        supplied = Path(os.path.abspath(str(Path(args.payload).expanduser())))
        candidate = (
            supplied.parent
            if supplied.is_file() and supplied.name == "manifest.json"
            else supplied
        )
        candidate_name = validate_payload_name(candidate.name)
        requested_name = validate_payload_name(args.payload_dir)
        if requested_name != DEFAULT_PAYLOAD_DIR and candidate_name != requested_name:
            raise TeamworkError(
                f"Explicit payload name {candidate.name!r} does not match --payload-dir {requested_name!r}"
            )
        return candidate
    payload_name = validate_payload_name(args.payload_dir)
    if getattr(args, "repo", None):
        root, _is_git = find_repo_root(Path(args.repo), allow_non_git=True)
        return payload_for(root, payload_name)
    explicit_search_root = getattr(args, "search_root", None)
    start = Path(explicit_search_root or Path.cwd()).expanduser().resolve()
    if not explicit_search_root:
        current = start
        while True:
            candidate = current / payload_name
            if (
                not is_unsafe_link(candidate)
                and (candidate / "manifest.json").is_file()
            ):
                return candidate
            if current.parent == current:
                break
            current = current.parent
    if explicit_search_root:
        matches: list[Path] = []
        search_counters = [0, 0]
        pending: list[tuple[Path, int]] = [(start, 0)]
        while pending:
            if search_counters[0] >= MAX_SEARCH_DIRS:
                raise TeamworkError(
                    f"Payload search exceeded {MAX_SEARCH_DIRS} directories; pass --payload explicitly"
                )
            current_path, depth = pending.pop()
            search_counters[0] += 1
            candidate = current_path / payload_name
            manifest_path = candidate / "manifest.json"
            try:
                candidate_unsafe = is_unsafe_link(candidate)
                if candidate_unsafe:
                    found = False
                else:
                    manifest_unsafe = is_unsafe_link(manifest_path)
                    manifest_metadata = manifest_path.stat()
                    found = not manifest_unsafe and stat.S_ISREG(
                        manifest_metadata.st_mode
                    )
            except FileNotFoundError:
                found = False
            except (OSError, TeamworkError) as exc:
                raise TeamworkError(
                    "Payload search was incomplete due to a filesystem-access limit; "
                    "pass --payload explicitly"
                ) from exc
            if found:
                matches.append(candidate.resolve())
                continue
            try:
                entries = bounded_directory_entries(
                    current_path,
                    search_counters,
                    MAX_SEARCH_ENTRIES,
                    "Payload search",
                )
            except TeamworkError as exc:
                raise TeamworkError(
                    "Payload search was incomplete due to a filesystem entry or access limit; "
                    "pass --payload explicitly"
                ) from exc
            directories = [
                current_path / name
                for name, is_directory in entries
                if is_directory and name not in SKIP_DIRS - {payload_name}
            ]
            if directories and depth >= MAX_SEARCH_DEPTH:
                raise TeamworkError(
                    "Payload search was incomplete due to a depth limit; pass --payload explicitly"
                )
            pending.extend((path, depth + 1) for path in reversed(directories))
        unique = sorted(set(matches))
        if len(unique) == 1:
            return unique[0]
        if len(unique) > 1:
            joined = "\n".join(str(path) for path in unique[:20])
            raise TeamworkError(
                f"Multiple payloads found; pass --payload explicitly:\n{joined}"
            )
    raise TeamworkError(f"No {payload_name}/manifest.json found from {start}")


def verify_payload(
    payload: Path,
    require_ready: bool = True,
    *,
    allow_lock: bool = False,
    verify_git: bool = True,
) -> dict[str, Any]:
    payload = payload.expanduser()
    validate_payload_name(payload.name)
    if is_unsafe_link(payload) or not payload.is_dir():
        raise TeamworkError(f"Payload directory not found or unsafe: {payload}")
    payload = payload.resolve()
    validate_payload_layout(payload, allow_lock=allow_lock)
    manifest_path = payload / "manifest.json"
    if not manifest_path.is_file():
        raise TeamworkError(f"Missing manifest: {manifest_path}")
    manifest = load_json(manifest_path)
    validate_existing_manifest(manifest)
    payload_schema = load_json(payload / MANIFEST_SCHEMA_FILE)
    bundled_schema = json.loads(manifest_schema_text())
    if payload_schema != bundled_schema:
        raise TeamworkError("Payload manifest schema does not match this skill release")
    if require_ready and manifest.get("payload_state") != "ready":
        raise TeamworkError(
            f"Payload state is {manifest.get('payload_state')!r}; expected 'ready'"
        )
    checksums_path = payload / "checksums.json"
    checksums = load_json(checksums_path)
    if set(checksums) != {"algorithm", "files", "schema_version"}:
        raise TeamworkError("Checksum metadata fields do not match canonical contract")
    if (
        checksums.get("algorithm") != "sha256"
        or checksums.get("schema_version") != SCHEMA_VERSION
    ):
        raise TeamworkError("Unsupported checksum metadata")
    recorded = checksums.get("files")
    if not isinstance(recorded, dict):
        raise TeamworkError("Checksum file map is missing")
    expected_names = set(HASHED_FILES)
    if set(recorded) != expected_names:
        raise TeamworkError(
            "Checksum file set does not match canonical payload contract"
        )
    if any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
        for value in recorded.values()
    ):
        raise TeamworkError("Checksum values must be lowercase SHA-256 digests")
    mismatches = []
    for name in HASHED_FILES:
        path = payload / name
        if not path.is_file() or is_unsafe_link(path):
            mismatches.append(f"{name}: missing or non-regular")
        elif sha256_file(path) != recorded[name]:
            mismatches.append(f"{name}: SHA-256 mismatch")
    if mismatches:
        raise TeamworkError("Payload integrity check failed:\n" + "\n".join(mismatches))
    for name in HASHED_FILES:
        read_text_strict(payload / name)
    context_index = load_json(payload / "context-index.json")
    validate_context_index(context_index)
    discovery = manifest["discovery"]
    if (
        discovery["candidate_count"] != len(context_index["candidates"])
        or discovery["truncated"] != context_index["truncated"]
    ):
        raise TeamworkError("Manifest discovery summary does not match context index")
    sensitive = find_sensitive_values(payload)
    if sensitive:
        raise TeamworkError(
            "Likely sensitive values found in payload:\n" + "\n".join(sensitive)
        )
    warnings = list(manifest.get("warnings") or [])
    if verify_git:
        warnings.extend(verify_git_excluded(payload.parent, payload.name))
    return {
        "payload": str(payload),
        "project_root": str(payload.parent.resolve()),
        "revision": manifest.get("revision"),
        "schema_version": manifest.get("schema_version"),
        "state": manifest.get("payload_state"),
        "warnings": sorted(set(warnings)),
    }


def seal(args: argparse.Namespace) -> dict[str, Any]:
    payload = locate_payload(args)
    validate_payload_name(payload.name)
    if is_unsafe_link(payload) or not payload.is_dir():
        raise TeamworkError(f"Payload directory not found or unsafe: {payload}")
    with payload_lock(payload):
        validate_payload_layout(payload, allow_lock=True)
        original = snapshot_payload(payload)
        try:
            manifest = load_json(payload / "manifest.json")
            validate_existing_manifest(manifest)
            payload_schema = load_json(payload / MANIFEST_SCHEMA_FILE)
            if payload_schema != json.loads(manifest_schema_text()):
                raise TeamworkError(
                    "Payload manifest schema does not match this skill release"
                )
            context_index = load_json(payload / "context-index.json")
            validate_context_index(context_index)
            if (
                manifest["discovery"]["candidate_count"]
                != len(context_index["candidates"])
                or manifest["discovery"]["truncated"] != context_index["truncated"]
            ):
                raise TeamworkError(
                    "Manifest discovery summary does not match context index"
                )
            placeholders = find_placeholders(payload)
            if placeholders:
                raise TeamworkError(
                    "Required payload content is incomplete:\n"
                    + "\n".join(placeholders)
                )
            sensitive = find_sensitive_values(payload)
            if sensitive:
                raise TeamworkError(
                    "Likely sensitive values found in payload:\n" + "\n".join(sensitive)
                )
            extract_resume_instruction(payload / "STATUS.md")
            now = utc_now()
            manifest["payload_state"] = "ready"
            manifest["revision"] = int(manifest.get("revision", 0)) + 1
            manifest["sealed_at"] = now
            manifest["updated_at"] = now
            validate_existing_manifest(manifest)
            atomic_write_json(payload / "manifest.json", manifest)
            write_checksums(payload)
            result = verify_payload(payload, require_ready=True, allow_lock=True)
        except BaseException:
            restore_payload(payload, original)
            raise
    return result


def extract_resume_instruction(status_path: Path) -> str:
    text = read_text_strict(status_path)
    match = re.search(r"(?ms)^## Resume instruction\s*$\s*(.*?)(?=^## |\Z)", text)
    if not match:
        raise TeamworkError("STATUS.md has no 'Resume instruction' section")
    lines = [
        line.strip()
        for line in match.group(1).splitlines()
        if line.strip() and not line.strip().startswith("<!--")
    ]
    if not lines:
        raise TeamworkError("STATUS.md resume instruction is empty")
    instruction = " ".join(lines)
    if contains_terminal_controls(instruction):
        raise TeamworkError("STATUS.md resume instruction contains terminal controls")
    if len(instruction) > MAX_RESUME_ACTION_CHARS:
        raise TeamworkError(
            f"STATUS.md resume instruction exceeds {MAX_RESUME_ACTION_CHARS} characters"
        )
    return instruction


def resume(args: argparse.Namespace) -> dict[str, Any]:
    payload = locate_payload(args)
    validate_payload_name(payload.name)
    if is_unsafe_link(payload) or not payload.is_dir():
        raise TeamworkError(f"Payload directory not found or unsafe: {payload}")
    with payload_lock(payload):
        # Integrity and contract validation must happen before any repository mutation.
        verify_payload(payload, require_ready=True, allow_lock=True, verify_git=False)
        exclude_change: tuple[Path, bytes | None, bytes] | None = None
        try:
            if shutil.which("git"):
                probe = run_git(payload.parent, "rev-parse", "--show-toplevel")
                if probe.returncode == 0 and probe.stdout.strip():
                    top_level = Path(probe.stdout.strip()).resolve()
                    if top_level != payload.parent.resolve():
                        raise TeamworkError(
                            f"Payload parent must be the Git repository root: {payload.parent} (Git root: {top_level})"
                        )
                    _warnings, exclude_change = ensure_git_excluded(
                        payload.parent.resolve(), payload.name, is_git=True
                    )
            result = verify_payload(payload, require_ready=True, allow_lock=True)
            manifest = load_json(payload / "manifest.json")
            extra_roots = [Path(value) for value in (args.source_root or [])]
            result.update(
                {
                    "consumer": runtime_facts(args.agent, args.harness),
                    "first_action": extract_resume_instruction(payload / "STATUS.md"),
                    "producer": manifest.get("producer"),
                    "reading_order": [
                        str(payload / name)
                        for name in manifest["resume"]["required_read_order"]
                    ],
                    "relocated": str(payload.parent.resolve())
                    != str(manifest["project"].get("root_hint")),
                    "source_provenance": compare_source_provenance(
                        payload, payload.parent.resolve(), extra_roots
                    ),
                }
            )
        except BaseException:
            restore_git_exclude(exclude_change)
            raise
    return result


def render_result(result: dict[str, Any], as_json: bool) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return
    print(f"Payload: {result.get('payload')}")
    if result.get("project_root"):
        print(f"Project root: {result['project_root']}")
    if result.get("state"):
        print(f"State: {result['state']}")
    if result.get("revision") is not None:
        print(f"Revision: {result['revision']}")
    if result.get("candidate_count") is not None:
        print(f"Context candidates: {result['candidate_count']}")
    if result.get("first_action"):
        print(f"First action: {result['first_action']}")
    if result.get("reading_order"):
        print("Reading order:")
        for path in result["reading_order"]:
            print(f"- {path}")
    provenance = result.get("source_provenance")
    if provenance:
        print(
            "Source provenance: "
            f"{provenance['unchanged_count']} unchanged, {provenance['changed_count']} changed, "
            f"{provenance['missing_count']} missing, {provenance['new_count']} new"
        )
        for category in ("changed", "missing", "new"):
            for item in provenance[category]:
                print(f"- {category}: {item['id']} {item['path']}")
    for warning in result.get("warnings", []):
        print(f"Warning: {warning}")


def add_common_location_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--repo", help="Repository root or a path inside it")
    parser.add_argument(
        "--payload-dir", default=DEFAULT_PAYLOAD_DIR, help="Payload directory name"
    )
    parser.add_argument(
        "--json", action="store_true", help="Emit machine-readable JSON"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=SKILL_VERSION)
    subparsers = parser.add_subparsers(dest="command", required=True)

    prepare_parser = subparsers.add_parser(
        "prepare", help="Create or refresh a draft payload"
    )
    add_common_location_arguments(prepare_parser)
    prepare_parser.add_argument("--agent", help="Producing agent name or model")
    prepare_parser.add_argument("--harness", help="Producing harness name")
    prepare_parser.add_argument(
        "--source-root", action="append", help="Additional allowlisted guidance root"
    )
    prepare_parser.add_argument(
        "--allow-non-git",
        action="store_true",
        help="Permit non-Git projects with warning",
    )

    for name, help_text in (
        ("seal", "Validate content and seal a ready payload"),
        ("verify", "Verify schema, integrity, sensitivity, and Git exclusion"),
        ("resume", "Verify payload and emit the canonical resume plan"),
    ):
        command_parser = subparsers.add_parser(name, help=help_text)
        add_common_location_arguments(command_parser)
        command_parser.add_argument(
            "--payload", help="Explicit payload directory or manifest path"
        )
        command_parser.add_argument(
            "--search-root",
            help="Bounded search root when payload is not above current path",
        )
    verify_parser = subparsers.choices["verify"]
    verify_parser.add_argument(
        "--allow-draft", action="store_true", help="Verify a draft payload"
    )
    resume_parser = subparsers.choices["resume"]
    resume_parser.add_argument("--agent", help="Resuming agent name or model")
    resume_parser.add_argument("--harness", help="Resuming harness name")
    resume_parser.add_argument(
        "--source-root", action="append", help="Additional allowlisted guidance root"
    )
    return parser


def configure_standard_streams() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="backslashreplace")
            except (OSError, ValueError):
                pass


def main(argv: Sequence[str] | None = None) -> int:
    configure_standard_streams()
    if sys.version_info < MIN_PYTHON:
        print("ERROR: Teamwork requires Python 3.11+", file=sys.stderr)
        return 2
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "prepare":
            result = prepare(args)
        elif args.command == "seal":
            result = seal(args)
        elif args.command == "verify":
            payload = locate_payload(args)
            result = verify_payload(payload, require_ready=not args.allow_draft)
        elif args.command == "resume":
            result = resume(args)
        else:
            parser.error(f"Unknown command: {args.command}")
            return 2
        render_result(result, args.json)
        return 0
    except (TeamworkError, OSError, UnicodeError) as exc:
        if getattr(args, "json", False):
            print(
                json.dumps({"error": str(exc), "ok": False}, indent=2), file=sys.stderr
            )
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
