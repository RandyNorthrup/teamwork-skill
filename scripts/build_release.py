#!/usr/bin/env python3
"""Build a deterministic, self-verifying Teamwork skill archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
SKILLS = ("teamwork-handoff", "teamwork-resume")
ARCHIVE_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
MAX_RELEASE_FILE_BYTES = 2_097_152
MAX_RELEASE_TOTAL_BYTES = 10_485_760
MAX_ARCHIVE_TOTAL_BYTES = 12_582_912
SEMVER_PATTERN = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*))"
    r"(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
SKILL_FILES = (
    "SKILL.md",
    "agents/openai.yaml",
    "references/payload-contract.md",
    "references/teamwork-manifest.schema.json",
    "scripts/teamwork_payload.py",
)
ROOT_FILES = {
    "INSTALL.md": "INSTALL.md",
    "LICENSE.txt": "LICENSE.txt",
    "verify_release.py": "scripts/verify_release.py",
}
CANONICAL_FILES = {
    "scripts/teamwork_payload.py": "src/teamwork_payload.py",
    "references/payload-contract.md": "docs/PAYLOAD_CONTRACT.md",
    "references/teamwork-manifest.schema.json": "schemas/teamwork-manifest.schema.json",
}


def is_unsafe_link(path: Path) -> bool:
    """Return true for symbolic links and Windows reparse points."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def canonicalize_macos_system_alias(path: Path) -> Path:
    """Resolve only Apple's fixed /var and /tmp compatibility aliases.

    macOS returns temporary paths below ``/var`` even though that root entry is
    a system-owned link to ``/private/var``. Arbitrary linked descendants must
    still fail the output-path check.
    """
    if sys.platform != "darwin":
        return path
    aliases = (
        (Path("/var"), Path("/private/var")),
        (Path("/tmp"), Path("/private/tmp")),
    )
    for alias, expected in aliases:
        try:
            relative = path.relative_to(alias)
        except ValueError:
            continue
        try:
            if not alias.is_symlink() or alias.resolve(strict=True) != expected:
                continue
        except OSError:
            continue
        return expected / relative
    return path


def ensure_safe_output_path(path: Path, label: str) -> Path:
    """Validate the lexical path before resolving any filesystem links."""
    supplied = Path(os.path.abspath(str(path.expanduser())))
    supplied = canonicalize_macos_system_alias(supplied)
    cursor = supplied.parent
    while True:
        if cursor.exists() and is_unsafe_link(cursor):
            raise RuntimeError(
                f"{label} parent contains a link or reparse point: {cursor}"
            )
        if cursor.parent == cursor:
            break
        cursor = cursor.parent
    if supplied.exists() and (is_unsafe_link(supplied) or not supplied.is_file()):
        raise RuntimeError(f"{label} is not a regular file: {supplied}")
    parent = supplied.parent.resolve()
    return parent / supplied.name


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha1_bytes(value: bytes) -> str:
    return hashlib.sha1(value, usedforsecurity=False).hexdigest()


def content_identity(files: dict[str, bytes]) -> str:
    material = "".join(
        f"{name}\0{sha256_bytes(content)}\n" for name, content in sorted(files.items())
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def validate_source_files(
    files: dict[str, bytes], canonical_contents: dict[str, bytes]
) -> dict[str, bytes]:
    for relative, expected in canonical_contents.items():
        for skill in SKILLS:
            packaged = files.get(f"{skill}/{relative}")
            if packaged != expected:
                raise RuntimeError(
                    f"Embedded resource drift: {skill}/{relative}; run scripts/sync_skills.py"
                )
    total = 0
    for name, content in files.items():
        if name.startswith("/") or ".." in Path(name).parts or "\\" in name:
            raise RuntimeError(f"Unsafe archive path: {name}")
        if len(content) > MAX_RELEASE_FILE_BYTES:
            raise RuntimeError(
                f"Release file exceeds {MAX_RELEASE_FILE_BYTES} bytes: {name}"
            )
        total += len(content)
    if total > MAX_RELEASE_TOTAL_BYTES:
        raise RuntimeError(f"Release content exceeds {MAX_RELEASE_TOTAL_BYTES} bytes")
    return files


def source_files() -> dict[str, bytes]:
    """Read a development build from the current working tree."""
    files: dict[str, bytes] = {}
    for skill in SKILLS:
        skill_root = ROOT / "skills" / skill
        actual: set[str] = set()
        for path in sorted(skill_root.rglob("*")):
            if is_unsafe_link(path):
                raise RuntimeError(f"Skill package cannot contain symlink: {path}")
            if (
                path.is_file()
                and "__pycache__" not in path.parts
                and path.suffix not in {".pyc", ".pyo"}
            ):
                actual.add(path.relative_to(skill_root).as_posix())
        unexpected = actual - set(SKILL_FILES)
        missing = set(SKILL_FILES) - actual
        if unexpected or missing:
            raise RuntimeError(
                f"Skill package contents differ from allowlist for {skill}; "
                f"unexpected={sorted(unexpected)}, missing={sorted(missing)}"
            )
        for relative in SKILL_FILES:
            path = skill_root / relative
            files[f"{skill}/{relative}"] = path.read_bytes()
    for relative, repository_path in ROOT_FILES.items():
        path = ROOT / repository_path
        if is_unsafe_link(path) or not path.is_file():
            raise RuntimeError(f"Required release file is missing or unsafe: {path}")
        files[relative] = path.read_bytes()
    canonical_contents = {
        archive_path: (ROOT / repository_path).read_bytes()
        for archive_path, repository_path in CANONICAL_FILES.items()
    }
    return validate_source_files(files, canonical_contents)


def git_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"
    return environment


def git_capture_bytes(max_bytes: int, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(ROOT), *args],
        capture_output=True,
        check=False,
        env=git_environment(),
        timeout=30,
    )
    if result.returncode != 0:
        detail = result.stderr[:4_096].decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Git object read failed: git {' '.join(args)}: {detail}")
    if len(result.stdout) > max_bytes or len(result.stderr) > 4_096:
        raise RuntimeError(
            f"Git object read exceeded its output limit: {' '.join(args)}"
        )
    return result.stdout


def git_blob(commit: str, repository_path: str) -> bytes:
    specification = f"{commit}:{repository_path}"
    raw_size = git_capture_bytes(128, "cat-file", "-s", specification)
    try:
        size = int(raw_size.decode("ascii").strip())
    except (UnicodeError, ValueError) as exc:
        raise RuntimeError(f"Git blob size is invalid: {repository_path}") from exc
    if size > MAX_RELEASE_FILE_BYTES:
        raise RuntimeError(
            f"Release file exceeds {MAX_RELEASE_FILE_BYTES} bytes: {repository_path}"
        )
    content = git_capture_bytes(MAX_RELEASE_FILE_BYTES, "show", specification)
    if len(content) != size:
        raise RuntimeError(f"Git blob size changed while reading: {repository_path}")
    return content


def git_release_capture(commit: str) -> tuple[bytes, dict[str, bytes]]:
    """Read clean-release bytes from immutable Git blobs, not checkout filters."""
    archive_to_repository = {
        **{
            f"{skill}/{relative}": f"skills/{skill}/{relative}"
            for skill in SKILLS
            for relative in SKILL_FILES
        },
        **ROOT_FILES,
    }
    expected_repository_paths = (
        set(archive_to_repository.values())
        | set(CANONICAL_FILES.values())
        | {"VERSION"}
    )
    tree_output = git_capture_bytes(
        MAX_RELEASE_FILE_BYTES,
        "ls-tree",
        "-r",
        "-z",
        commit,
        "--",
        *(f"skills/{skill}" for skill in SKILLS),
        *(
            path
            for path in sorted(expected_repository_paths)
            if not path.startswith("skills/")
        ),
    )
    observed: set[str] = set()
    for raw_entry in tree_output.split(b"\0"):
        if not raw_entry:
            continue
        try:
            metadata, raw_path = raw_entry.split(b"\t", 1)
            mode, object_type, _object_id = metadata.decode("ascii").split()
            repository_path = raw_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError) as exc:
            raise RuntimeError("Git tree metadata is invalid") from exc
        if mode not in {"100644", "100755"} or object_type != "blob":
            raise RuntimeError(
                f"Release source is not a regular Git blob: {repository_path}"
            )
        observed.add(repository_path)
    if observed != expected_repository_paths:
        raise RuntimeError(
            "Committed release source differs from allowlist; "
            f"unexpected={sorted(observed - expected_repository_paths)}, "
            f"missing={sorted(expected_repository_paths - observed)}"
        )
    repository_contents = {
        path: git_blob(commit, path) for path in sorted(expected_repository_paths)
    }
    files = {
        archive_path: repository_contents[repository_path]
        for archive_path, repository_path in archive_to_repository.items()
    }
    canonical_contents = {
        archive_path: repository_contents[repository_path]
        for archive_path, repository_path in CANONICAL_FILES.items()
    }
    return repository_contents["VERSION"], validate_source_files(
        files, canonical_contents
    )


def git_source_files(commit: str) -> dict[str, bytes]:
    return git_release_capture(commit)[1]


def working_release_capture() -> tuple[bytes, dict[str, bytes]]:
    version_path = ROOT / "VERSION"
    version_bytes = version_path.read_bytes()
    if len(version_bytes) > 128:
        raise RuntimeError("VERSION exceeds its size limit")
    return version_bytes, source_files()


def parse_version(content: bytes) -> str:
    try:
        text = content.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise RuntimeError("VERSION is not strict UTF-8") from exc
    if not re.fullmatch(f"{SEMVER_PATTERN}(?:\\r?\\n)?", text):
        raise RuntimeError("VERSION is not canonical SemVer")
    return text.rstrip("\r\n")


def zip_info(name: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, ARCHIVE_TIMESTAMP)
    info.compress_type = zipfile.ZIP_STORED
    info.create_system = 3
    info.external_attr = 0o100644 << 16
    return info


def build_sbom(
    version: str, files: dict[str, bytes], provenance: dict[str, object]
) -> bytes:
    spdx_files = []
    relationships = []
    for index, (name, content) in enumerate(sorted(files.items()), start=1):
        identifier = f"SPDXRef-File-{index}"
        spdx_files.append(
            {
                "SPDXID": identifier,
                "checksums": [
                    {"algorithm": "SHA1", "checksumValue": sha1_bytes(content)},
                    {"algorithm": "SHA256", "checksumValue": sha256_bytes(content)},
                ],
                "copyrightText": "NOASSERTION",
                "fileName": f"./{name}",
                "licenseConcluded": "NOASSERTION",
            }
        )
        relationships.append(
            {
                "relatedSpdxElement": identifier,
                "relationshipType": "CONTAINS",
                "spdxElementId": "SPDXRef-Package-Teamwork",
            }
        )
    source_identity = (
        provenance.get("commit")
        if provenance.get("available") is True and provenance.get("dirty") is False
        else content_identity(files)
    )
    if not isinstance(source_identity, str):
        raise RuntimeError("Cannot derive SPDX source identity")
    created_at = provenance.get("created_at")
    if not isinstance(created_at, str):
        created_at = "1980-01-01T00:00:00Z"
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": created_at,
            "creators": ["Tool: teamwork-build-release"],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"urn:teamwork:spdx:{version}:{source_identity}",
        "files": spdx_files,
        "name": f"teamwork-skills-{version}",
        "packages": [
            {
                "SPDXID": "SPDXRef-Package-Teamwork",
                "copyrightText": "Copyright (c) 2026 Randy Northrup",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "MIT",
                "licenseDeclared": "MIT",
                "name": "teamwork-skills",
                "versionInfo": version,
            }
        ],
        "relationships": [
            {
                "relatedSpdxElement": "SPDXRef-Package-Teamwork",
                "relationshipType": "DESCRIBES",
                "spdxElementId": "SPDXRef-DOCUMENT",
            },
            *relationships,
        ],
        "hasExtractedLicensingInfos": [],
        "spdxVersion": "SPDX-2.3",
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def git_provenance(require_clean: bool) -> dict[str, object]:
    def git(*args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            ["git", "-C", str(ROOT), *args],
            text=True,
            encoding="utf-8",
            errors="replace",
            capture_output=True,
            check=False,
            env=git_environment(),
            timeout=30,
        )

    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    committed_at = git("show", "-s", "--format=%cI", "HEAD")
    object_format_result = git("rev-parse", "--show-object-format")
    object_format = object_format_result.stdout.strip()
    if object_format not in {"sha1", "sha256"}:
        object_format = "sha1" if len(head.stdout.strip()) == 40 else "sha256"
    available = (
        head.returncode == 0
        and bool(head.stdout.strip())
        and status.returncode == 0
        and committed_at.returncode == 0
        and bool(committed_at.stdout.strip())
        and object_format in {"sha1", "sha256"}
    )
    dirty = bool(status.stdout.strip()) if available else None
    if require_clean and (not available or dirty):
        raise RuntimeError(
            "A clean committed Git checkout is required for a release build"
        )
    created_at = None
    if available:
        try:
            created_at = (
                datetime.fromisoformat(committed_at.stdout.strip())
                .astimezone(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        except ValueError as exc:
            raise RuntimeError("Git commit timestamp is invalid") from exc
    return {
        "available": available,
        "commit": head.stdout.strip() if available else None,
        "created_at": created_at,
        "dirty": dirty,
        "object_format": object_format if available else None,
    }


def backup_existing(path: Path) -> Path | None:
    if not path.exists():
        return None
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as handle:
        backup = Path(handle.name)
    try:
        shutil.copyfile(path, backup)
        with backup.open("r+b") as handle:
            os.fsync(handle.fileno())
    except BaseException:
        backup.unlink(missing_ok=True)
        raise
    return backup


def commit_release_pair(
    archive_temp: Path, output: Path, sidecar_temp: Path, sidecar: Path
) -> None:
    """Replace archive and sidecar as one recoverable filesystem transaction."""
    output_backup: Path | None = None
    sidecar_backup: Path | None = None
    output_replaced = False
    sidecar_replaced = False
    try:
        output_backup = backup_existing(output)
        sidecar_backup = backup_existing(sidecar)
        os.replace(archive_temp, output)
        output_replaced = True
        os.replace(sidecar_temp, sidecar)
        sidecar_replaced = True
    except BaseException as exc:
        rollback_failures: list[str] = []
        for path, backup, replaced in (
            (output, output_backup, output_replaced),
            (sidecar, sidecar_backup, sidecar_replaced),
        ):
            try:
                if backup is not None:
                    os.replace(backup, path)
                elif replaced and path.exists():
                    path.unlink()
            except OSError as rollback_exc:
                rollback_failures.append(f"{path}: {rollback_exc}")
        if rollback_failures:
            raise RuntimeError(
                f"Release pair update failed ({exc}); rollback also failed: "
                + "; ".join(rollback_failures)
            ) from exc
        raise RuntimeError(
            f"Release pair update failed and was rolled back: {exc}"
        ) from exc
    finally:
        if output_backup is not None:
            output_backup.unlink(missing_ok=True)
        if sidecar_backup is not None:
            sidecar_backup.unlink(missing_ok=True)


def build(output: Path | None = None, require_clean: bool = False) -> dict[str, object]:
    provenance = git_provenance(require_clean)
    if provenance["available"] is True and provenance["dirty"] is False:
        commit = provenance["commit"]
        if not isinstance(commit, str):
            raise RuntimeError("Clean Git source provenance is missing a commit")
        version_bytes, files = git_release_capture(commit)
    else:
        version_bytes, files = working_release_capture()
        if working_release_capture() != (version_bytes, files):
            raise RuntimeError("Release source files changed while being captured")
    version = parse_version(version_bytes)
    confirmed_provenance = git_provenance(require_clean)
    if confirmed_provenance != provenance:
        raise RuntimeError("Git source provenance changed while release was captured")
    files["SBOM.spdx.json"] = build_sbom(version, files, provenance)
    release_manifest = {
        "archive_format": "teamwork-skills",
        "files": {
            name: sha256_bytes(content) for name, content in sorted(files.items())
        },
        "format_specification": "https://agentskills.io/specification",
        "minimum_python": "3.11",
        "source": provenance,
        "skills": list(SKILLS),
        "version": version,
    }
    manifest_bytes = (
        json.dumps(release_manifest, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    archive_files = dict(files)
    archive_files["release-manifest.json"] = manifest_bytes
    if any(len(content) > MAX_RELEASE_FILE_BYTES for content in archive_files.values()):
        raise RuntimeError("Generated release metadata exceeds the per-file size limit")
    if (
        sum(len(content) for content in archive_files.values())
        > MAX_ARCHIVE_TOTAL_BYTES
    ):
        raise RuntimeError("Generated release archive exceeds the total size limit")
    if output is None:
        output = ROOT / "dist" / f"teamwork-skills-{version}.zip"
    output = ensure_safe_output_path(output, "Release output")
    sidecar = ensure_safe_output_path(Path(str(output) + ".sha256"), "Checksum sidecar")
    for skill in SKILLS:
        try:
            output.relative_to((ROOT / "skills" / skill).resolve())
        except ValueError:
            pass
        else:
            raise RuntimeError(
                "Release output cannot be written inside a packaged skill directory"
            )
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=output.parent, suffix=".zip", delete=False
    ) as handle:
        temporary = Path(handle.name)
    sidecar_temp: Path | None = None
    try:
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in sorted(archive_files.items()):
                archive.writestr(zip_info(name), content)
        with temporary.open("r+b") as handle:
            os.fsync(handle.fileno())
        digest = hashlib.sha256(temporary.read_bytes()).hexdigest()
        sidecar_bytes = f"{digest}  {output.name}\n".encode("utf-8")
        with tempfile.NamedTemporaryFile(dir=sidecar.parent, delete=False) as handle:
            handle.write(sidecar_bytes)
            handle.flush()
            os.fsync(handle.fileno())
            sidecar_temp = Path(handle.name)
        commit_release_pair(temporary, output, sidecar_temp, sidecar)
    finally:
        temporary.unlink(missing_ok=True)
        if sidecar_temp is not None:
            sidecar_temp.unlink(missing_ok=True)
    return {
        "archive": str(output),
        "file_count": len(files) + 1,
        "sha256": digest,
        "sha256_file": str(sidecar),
        "version": version,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", help="Output ZIP path")
    parser.add_argument("--json", action="store_true", help="Emit JSON result")
    parser.add_argument(
        "--require-clean", action="store_true", help="Require committed clean source"
    )
    args = parser.parse_args(argv)
    output = Path(args.output) if args.output else None
    try:
        result = build(output, require_clean=args.require_clean)
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}")
        return 2
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(f"Archive: {result['archive']}")
        print(f"SHA-256: {result['sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
