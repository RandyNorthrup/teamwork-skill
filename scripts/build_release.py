#!/usr/bin/env python3
"""Build a deterministic, self-verifying Teamwork skill archive."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
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
    "INSTALL.md": ROOT / "INSTALL.md",
    "LICENSE.txt": ROOT / "LICENSE.txt",
    "verify_release.py": ROOT / "scripts" / "verify_release.py",
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


def ensure_safe_output_path(path: Path, label: str) -> Path:
    """Validate the lexical path before resolving any filesystem links."""
    supplied = Path(os.path.abspath(str(path.expanduser())))
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


def source_files() -> dict[str, bytes]:
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
    for relative, path in ROOT_FILES.items():
        if is_unsafe_link(path) or not path.is_file():
            raise RuntimeError(f"Required release file is missing or unsafe: {path}")
        files[relative] = path.read_bytes()
    canonical = {
        "scripts/teamwork_payload.py": ROOT / "src" / "teamwork_payload.py",
        "references/payload-contract.md": ROOT / "docs" / "PAYLOAD_CONTRACT.md",
        "references/teamwork-manifest.schema.json": ROOT
        / "schemas"
        / "teamwork-manifest.schema.json",
    }
    for relative, source in canonical.items():
        expected = source.read_bytes()
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
    source_identity = provenance.get("commit")
    if not isinstance(source_identity, str):
        source_identity = hashlib.sha256(
            "".join(
                sha256_bytes(content) for _name, content in sorted(files.items())
            ).encode("ascii")
        ).hexdigest()
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
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": True,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "LicenseRef-Teamwork-Proprietary",
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
        "hasExtractedLicensingInfos": [
            {
                "extractedText": "Proprietary. Use requires authorization from the copyright holder or another applicable agreement.",
                "licenseId": "LicenseRef-Teamwork-Proprietary",
                "name": "Teamwork Proprietary License",
            }
        ],
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
            timeout=30,
        )

    head = git("rev-parse", "HEAD")
    status = git("status", "--porcelain=v1", "--untracked-files=all")
    committed_at = git("show", "-s", "--format=%cI", "HEAD")
    available = (
        head.returncode == 0
        and bool(head.stdout.strip())
        and status.returncode == 0
        and committed_at.returncode == 0
        and bool(committed_at.stdout.strip())
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
    }


def build(output: Path, require_clean: bool = False) -> dict[str, object]:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    if not re.fullmatch(SEMVER_PATTERN, version):
        raise RuntimeError("VERSION is not valid SemVer")
    provenance = git_provenance(require_clean)
    files = source_files()
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
    try:
        archive_files = dict(files)
        archive_files["release-manifest.json"] = manifest_bytes
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_STORED) as archive:
            for name, content in sorted(archive_files.items()):
                archive.writestr(zip_info(name), content)
        os.replace(temporary, output)
    finally:
        temporary.unlink(missing_ok=True)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    sidecar_bytes = f"{digest}  {output.name}\n".encode("utf-8")
    with tempfile.NamedTemporaryFile(dir=sidecar.parent, delete=False) as handle:
        handle.write(sidecar_bytes)
        handle.flush()
        os.fsync(handle.fileno())
        sidecar_temp = Path(handle.name)
    try:
        os.replace(sidecar_temp, sidecar)
    finally:
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
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    output = (
        Path(args.output)
        if args.output
        else ROOT / "dist" / f"teamwork-skills-{version}.zip"
    )
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
