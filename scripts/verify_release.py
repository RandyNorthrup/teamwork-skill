#!/usr/bin/env python3
"""Verify an extracted Teamwork release against its embedded manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path, PurePosixPath


SEMVER_PATTERN = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*))"
    r"(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def is_unsafe_link(path: Path) -> bool:
    """Return true for symbolic links and Windows reparse points."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131_072), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify(root: Path, installed_skills_root: Path | None = None) -> dict[str, object]:
    root = root.expanduser()
    if is_unsafe_link(root) or not root.is_dir():
        raise RuntimeError("Extracted release root is missing or unsafe")
    root = root.resolve()
    manifest_path = root / "release-manifest.json"
    if is_unsafe_link(manifest_path) or not manifest_path.is_file():
        raise RuntimeError("release-manifest.json is missing or unsafe")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read release manifest: {exc}") from exc
    required = {
        "archive_format",
        "files",
        "format_specification",
        "minimum_python",
        "source",
        "skills",
        "version",
    }
    if not isinstance(manifest, dict) or set(manifest) != required:
        raise RuntimeError("Release manifest fields are noncanonical")
    if (
        manifest["archive_format"] != "teamwork-skills"
        or manifest["format_specification"] != "https://agentskills.io/specification"
        or manifest["minimum_python"] != "3.11"
        or manifest["skills"] != ["teamwork-handoff", "teamwork-resume"]
        or not isinstance(manifest["version"], str)
        or not re.fullmatch(SEMVER_PATTERN, manifest["version"])
    ):
        raise RuntimeError("Unsupported release manifest")
    source = manifest["source"]
    if not isinstance(source, dict) or set(source) != {
        "available",
        "commit",
        "created_at",
        "dirty",
    }:
        raise RuntimeError("Release source provenance is noncanonical")
    if not isinstance(source["available"], bool):
        raise RuntimeError("Release source availability must be boolean")
    if source["available"]:
        if (
            not isinstance(source["commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", source["commit"])
            or not isinstance(source["created_at"], str)
            or not re.fullmatch(
                r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z",
                source["created_at"],
            )
            or not isinstance(source["dirty"], bool)
        ):
            raise RuntimeError("Release source provenance is invalid")
    elif (
        source["commit"] is not None
        or source["created_at"] is not None
        or source["dirty"] is not None
    ):
        raise RuntimeError("Unavailable release source provenance must use null values")
    files = manifest.get("files")
    if not isinstance(files, dict) or not files:
        raise RuntimeError("Release file map is missing")
    required_files = {
        "INSTALL.md",
        "LICENSE.txt",
        "SBOM.spdx.json",
        "verify_release.py",
    }
    for skill in ("teamwork-handoff", "teamwork-resume"):
        required_files.update(
            {
                f"{skill}/SKILL.md",
                f"{skill}/agents/openai.yaml",
                f"{skill}/references/payload-contract.md",
                f"{skill}/references/teamwork-manifest.schema.json",
                f"{skill}/scripts/teamwork_payload.py",
            }
        )
    if set(files) != required_files:
        raise RuntimeError("Release file map does not match the canonical package")
    expected = set(files) | {"release-manifest.json"}
    actual: set[str] = set()
    for path in root.rglob("*"):
        if is_unsafe_link(path):
            raise RuntimeError(
                f"Link or reparse point is not allowed in extracted release: {path}"
            )
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != expected:
        raise RuntimeError(
            f"Extracted release file set differs: unexpected={sorted(actual - expected)}, "
            f"missing={sorted(expected - actual)}"
        )
    for name, digest in files.items():
        parts = PurePosixPath(name).parts if isinstance(name, str) else ()
        if (
            not parts
            or name.startswith("/")
            or "\\" in name
            or any(part in {"", ".", ".."} for part in parts)
            or not isinstance(digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", digest)
        ):
            raise RuntimeError(f"Unsafe release file entry: {name!r}")
        path = root.joinpath(*parts)
        if is_unsafe_link(path) or not path.is_file() or sha256_file(path) != digest:
            raise RuntimeError(f"Release file verification failed: {name}")
    try:
        sbom = json.loads((root / "SBOM.spdx.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"Cannot read SPDX SBOM: {exc}") from exc
    if (
        not isinstance(sbom, dict)
        or sbom.get("spdxVersion") != "SPDX-2.3"
        or sbom.get("name") != f"teamwork-skills-{manifest['version']}"
        or not isinstance(sbom.get("files"), list)
    ):
        raise RuntimeError("SPDX SBOM metadata is invalid")
    sbom_hashes: dict[str, str] = {}
    for item in sbom["files"]:
        if not isinstance(item, dict) or not isinstance(item.get("fileName"), str):
            raise RuntimeError("SPDX SBOM file entry is invalid")
        checksums = item.get("checksums")
        if (
            not isinstance(checksums, list)
            or len(checksums) != 2
            or any(not isinstance(checksum, dict) for checksum in checksums)
        ):
            raise RuntimeError("SPDX SBOM checksum entry is invalid")
        checksum_map = {
            checksum.get("algorithm"): checksum.get("checksumValue")
            for checksum in checksums
        }
        if (
            set(checksum_map) != {"SHA1", "SHA256"}
            or not isinstance(checksum_map["SHA1"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", checksum_map["SHA1"])
            or not isinstance(checksum_map["SHA256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", checksum_map["SHA256"])
        ):
            raise RuntimeError("SPDX SBOM checksum entry is invalid")
        name = item["fileName"].removeprefix("./")
        if name in sbom_hashes:
            raise RuntimeError(f"SPDX SBOM duplicates file: {name}")
        sbom_hashes[name] = checksum_map["SHA256"]
    expected_sbom_hashes = {
        name: digest for name, digest in files.items() if name != "SBOM.spdx.json"
    }
    if sbom_hashes != expected_sbom_hashes:
        raise RuntimeError("SPDX SBOM file inventory does not match release manifest")
    result: dict[str, object] = {
        "file_count": len(files),
        "ok": True,
        "version": manifest["version"],
    }
    if installed_skills_root is not None:
        supplied_root = installed_skills_root.expanduser()
        if is_unsafe_link(supplied_root) or not supplied_root.is_dir():
            raise RuntimeError("Installed skills root is missing or unsafe")
        installed_root = supplied_root.resolve()
        installed_files = {
            name: digest
            for name, digest in files.items()
            if name.startswith("teamwork-handoff/")
            or name.startswith("teamwork-resume/")
        }
        for skill in ("teamwork-handoff", "teamwork-resume"):
            skill_root = installed_root / skill
            if is_unsafe_link(skill_root) or not skill_root.is_dir():
                raise RuntimeError(
                    f"Installed skill directory is missing or unsafe: {skill}"
                )
        for name, digest in installed_files.items():
            path = installed_root.joinpath(*PurePosixPath(name).parts)
            relative_parts = PurePosixPath(name).parts
            parents = [
                installed_root.joinpath(*relative_parts[:index])
                for index in range(1, len(relative_parts))
            ]
            if (
                any(is_unsafe_link(parent) for parent in parents)
                or is_unsafe_link(path)
                or not path.is_file()
                or sha256_file(path) != digest
            ):
                raise RuntimeError(f"Installed skill verification failed: {name}")
        for skill in ("teamwork-handoff", "teamwork-resume"):
            skill_root = installed_root / skill
            installed_actual: set[str] = set()
            for path in skill_root.rglob("*"):
                if is_unsafe_link(path):
                    raise RuntimeError(
                        f"Installed skill contains a link or reparse point: {path}"
                    )
                if path.is_file():
                    installed_actual.add(path.relative_to(installed_root).as_posix())
            expected_skill = {
                name for name in installed_files if name.startswith(f"{skill}/")
            }
            if installed_actual != expected_skill:
                raise RuntimeError(
                    f"Installed {skill} file set differs: "
                    f"unexpected={sorted(installed_actual - expected_skill)}, "
                    f"missing={sorted(expected_skill - installed_actual)}"
                )
        result["installed_skills_root"] = str(installed_root)
        result["installed_verified"] = True
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", default=Path(__file__).resolve().parent)
    parser.add_argument("--installed-skills-root", type=Path)
    args = parser.parse_args()
    try:
        result = verify(Path(args.root), args.installed_skills_root)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
