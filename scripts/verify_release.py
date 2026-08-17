#!/usr/bin/env python3
"""Verify an extracted Teamwork release against its embedded manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from datetime import datetime
from pathlib import Path, PurePosixPath


SEMVER_PATTERN = (
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*))"
    r"(?:\.(?:(?:0|[1-9][0-9]*)|(?:[0-9]*[A-Za-z-][0-9A-Za-z-]*)))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)
MAX_RELEASE_FILE_BYTES = 2_097_152
MAX_ARCHIVE_TOTAL_BYTES = 12_582_912
MAX_RELEASE_ENTRIES = 64


def is_unsafe_link(path: Path) -> bool:
    """Return true for symbolic links and Windows reparse points."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x400
    )


def hash_file(path: Path, algorithm: str) -> str:
    digest = (
        hashlib.sha1(usedforsecurity=False)
        if algorithm == "sha1"
        else hashlib.new(algorithm)
    )
    total = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(131_072), b""):
            total += len(chunk)
            if total > MAX_RELEASE_FILE_BYTES:
                raise RuntimeError(
                    f"Release file exceeds {MAX_RELEASE_FILE_BYTES} bytes: {path}"
                )
            digest.update(chunk)
    return digest.hexdigest()


def sha256_file(path: Path) -> str:
    return hash_file(path, "sha256")


def sha1_file(path: Path) -> str:
    return hash_file(path, "sha1")


def strict_timestamp(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value
    ):
        raise RuntimeError("Release source timestamp is invalid")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RuntimeError("Release source timestamp is invalid") from exc
    return value


def content_identity(files: dict[str, str]) -> str:
    material = "".join(f"{name}\0{digest}\n" for name, digest in sorted(files.items()))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def verify(root: Path, installed_skills_root: Path | None = None) -> dict[str, object]:
    root = root.expanduser()
    if is_unsafe_link(root) or not root.is_dir():
        raise RuntimeError("Extracted release root is missing or unsafe")
    root = root.resolve()
    manifest_path = root / "release-manifest.json"
    if is_unsafe_link(manifest_path) or not manifest_path.is_file():
        raise RuntimeError("release-manifest.json is missing or unsafe")
    if manifest_path.stat().st_size > MAX_RELEASE_FILE_BYTES:
        raise RuntimeError("release-manifest.json exceeds the file size limit")
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
        "object_format",
    }:
        raise RuntimeError("Release source provenance is noncanonical")
    if not isinstance(source["available"], bool):
        raise RuntimeError("Release source availability must be boolean")
    if source["available"]:
        object_format = source["object_format"]
        commit_lengths = {"sha1": 40, "sha256": 64}
        if (
            object_format not in commit_lengths
            or not isinstance(source["commit"], str)
            or not re.fullmatch(
                rf"[0-9a-f]{{{commit_lengths.get(object_format, 0)}}}",
                source["commit"],
            )
            or not isinstance(source["dirty"], bool)
        ):
            raise RuntimeError("Release source provenance is invalid")
        strict_timestamp(source["created_at"])
    elif (
        source["commit"] is not None
        or source["created_at"] is not None
        or source["dirty"] is not None
        or source["object_format"] is not None
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
    total_size = 0
    visited_entries = 0
    for path in root.rglob("*"):
        visited_entries += 1
        if visited_entries > MAX_RELEASE_ENTRIES:
            raise RuntimeError("Extracted release exceeds the entry-count limit")
        if is_unsafe_link(path):
            raise RuntimeError(
                f"Link or reparse point is not allowed in extracted release: {path}"
            )
        if path.is_file():
            size = path.stat().st_size
            if size > MAX_RELEASE_FILE_BYTES:
                raise RuntimeError(
                    f"Release file exceeds {MAX_RELEASE_FILE_BYTES} bytes: {path}"
                )
            total_size += size
            if total_size > MAX_ARCHIVE_TOTAL_BYTES:
                raise RuntimeError("Extracted release exceeds the total size limit")
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
    expected_sbom_fields = {
        "SPDXID",
        "creationInfo",
        "dataLicense",
        "documentNamespace",
        "files",
        "hasExtractedLicensingInfos",
        "name",
        "packages",
        "relationships",
        "spdxVersion",
    }
    if not isinstance(sbom, dict) or set(sbom) != expected_sbom_fields:
        raise RuntimeError("SPDX SBOM metadata is invalid")
    base_hashes = {
        name: digest for name, digest in files.items() if name != "SBOM.spdx.json"
    }
    source_identity = (
        source["commit"]
        if source["available"] and source["dirty"] is False
        else content_identity(base_hashes)
    )
    created_at = source["created_at"] if source["available"] else "1980-01-01T00:00:00Z"
    expected_license = {
        "extractedText": "Proprietary. Use requires authorization from the copyright holder or another applicable agreement.",
        "licenseId": "LicenseRef-Teamwork-Proprietary",
        "name": "Teamwork Proprietary License",
    }
    expected_package = {
        "SPDXID": "SPDXRef-Package-Teamwork",
        "copyrightText": "NOASSERTION",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": True,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "LicenseRef-Teamwork-Proprietary",
        "name": "teamwork-skills",
        "versionInfo": manifest["version"],
    }
    if (
        sbom["SPDXID"] != "SPDXRef-DOCUMENT"
        or sbom["spdxVersion"] != "SPDX-2.3"
        or sbom["dataLicense"] != "CC0-1.0"
        or sbom["name"] != f"teamwork-skills-{manifest['version']}"
        or sbom["documentNamespace"]
        != f"urn:teamwork:spdx:{manifest['version']}:{source_identity}"
        or sbom["creationInfo"]
        != {"created": created_at, "creators": ["Tool: teamwork-build-release"]}
        or sbom["packages"] != [expected_package]
        or sbom["hasExtractedLicensingInfos"] != [expected_license]
        or not isinstance(sbom["files"], list)
    ):
        raise RuntimeError("SPDX SBOM semantic binding is invalid")
    sbom_hashes: dict[str, str] = {}
    expected_sbom_names = sorted(base_hashes)
    if len(sbom["files"]) != len(expected_sbom_names):
        raise RuntimeError("SPDX SBOM file inventory does not match release manifest")
    expected_relationships = [
        {
            "relatedSpdxElement": "SPDXRef-Package-Teamwork",
            "relationshipType": "DESCRIBES",
            "spdxElementId": "SPDXRef-DOCUMENT",
        }
    ]
    for index, (item, expected_name) in enumerate(
        zip(sbom["files"], expected_sbom_names, strict=True), start=1
    ):
        if (
            not isinstance(item, dict)
            or set(item)
            != {
                "SPDXID",
                "checksums",
                "copyrightText",
                "fileName",
                "licenseConcluded",
            }
            or item.get("SPDXID") != f"SPDXRef-File-{index}"
            or item.get("copyrightText") != "NOASSERTION"
            or item.get("licenseConcluded") != "NOASSERTION"
            or item.get("fileName") != f"./{expected_name}"
        ):
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
        name = expected_name
        if name in sbom_hashes:
            raise RuntimeError(f"SPDX SBOM duplicates file: {name}")
        sbom_hashes[name] = checksum_map["SHA256"]
        path = root.joinpath(*PurePosixPath(name).parts)
        if sha1_file(path) != checksum_map["SHA1"]:
            raise RuntimeError(f"SPDX SBOM SHA1 mismatch: {name}")
        expected_relationships.append(
            {
                "relatedSpdxElement": f"SPDXRef-File-{index}",
                "relationshipType": "CONTAINS",
                "spdxElementId": "SPDXRef-Package-Teamwork",
            }
        )
    if sbom_hashes != base_hashes:
        raise RuntimeError("SPDX SBOM file inventory does not match release manifest")
    if sbom["relationships"] != expected_relationships:
        raise RuntimeError("SPDX SBOM relationships are invalid")
    result: dict[str, object] = {
        "file_count": len(files),
        "ok": True,
        "release_grade": bool(source["available"] and source["dirty"] is False),
        "source": source,
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
            visited_entries = 0
            for path in skill_root.rglob("*"):
                visited_entries += 1
                if visited_entries > MAX_RELEASE_ENTRIES:
                    raise RuntimeError(
                        f"Installed {skill} exceeds the entry-count limit"
                    )
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
