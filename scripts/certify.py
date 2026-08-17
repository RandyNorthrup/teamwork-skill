#!/usr/bin/env python3
"""Run deterministic Teamwork code and local end-to-end certification gates."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import zipfile
import argparse
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run(command: list[str]) -> None:
    print(f"> {' '.join(command)}", flush=True)
    result = subprocess.run(command, cwd=ROOT, check=False)
    if result.returncode != 0:
        raise SystemExit(result.returncode)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", type=Path, help="Write a machine-readable certification report"
    )
    parser.add_argument(
        "--require-clean",
        action="store_true",
        help="Require a clean committed source identity for the release artifact",
    )
    args = parser.parse_args()
    if sys.version_info < (3, 11):
        print("Python 3.11+ is required", file=sys.stderr)
        return 2
    run([sys.executable, str(ROOT / "scripts" / "sync_skills.py"), "--check"])
    run([sys.executable, str(ROOT / "scripts" / "check_version.py")])
    scripts = [
        ROOT / "src" / "teamwork_payload.py",
        ROOT / "skills" / "teamwork-handoff" / "scripts" / "teamwork_payload.py",
        ROOT / "skills" / "teamwork-resume" / "scripts" / "teamwork_payload.py",
        ROOT / "scripts" / "sync_skills.py",
        ROOT / "scripts" / "build_release.py",
        ROOT / "scripts" / "certify.py",
        ROOT / "scripts" / "check_version.py",
        ROOT / "scripts" / "run_tests.py",
        ROOT / "scripts" / "validate_schema.py",
        ROOT / "scripts" / "validate_sbom.py",
        ROOT / "scripts" / "verify_release.py",
    ]
    run([sys.executable, "-m", "py_compile", *map(str, scripts)])
    run([sys.executable, "-m", "ruff", "check", "src", "scripts", "tests"])
    run([sys.executable, "-m", "ruff", "format", "--check", "src", "scripts", "tests"])
    run(
        [
            sys.executable,
            "-m",
            "mypy",
            "src/teamwork_payload.py",
            "scripts/build_release.py",
            "scripts/verify_release.py",
            "scripts/check_version.py",
            "scripts/run_tests.py",
            "scripts/validate_schema.py",
            "scripts/validate_sbom.py",
        ]
    )
    run([sys.executable, str(ROOT / "scripts" / "validate_schema.py")])
    with tempfile.TemporaryDirectory() as temporary:
        test_report_path = Path(temporary) / "tests.json"
        coverage_report_path = Path(temporary) / "coverage.json"
        archive = Path(temporary) / "teamwork-skills.zip"
        extracted = Path(temporary) / "extracted"
        run([sys.executable, "-m", "coverage", "erase"])
        run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                str(ROOT / "scripts" / "run_tests.py"),
                "--output",
                str(test_report_path),
            ]
        )
        run([sys.executable, "-m", "coverage", "combine"])
        run([sys.executable, "-m", "coverage", "report", "--fail-under=80"])
        run(
            [
                sys.executable,
                "-m",
                "coverage",
                "json",
                "-o",
                str(coverage_report_path),
            ]
        )
        build_command = [
            sys.executable,
            str(ROOT / "scripts" / "build_release.py"),
            "--output",
            str(archive),
            "--json",
        ]
        if args.require_clean:
            build_command.append("--require-clean")
        run(build_command)
        with zipfile.ZipFile(archive) as release:
            release_manifest = json.loads(release.read("release-manifest.json"))
            release.extractall(extracted)
        run([sys.executable, str(extracted / "verify_release.py"), str(extracted)])
        run(
            [
                sys.executable,
                str(ROOT / "scripts" / "validate_sbom.py"),
                str(extracted / "SBOM.spdx.json"),
            ]
        )
        test_report = json.loads(test_report_path.read_text(encoding="utf-8"))
        coverage_report = json.loads(coverage_report_path.read_text(encoding="utf-8"))
        release_sha256 = hashlib.sha256(archive.read_bytes()).hexdigest()
    git_head = subprocess.run(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
    )
    result = {
        "claim_level": "LocalE2ECertified",
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "operating_system": platform.platform(),
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "gates": [
            "sync-check",
            "version-governance",
            "compile",
            "ruff-lint",
            "ruff-format",
            "mypy",
            "draft-2020-12-schema",
            "packaging-parity",
            "deterministic-release",
            "extracted-release-integrity",
            "official-spdx-validation",
            "unit",
            "local-e2e",
            "branch-coverage-80-percent",
        ],
        "ci": bool(os.environ.get("CI")),
        "result": "passed",
        "tests": test_report,
        "coverage": {
            "branch_coverage": True,
            "percent": coverage_report["totals"]["percent_covered"],
            "threshold": 80,
        },
        "release": {
            "file_count": len(release_manifest["files"]) + 1,
            "sha256": release_sha256,
            "source": release_manifest["source"],
            "version": release_manifest["version"],
        },
        "source_commit": git_head.stdout.strip() if git_head.returncode == 0 else None,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output.expanduser().resolve()
        output.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=output.parent, delete=False
        ) as handle:
            handle.write(rendered)
            temporary_output = Path(handle.name)
        try:
            os.replace(temporary_output, output)
        finally:
            temporary_output.unlink(missing_ok=True)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
