#!/usr/bin/env python3
"""Synchronize canonical resources into both self-contained skill folders."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Sequence


DEFAULT_ROOT = Path(__file__).resolve().parents[1]
SKILLS = ("teamwork-handoff", "teamwork-resume")


def synchronize(root: Path, check: bool) -> int:
    sources = {
        root / "src" / "teamwork_payload.py": Path("scripts/teamwork_payload.py"),
        root / "docs" / "PAYLOAD_CONTRACT.md": Path("references/payload-contract.md"),
        root / "schemas" / "teamwork-manifest.schema.json": Path(
            "references/teamwork-manifest.schema.json"
        ),
    }
    drift: list[str] = []
    for skill in SKILLS:
        skill_root = root / "skills" / skill
        for source, relative_target in sources.items():
            target = skill_root / relative_target
            if not source.is_file():
                print(f"Missing canonical resource: {source}")
                return 2
            if check:
                if not target.is_file() or target.read_bytes() != source.read_bytes():
                    drift.append(str(target.relative_to(root)))
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        if not check:
            print(f"Synchronized {skill}")
    if drift:
        print("Embedded skill resources are out of sync:")
        for path in drift:
            print(f"- {path}")
        print("Run: python scripts/sync_skills.py")
        return 2
    if check:
        print("Embedded skill resources are synchronized")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check", action="store_true", help="Fail on drift without changing files"
    )
    parser.add_argument(
        "--root", type=Path, default=DEFAULT_ROOT, help=argparse.SUPPRESS
    )
    args = parser.parse_args(argv)
    return synchronize(args.root.expanduser().resolve(), args.check)


if __name__ == "__main__":
    raise SystemExit(main())
