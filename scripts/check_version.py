#!/usr/bin/env python3
"""Fail when duplicated Teamwork contract/release versions drift."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    source = (ROOT / "src" / "teamwork_payload.py").read_text(encoding="utf-8")
    schema = json.loads(
        (ROOT / "schemas" / "teamwork-manifest.schema.json").read_text(encoding="utf-8")
    )
    observed = {
        "SCHEMA_VERSION": re.search(
            r'^SCHEMA_VERSION = "([^"]+)"$', source, re.MULTILINE
        ),
        "SKILL_VERSION": re.search(
            r'^SKILL_VERSION = "([^"]+)"$', source, re.MULTILINE
        ),
    }
    failures: list[str] = []
    skill_version = observed["SKILL_VERSION"]
    schema_version = observed["SCHEMA_VERSION"]
    if not skill_version or skill_version.group(1) != version:
        failures.append("SKILL_VERSION")
    if not schema_version:
        failures.append("SCHEMA_VERSION")
        contract_version = None
    else:
        contract_version = schema_version.group(1)
    if schema.get("$id") != f"urn:teamwork:manifest:{contract_version}":
        failures.append("schema.$id")
    if (
        schema.get("properties", {}).get("schema_version", {}).get("const")
        != contract_version
    ):
        failures.append("schema.schema_version")
    skill_schema = (
        schema.get("properties", {})
        .get("producer", {})
        .get("properties", {})
        .get("skill_version", {})
    )
    if skill_schema.get("type") != "string" or "pattern" not in skill_schema:
        failures.append("schema.producer.skill_version")
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {version} " not in changelog:
        failures.append("CHANGELOG.md")
    if failures:
        print("Version drift: " + ", ".join(failures), file=sys.stderr)
        return 2
    print(f"Version surfaces synchronized: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
