#!/usr/bin/env python3
"""Validate the canonical Teamwork manifest schema with a Draft 2020-12 implementation."""

from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    schema_path = ROOT / "schemas" / "teamwork-manifest.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    print(f"Draft 2020-12 schema valid: {schema_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
