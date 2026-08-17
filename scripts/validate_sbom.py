#!/usr/bin/env python3
"""Validate an SPDX 2.x document with the official SPDX Python tools."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from spdx_tools.spdx.parser.parse_anything import parse_file
from spdx_tools.spdx.validation.document_validator import validate_full_spdx_document


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("document", type=Path)
    args = parser.parse_args()
    document_path = args.document.expanduser().resolve()
    try:
        document = parse_file(str(document_path))
        messages = validate_full_spdx_document(document)
    except Exception as exc:  # SPDX parser exposes multiple format-specific errors.
        print(f"ERROR: SPDX parsing failed: {exc}", file=sys.stderr)
        return 2
    if messages:
        print("ERROR: SPDX validation failed", file=sys.stderr)
        for message in messages:
            print(str(message), file=sys.stderr)
        return 2
    print(json.dumps({"document": str(document_path), "ok": True}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
