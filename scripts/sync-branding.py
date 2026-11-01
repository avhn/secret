#!/usr/bin/env python3
"""Copy reviewed branding bytes into MCPB packaging. Run with python3 -I."""

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
COPIES = (("resources/logo.svg", "packaging/mcpb/icon.svg"),
          ("resources/logo-256.png", "packaging/mcpb/icon.png"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check copies without writing")
    parser.add_argument("--root", type=Path, default=ROOT, help="checkout root (default: script's checkout)")
    args = parser.parse_args()
    failed = False
    for source_name, target_name in COPIES:
        source, target = args.root / source_name, args.root / target_name
        if not source.is_file():
            print(f"FAIL branding: missing source {source_name}", file=sys.stderr)
            failed = True
            continue
        data = source.read_bytes()
        if args.check:
            if not target.is_file() or target.read_bytes() != data:
                print(f"FAIL branding: {target_name} differs from {source_name}; "
                      "run python3 -I scripts/sync-branding.py", file=sys.stderr)
                failed = True
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            print(f"Synced {source_name} to {target_name}")
    if failed:
        return 1
    if args.check:
        print("PASS branding: MCPB icons match reviewed resources")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except OSError as error:
        print(f"FAIL branding: {error}", file=sys.stderr)
        sys.exit(1)
