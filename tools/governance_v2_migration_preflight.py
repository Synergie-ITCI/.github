#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "governance-v2" / "governance_v2.py"
SPEC = importlib.util.spec_from_file_location("governance_v2", MODULE_PATH)
assert SPEC and SPEC.loader
GOV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GOV)


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: governance_v2_migration_preflight.py <input.json>", file=sys.stderr)
        return 2
    data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    report = GOV.build_migration_preflight_report(data)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["status"] == "READY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
