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
    if len(sys.argv) not in {2, 3}:
        print("usage: governance_v2_qa_packet.py <current.json> [previous.json]", file=sys.stderr)
        return 2
    current = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    if len(sys.argv) == 3:
        previous = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
        packet = GOV.build_delta_qa_packet(previous, current)
    else:
        packet = GOV.build_qa_packet(current)
    print(json.dumps(packet, indent=2, sort_keys=True))
    return 0 if packet["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
