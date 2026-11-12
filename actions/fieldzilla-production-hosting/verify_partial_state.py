#!/usr/bin/env python3
"""Bind the six-role residual rehearsal state to a destroy-only recovery plan."""

import json
import sys


LINEAGE = "d5ba55e1-56eb-a8ce-a60d-ef29aeafe0f2"
SERIAL = 13
SOURCE = "ebb5ef7c3f0b9f174ac1598143fbc72d2bf8cd7a"
EXPIRY = "2026-11-11T13:20:00Z"
PARTIAL_COUNTS = {
    "aws_iam_role.application": 1,
    "aws_iam_role.execution": 3,
    "aws_iam_role.flow_logs": 1,
    "aws_iam_role.host": 1,
}
DATA_SOURCES = {
    "aws_iam_policy_document.flow_logs_assume",
    "aws_iam_policy_document.host_assume",
    "aws_iam_policy_document.task_assume",
}
EXECUTION_ROLES = {"admin", "api", "migration"}
TAINTED = {
    "aws_iam_role.application": {None},
    "aws_iam_role.execution": EXECUTION_ROLES,
    "aws_iam_role.flow_logs": {None},
    "aws_iam_role.host": {None},
}
EXPECTED_TAGS = {
    "Application": "fieldzilla",
    "Environment": "production-rehearsal",
    "ManagedBy": "opentofu",
    "Repository": "Synergie-ITCI/programme-management-platform",
    "Source": SOURCE,
    "ExpiresAt": EXPIRY,
}


def verify(state, source, expiry):
    if source != SOURCE or expiry != EXPIRY:
        raise ValueError("Partial cleanup is bound to the failed rehearsal source and expiry")
    if state.get("lineage") != LINEAGE or state.get("serial") != SERIAL or state.get("outputs") != {}:
        raise ValueError("Partial rehearsal state identity or output shape changed")
    resources = state.get("resources")
    if not isinstance(resources, list):
        raise ValueError("Partial rehearsal state resource list is absent")
    counts = {}
    data_sources = set()
    for resource in resources:
        address = f"{resource.get('type')}.{resource.get('name')}"
        instances = resource.get("instances")
        if resource.get("mode") == "data":
            if address not in DATA_SOURCES or address in data_sources or not isinstance(instances, list) or len(instances) != 1:
                raise ValueError("Partial state data-source inventory changed")
            data_sources.add(address)
            continue
        if resource.get("mode") != "managed":
            raise ValueError("Partial state contains an unexpected resource mode")
        if address in counts or address not in PARTIAL_COUNTS or not isinstance(instances, list):
            raise ValueError("Partial state has an unexpected resource address")
        counts[address] = len(instances)
        keys = {item.get("index_key") for item in instances}
        if address == "aws_iam_role.execution" and keys != EXECUTION_ROLES:
            raise ValueError("Partial state execution-role inventory changed")
        for instance in instances:
            if instance.get("deposed") or instance.get("status") not in (None, "tainted"):
                raise ValueError("Partial state includes an unreviewed instance")
            expected_tainted = instance.get("index_key") in TAINTED.get(address, set())
            if (instance.get("status") == "tainted") != expected_tainted:
                raise ValueError("Partial state instance status changed")
            tags = (instance.get("attributes") or {}).get("tags_all") or {}
            if any(tags.get(key) != value for key, value in EXPECTED_TAGS.items()):
                raise ValueError("Partial state resource source or expiry tags changed")
    if counts != PARTIAL_COUNTS:
        raise ValueError("Partial rehearsal state inventory changed")
    if data_sources != DATA_SOURCES:
        raise ValueError("Partial rehearsal data-source inventory changed")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Expected exact partial-state source and original expiry")
    verify(json.load(sys.stdin), sys.argv[1], sys.argv[2])
    print("Exact failed rehearsal state verified for destroy-only recovery")
