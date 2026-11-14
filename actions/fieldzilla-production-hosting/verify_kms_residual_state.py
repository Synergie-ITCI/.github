#!/usr/bin/env python3
"""Bind the post-interruption KMS remainder to one destroy-only recovery."""

import json
import sys

from verify_interrupted_state import EXPIRY, LINEAGE, SOURCE, TAGS, identity_digest


VERSION = "_5D8ll2jFTMW0Nflg9u3UACnTsLaHoCx"
SERIAL = 35
KEY_ID = "82e3b568-d5a0-4ea9-ac09-308d188065ee"
ALIAS = "alias/synergie/fieldzilla/production-rehearsal"
ID_SHA256 = "a80d70505723804a4f40c02e9756fc2392e1c6e4cc781c6f6f805e3c4913497f"
COUNTS = {"aws_kms_alias.rehearsal": 1, "aws_kms_key.rehearsal": 1}
DATA_SOURCES = {"aws_caller_identity.current", "aws_iam_policy_document.rehearsal_kms"}


def verify(state, source, expiry):
    if (source, expiry) != (SOURCE, EXPIRY):
        raise ValueError("KMS residual source or original expiry changed")
    if (state.get("lineage"), state.get("serial"), state.get("outputs")) != (LINEAGE, SERIAL, {}):
        raise ValueError("KMS residual state identity changed")
    counts, data, identities = {}, set(), []
    for resource in state.get("resources", []):
        address = f"{resource.get('type')}.{resource.get('name')}"
        instances = resource.get("instances")
        if not isinstance(instances, list) or len(instances) != 1:
            raise ValueError("KMS residual instance shape changed")
        if resource.get("mode") == "data":
            if address not in DATA_SOURCES or address in data:
                raise ValueError("KMS residual data-source inventory changed")
            data.add(address)
            continue
        if resource.get("mode") != "managed" or address not in COUNTS or address in counts:
            raise ValueError("KMS residual managed address changed")
        counts[address] = len(instances)
        instance = instances[0]
        if instance.get("deposed") or instance.get("status") is not None:
            raise ValueError("KMS residual contains a deposed or tainted resource")
        attributes = instance.get("attributes") or {}
        identities.append((address, instance.get("index_key"), attributes.get("id")))
        if address == "aws_kms_alias.rehearsal":
            if (attributes.get("id"), attributes.get("name"), attributes.get("target_key_id")) != (
                ALIAS, ALIAS, KEY_ID
            ):
                raise ValueError("KMS residual alias identity changed")
        elif (
            attributes.get("id") != KEY_ID
            or attributes.get("tags_all") != TAGS
            or attributes.get("deletion_window_in_days") != 7
            or attributes.get("is_enabled") is not True
        ):
            raise ValueError("KMS residual key identity or lifecycle changed")
    if counts != COUNTS or data != DATA_SOURCES or identity_digest(identities) != ID_SHA256:
        raise ValueError("KMS residual inventory or resource identities changed")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Expected exact residual source and original expiry")
    verify(json.load(sys.stdin), sys.argv[1], sys.argv[2])
    print("Exact serial-35 KMS residual verified for destroy-only recovery")
