#!/usr/bin/env python3
"""Bind the November 12 interrupted rehearsal to one destroy-only recovery."""

import json
import hashlib
import sys


VERSION = "nBarifpRPSS8L8B1sm5wVXIihLhhLneD"
LINEAGE = "d5ba55e1-56eb-a8ce-a60d-ef29aeafe0f2"
SERIAL = 29
ID_SHA256 = "c0a0f2bf1b363aa9e3e0f002f11066152dd1ef7ce435bcd1a7c37f269cfe8a53"
SOURCE = "ebb5ef7c3f0b9f174ac1598143fbc72d2bf8cd7a"
EXPIRY = "2026-11-12T16:30:00Z"
COUNTS = {
    "aws_cloudwatch_log_group.container_insights": 1,
    "aws_cloudwatch_log_group.flow_logs": 1,
    "aws_cloudwatch_log_group.runtime": 3,
    "aws_db_subnet_group.rehearsal": 1,
    "aws_iam_instance_profile.host": 1,
    "aws_iam_role.application": 1,
    "aws_iam_role.execution": 3,
    "aws_iam_role.flow_logs": 1,
    "aws_iam_role.host": 1,
    "aws_iam_role_policy.application_attachments": 1,
    "aws_iam_role_policy_attachment.execution": 3,
    "aws_iam_role_policy_attachment.host_ecs": 1,
    "aws_iam_role_policy_attachment.host_ssm": 1,
    "aws_kms_alias.rehearsal": 1,
    "aws_kms_key.rehearsal": 1,
    "aws_lb.rehearsal": 1,
    "aws_lb_listener.rehearsal": 1,
    "aws_lb_listener_rule.api": 1,
    "aws_lb_target_group.admin": 1,
    "aws_lb_target_group.api": 1,
    "aws_s3_bucket.attachments": 1,
    "aws_s3_bucket_logging.attachments": 1,
    "aws_s3_bucket_ownership_controls.attachments": 1,
    "aws_s3_bucket_policy.attachments": 1,
    "aws_s3_bucket_public_access_block.attachments": 1,
    "aws_s3_bucket_server_side_encryption_configuration.attachments": 1,
    "aws_s3_bucket_versioning.attachments": 1,
    "aws_security_group.alb": 1,
    "aws_security_group.database": 1,
    "aws_security_group.endpoints": 1,
    "aws_security_group.host": 1,
    "aws_subnet.rehearsal_a": 1,
    "aws_subnet.rehearsal_b": 1,
    "aws_vpc.rehearsal": 1,
    "aws_vpc_endpoint.services": 13,
    "aws_vpc_security_group_egress_rule.alb_admin": 1,
    "aws_vpc_security_group_egress_rule.alb_api": 1,
    "aws_vpc_security_group_egress_rule.database": 1,
    "aws_vpc_security_group_egress_rule.host_endpoints": 1,
    "aws_vpc_security_group_egress_rule.host_private_alb": 1,
    "aws_vpc_security_group_ingress_rule.alb_from_host": 1,
    "aws_vpc_security_group_ingress_rule.database": 1,
}
DATA_SOURCES = {
    "aws_caller_identity.current",
    "aws_iam_policy_document.application_attachments",
    "aws_iam_policy_document.attachments",
    "aws_iam_policy_document.flow_logs_assume",
    "aws_iam_policy_document.host_assume",
    "aws_iam_policy_document.rehearsal_kms",
    "aws_iam_policy_document.task_assume",
    "aws_ssm_parameter.ecs_ami",
}
TAGS = {
    "Application": "fieldzilla",
    "Environment": "production-rehearsal",
    "ManagedBy": "opentofu",
    "Repository": "Synergie-ITCI/programme-management-platform",
    "Source": SOURCE,
    "ExpiresAt": EXPIRY,
}


def verify(state, source, expiry):
    if (source, expiry) != (SOURCE, EXPIRY):
        raise ValueError("Interrupted cleanup source or expiry changed")
    if (state.get("lineage"), state.get("serial"), state.get("outputs")) != (LINEAGE, SERIAL, {}):
        raise ValueError("Interrupted rehearsal state identity changed")
    counts, data, identities = {}, set(), []
    for resource in state.get("resources", []):
        address = f"{resource.get('type')}.{resource.get('name')}"
        instances = resource.get("instances")
        if not isinstance(instances, list):
            raise ValueError("Interrupted state instance shape changed")
        if resource.get("mode") == "data":
            if address not in DATA_SOURCES or address in data or len(instances) != 1:
                raise ValueError("Interrupted state data-source inventory changed")
            data.add(address)
            continue
        if resource.get("mode") != "managed" or address in counts or address not in COUNTS:
            raise ValueError("Interrupted state contains an unreviewed managed address")
        counts[address] = len(instances)
        for instance in instances:
            if instance.get("deposed") or instance.get("status") is not None:
                raise ValueError("Interrupted state has a deposed or tainted resource")
            tags = (instance.get("attributes") or {}).get("tags_all")
            identities.append((address, instance.get("index_key"), (instance.get("attributes") or {}).get("id")))
            if tags is not None and any(tags.get(key) != value for key, value in TAGS.items()):
                raise ValueError("Interrupted state contains a differently owned resource")
    if counts != COUNTS or data != DATA_SOURCES or sum(counts.values()) != 60:
        raise ValueError("Interrupted state inventory changed")
    if identity_digest(identities) != ID_SHA256:
        raise ValueError("Interrupted state resource identities changed")


def identity_digest(identities):
    ordered = sorted(identities, key=lambda item: (item[0], str(item[1])))
    return hashlib.sha256(json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("Expected exact interrupted source and original expiry")
    verify(json.load(sys.stdin), sys.argv[1], sys.argv[2])
    print("Exact serial-29 interrupted rehearsal state verified for destroy-only recovery")
