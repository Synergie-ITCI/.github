"""Render a review-only, target-scoped ECS execution policy; never applies IAM.

Resource support follows AWS's ECS authorization reference (list_ecs.html).
In particular, ListTasks is bound to the approved container-instance resource
and the request supplies that instance; it is not a region-wide wildcard grant.
Live IAM simulation and exact-plan approval remain required before activation.
"""

from __future__ import annotations

import re

from application_plan import ACCOUNT, REGION, REGISTRY, render


def deployment_policy(manifest: dict) -> dict:
    scope = manifest["scope"]
    plan = render(manifest["application"], scope=scope)
    cluster = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/fieldzilla-{scope}"
    prefix = f"arn:aws:ecs:{REGION}:{ACCOUNT}:"
    instance = manifest.get("container_instance_arn", "")
    if not re.fullmatch(
        re.escape(prefix) + rf"container-instance/fieldzilla-{scope}/[0-9a-f]{{32}}",
        instance,
    ):
        raise ValueError("Policy requires the exact approved target container instance")
    definitions = [
        prefix + "task-definition/" + row["family"] + ":*"
        for row in plan["task_definitions"]
    ]
    application_services = [
        prefix + f"service/fieldzilla-{scope}/" + row["serviceName"]
        for row in plan["service_preparation"]
    ]
    # The worker runs the API image. Only an explicit worker rollout needs to register and
    # run a new worker definition; otherwise the worker is just stopped and restored.
    worker_rollout = scope == "production" and "worker_target_digest" in manifest
    worker_family = prefix + "task-definition/fieldzilla-production-worker:*"
    registrable = definitions + ([worker_family] if worker_rollout else [])
    services = list(application_services)
    if scope == "production":
        services.append(prefix + "service/fieldzilla-production/fieldzilla-production-worker")
    condition = {"ArnEquals": {"ecs:cluster": cluster}}
    statements = []

    def allow(sid, actions, resources, conditions=None):
        statement = {
            "Sid": sid,
            "Effect": "Allow",
            "Action": actions,
            "Resource": resources,
        }
        if conditions:
            statement["Condition"] = conditions
        statements.append(statement)

    allow("ReadExactCluster", ["ecs:DescribeClusters"], [cluster])
    allow("ReadExactServices", ["ecs:DescribeServices"], services, condition)
    allow(
        "ReadApprovedHost",
        ["ecs:DescribeContainerInstances", "ecs:ListTasks"],
        [instance],
        condition,
    )
    allow(
        "ReadTargetTasks",
        ["ecs:DescribeTasks"],
        [prefix + f"task/fieldzilla-{scope}/*"],
        condition,
    )
    allow(
        "RegisterOnlyTargetFamilies",
        ["ecs:RegisterTaskDefinition"],
        registrable,
        {
            "StringEquals": {
                "aws:RequestTag/environment": scope,
                "aws:RequestTag/source-sha": plan["source_sha"],
            },
            "StringEqualsIfExists": {"ecs:privileged": "false"},
        },
    )
    allow(
        "TagOnlyDuringRegistration",
        ["ecs:TagResource"],
        registrable,
        {"StringEquals": {"ecs:CreateAction": "RegisterTaskDefinition"}},
    )
    allow(
        "CreateOnlyTargetServices",
        ["ecs:CreateService"],
        application_services,
        {
            "ArnEquals": {"ecs:cluster": cluster},
            "ArnLike": {"ecs:task-definition": definitions[:2]},
        },
    )
    allow(
        "UpdateOnlyTargetServices",
        ["ecs:UpdateService"],
        services,
        {
            "ArnEquals": {"ecs:cluster": cluster},
            # Scaling to zero during reviewed recovery need not change the task.
            "ArnLikeIfExists": {
                "ecs:task-definition": definitions[:2]
                + ([worker_family] if worker_rollout else [])
            },
        },
    )
    if worker_rollout:
        # DescribeTaskDefinition has no resource-level permission; read-only.
        allow("ReadPriorWorkerDefinition", ["ecs:DescribeTaskDefinition"], ["*"])
    run_families = [definitions[2]]
    if scope == "production":
        run_families.append(definitions[0])  # read-only queue attestor, exact API image
    allow("RunOnlyAttestationAndMigrationFamilies", ["ecs:RunTask"], run_families, condition)
    roles = {row["executionRoleArn"] for row in plan["task_definitions"]}
    roles.add(plan["task_definitions"][0]["taskRoleArn"])
    allow(
        "PassOnlyReviewedTaskRoles",
        ["iam:PassRole"],
        sorted(roles),
        {"StringEquals": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}},
    )
    allow(
        "ReadOnlyCandidateRepositories",
        ["ecr:DescribeImages"],
        [
            f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/"
            + REGISTRY.split(".com/", 1)[1]
            + "/"
            + kind
            for kind in ("api", "admin-web")
        ],
    )
    allow(
        "ReadOnlyTargetHealth",
        ["elasticloadbalancing:DescribeTargetHealth"],
        [
            row["loadBalancers"][0]["targetGroupArn"]
            for row in plan["service_preparation"]
        ],
    )
    log_kinds = ["migration", "api"] if scope == "production" else ["migration"]
    allow(
        "ReadOnlyCandidateAttestations",
        ["logs:GetLogEvents"],
        [
            f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/synergie/fieldzilla/{scope}/{kind}:"
            f"log-stream:{plan['source_sha']}/{kind}/*"
            for kind in log_kinds
        ],
    )
    if scope == "production":
        snapshot = manifest.get("snapshot_id", "")
        if not re.fullmatch(r"fieldzilla-production-[a-z0-9-]+", snapshot):
            raise ValueError("Policy requires the exact production snapshot identity")
        allow(
            "ReadOnlyReviewedSnapshot",
            ["rds:DescribeDBSnapshots"],
            [f"arn:aws:rds:{REGION}:{ACCOUNT}:snapshot:{snapshot}"],
        )
    return {"Version": "2012-10-17", "Statement": statements}
