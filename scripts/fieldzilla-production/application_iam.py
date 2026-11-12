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
    services = [
        prefix + f"service/fieldzilla-{scope}/" + row["serviceName"]
        for row in plan["service_preparation"]
    ]
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
        definitions,
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
        definitions,
        {"StringEquals": {"ecs:CreateAction": "RegisterTaskDefinition"}},
    )
    allow(
        "CreateOnlyTargetServices",
        ["ecs:CreateService"],
        services,
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
            "ArnLikeIfExists": {"ecs:task-definition": definitions[:2]},
        },
    )
    allow("RunOnlyMigrationFamily", ["ecs:RunTask"], [definitions[2]], condition)
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
    allow(
        "ReadOnlyCandidateMigrationAttestations",
        ["logs:GetLogEvents"],
        [
            (
                f"arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/synergie/fieldzilla/{scope}/migration:"
                f"log-stream:{plan['source_sha']}/migration/*"
            )
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
