"""Render production-only ECS requests for review; never executes AWS calls.

The output is not deployment authorization. Runtime/migration secrets and roles
must already be provisioned through the approved security path. Services start
at zero; no listener or shared load-balancer resource is modified here.
The migration-only store must carry its own database credential and the same
context-signing key value as runtime; reference validation cannot prove values.
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ACCOUNT = "918870682888"
REGION = "ap-south-1"
REGISTRY = f"{ACCOUNT}.dkr.ecr.{REGION}.amazonaws.com/synergie/fieldzilla/production"
SHA = re.compile(r"[0-9a-f]{40}")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PR787_SOURCE_SHA = "a6e35a7ad36fbc21417a8575bb723a7948a5e8c7"
PR791_SOURCE_SHA = "8821f317a4316ec7bca639ac7b6d22e9f903cfd9"
PR798_SOURCE_SHA = "ee2b975c9c5a4881d71c6cd46d17af4e2f33aeae"
PR802_SOURCE_SHA = "b55cf18a881c1722d307cac4c04114667e8379ea"
PR804_SOURCE_SHA = "0d82540f4e2ca19a5edceea34d78728fea57fa46"
PR806_SOURCE_SHA = "670b7482120cda2375fad491a270e0b00f833450"
PR808_SOURCE_SHA = "5d92dd585eda25391297bfd9d408c585f556a4d6"
PR811_SOURCE_SHA = "410badf52529ace7a7e05295f012c8ff6b50be3a"
PR814_SOURCE_SHA = "6b2b91e65452a705ae856678dfda1441f8377c6e"
PR816_SOURCE_SHA = "d0760117e67cdff1c9b7aa9de7920533da4a35eb"
PR819_SOURCE_SHA = "59e520f20481ed2cc192d1c9a0ba569d480a5e90"
PR835_SOURCE_SHA = "54069e56d92bfc4546d924c7963e23db4a24e439"
PR841_SOURCE_SHA = "42730e5659959ba708fcfea4d37c80edde71fc9f"
PR844_SOURCE_SHA = "a4389d10fc8fde01b2b940ce912d748457901e8e"
PR853_SOURCE_SHA = "bfd3315a3847e3723940ec8548852d4e9c4c43fa"
PR857_SOURCE_SHA = "e1c5f8ecdc4e5e791580cf0b5a81daf19f79a8f9"
ROLE = re.compile(
    rf"arn:aws:iam::{ACCOUNT}:role/[A-Za-z0-9_+=,.@/-]*[Pp]roduction[A-Za-z0-9_+=,.@/-]*"
)
SECRET = re.compile(
    rf"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:/synergie/fieldzilla/production/(runtime|migration)-[A-Za-z0-9]{{6}}"
)


def require(pattern: re.Pattern[str], value: object, label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"Invalid production {label}")
    return value


def render(manifest: dict, *, scope: str = "production") -> dict:
    if scope not in {"production", "production-rehearsal"}:
        raise ValueError("Only production and its isolated rehearsal are supported")
    secret_pattern = re.compile(
        rf"arn:aws:secretsmanager:{REGION}:{ACCOUNT}:secret:/synergie/fieldzilla/{scope}/(runtime|migration)-[A-Za-z0-9]{{6}}"
    )
    sha = require(SHA, manifest["source_sha"], "source SHA")
    roles = {
        key: require(ROLE, manifest[key], key)
        for key in (
            "api_execution_role",
            "migration_execution_role",
            "admin_execution_role",
            "api_task_role",
        )
    }
    if any("staging" in role.lower() for role in roles.values()):
        raise ValueError("Staging identities are forbidden")
    for role in roles.values():
        if (scope == "production-rehearsal") != ("productionrehearsal" in role.lower()):
            raise ValueError(
                "Execution identities must belong to the exact target scope"
            )
    if len(set(roles.values())) != len(roles):
        raise ValueError("Each application and execution identity must be separate")
    secrets = {
        key: require(secret_pattern, manifest[key], key)
        for key in ("runtime_secret", "migration_secret")
    }
    for name in ("runtime", "migration"):
        if f"/{name}-" not in secrets[f"{name}_secret"]:
            raise ValueError(
                "Runtime and migration secret references must not be exchanged"
            )
    if secrets["runtime_secret"] == secrets["migration_secret"]:
        raise ValueError("Runtime and migration credentials must differ")
    definitions = []
    services = []
    for kind in ("api", "admin-web", "migration"):
        image_kind = "api" if kind == "migration" else kind
        digest = require(DIGEST, manifest[f"{image_kind}_digest"], "registry digest")
        role_key = {
            "api": "api_execution_role",
            "admin-web": "admin_execution_role",
            "migration": "migration_execution_role",
        }[kind]
        container = {
            "name": kind,
            "image": f"{REGISTRY}/{image_kind}@{digest}",
            "essential": True,
            "memory": 512 if kind != "admin-web" else 128,
            "logConfiguration": {
                "logDriver": "awslogs",
                "options": {
                    "awslogs-region": REGION,
                    "awslogs-group": f"/synergie/fieldzilla/{scope}/{kind}",
                    "awslogs-stream-prefix": sha,
                },
            },
        }
        if kind != "admin-web":
            secret = secrets[
                "migration_secret" if kind == "migration" else "runtime_secret"
            ]
            container["secrets"] = [
                {
                    "name": "APP_DATABASE_URL",
                    "valueFrom": secret + ":APP_DATABASE_URL::",
                },
                {
                    "name": "APP_DATABASE_CONTEXT_SECRET",
                    "valueFrom": secret + ":APP_DATABASE_CONTEXT_SECRET::",
                },
            ]
            container["environment"] = [
                {"name": "APP_ENVIRONMENT", "value": "production"}
            ]
            if kind == "api":
                key_names = ["APP_SECRET_KEY", "APP_FIELD_ENCRYPTION_MASTER_KEY"]
                if scope == "production":
                    key_names.append("APP_FIELD_ENCRYPTION_LEGACY_KEYS")
                for key in key_names:
                    container["secrets"].append(
                        {"name": key, "valueFrom": secret + ":" + key + "::"}
                    )
                # Configuration is reviewed separately, never supplied as arbitrary
                # environment/command overrides by a deployment operator.
                required_config = (
                    "APP_OBJECT_STORAGE_BUCKET",
                    "APP_OBJECT_STORAGE_KMS_KEY_ID",
                    "APP_FIELD_ENCRYPTION_KMS_KEY_ID",
                )
                for key in required_config:
                    container["secrets"].append(
                        {"name": key, "valueFrom": secret + ":" + key + "::"}
                    )
                if scope == "production":
                    # Exactly one trusted proxy: the shared internet-facing ALB (X-Forwarded-For
                    # in append mode, no WAF, no CDN, instance targets; verified live). Client IPs
                    # for abuse limits come from the last forwarded hop, not the load balancer.
                    container["environment"].append(
                        {"name": "APP_TRUSTED_PROXY_COUNT", "value": "1"}
                    )
                container["environment"] += [
                    {"name": "APP_OBJECT_STORAGE_BACKEND", "value": "s3_private"},
                    {"name": "APP_OBJECT_STORAGE_REGION", "value": REGION},
                    {
                        "name": "APP_ADMIN_WEB_BASE_URL",
                        "value": (
                            "https://fieldzilla.synergieinsights.in"
                            if scope == "production"
                            else "https://fieldzilla-rehearsal.invalid"
                        ),
                    },
                    {
                        "name": "APP_CORS_ORIGINS",
                        "value": (
                            "https://fieldzilla.synergieinsights.in"
                            if scope == "production"
                            else "https://fieldzilla-rehearsal.invalid"
                        ),
                    },
                ]
            else:
                if scope == "production" and sha in {PR802_SOURCE_SHA, PR804_SOURCE_SHA, PR806_SOURCE_SHA, PR808_SOURCE_SHA, PR811_SOURCE_SHA, PR814_SOURCE_SHA, PR816_SOURCE_SHA, PR819_SOURCE_SHA, PR841_SOURCE_SHA, PR844_SOURCE_SHA, PR853_SOURCE_SHA}:
                    container["command"] = ["alembic", "current"]
                elif scope == "production" and sha == PR857_SOURCE_SHA:
                    container["command"] = ["alembic", "upgrade", "20261123_0079"]
                elif scope == "production" and sha == PR835_SOURCE_SHA:
                    container["command"] = ["alembic", "upgrade", "20261121_0078"]
                elif scope == "production" and sha == PR798_SOURCE_SHA:
                    container["command"] = ["alembic", "upgrade", "20261117_0077"]
                elif scope == "production" and sha == PR791_SOURCE_SHA:
                    container["command"] = ["alembic", "upgrade", "20261117_0076"]
                elif scope == "production" and sha == PR787_SOURCE_SHA:
                    container["command"] = ["alembic", "upgrade", "20261116_0075"]
                elif scope == "production":
                    container["command"] = ["python", "scripts/production_historical_migrate.py"]
                else:
                    container["command"] = ["alembic", "upgrade", "fieldzilla_pr119@head"]
        definition = {
            "family": "fieldzilla-" + scope + "-" + kind,
            "networkMode": "bridge",
            "requiresCompatibilities": ["EC2"],
            "executionRoleArn": roles[role_key],
            "runtimePlatform": {
                "cpuArchitecture": "ARM64",
                "operatingSystemFamily": "LINUX",
            },
            "containerDefinitions": [container],
            "tags": [
                {"key": "source-sha", "value": sha},
                {"key": "environment", "value": scope},
            ],
        }
        if kind == "api":
            definition["taskRoleArn"] = roles["api_task_role"]
        if kind != "migration":
            port = 8000 if kind == "api" else 80
            container["portMappings"] = [
                {"containerPort": port, "hostPort": port, "protocol": "tcp"}
            ]
            target = manifest[f"{kind}_target_group"]
            require(
                re.compile(
                    rf"arn:aws:elasticloadbalancing:{REGION}:{ACCOUNT}:targetgroup/pmp-{scope}-{'api' if kind == 'api' else 'admin'}/[0-9a-f]+"
                ),
                target,
                "target group",
            )
            services.append(
                {
                    "cluster": "fieldzilla-" + scope,
                    "serviceName": definition["family"],
                    "desiredCount": 0,
                    "launchType": "EC2",
                    "deploymentConfiguration": {
                        "minimumHealthyPercent": 0,
                        "maximumPercent": 100,
                        # A prior image is not automatically safe after a schema
                        # migration or accepted writes. Recovery stays reviewed.
                        "deploymentCircuitBreaker": {"enable": True, "rollback": False},
                    },
                    "loadBalancers": [
                        {
                            "targetGroupArn": target,
                            "containerName": kind,
                            "containerPort": port,
                        }
                    ],
                }
            )
        definitions.append(definition)
    return {
        "source_sha": sha,
        "status": "REVIEW_ONLY_NOT_AUTHORIZED",
        "task_definitions": definitions,
        "service_preparation": services,
        "limitations": [
            "Supply the exact registered task revision to create-service; desired count stays zero until approved rehearsal/activation.",
            "Fixed existing host ports require stop-before-start on the single host; this is not zero-downtime rolling deployment.",
            "Migration secret, restricted SQL ownership, IAM policies and production config validation require separate review.",
            "No ALB listener action, IAM mutation, database mutation or workflow dispatch is included.",
            "First-deployment rollback is maintenance plus retained database/forward recovery, not restoration over accepted writes.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    print(json.dumps(render(json.loads(args.manifest.read_text())), indent=2))


if __name__ == "__main__":
    main()
