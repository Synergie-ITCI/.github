"""Image-only publication engine; no ECS, database, listener or IAM mutations.

Builds must run without AWS credentials in a separate job. This trusted fresh-job
engine accepts only same-run verified image artifacts, revalidates authorization,
and acknowledges images only after named ECR manifest/config readback. No Docker
container is started here. A partial or ambiguous push is never retried.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path

from application_plan import ACCOUNT, REGION, REGISTRY

KINDS = ("api", "admin-web")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
SOURCE = "https://github.com/Synergie-ITCI/programme-management-platform"
ROLE = "SynergieFieldzillaProductionImagePublisher"
RECIPES = {"api": "apps/api/Dockerfile", "admin-web": "apps/admin-web/Dockerfile"}
MEDIA = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}


def validate_request(manifest):
    fields = {
        "operation",
        "scope",
        "application",
        "caller_sha",
        "base_sha",
        "central_tag",
        "central_sha",
        "promotion_pr",
        "expires_at",
        "review_authorizations",
        "qa_evidence",
        "recipes",
        "existing_images",
    }
    if not isinstance(manifest, dict) or set(manifest) != fields:
        raise ValueError("Image request must contain only supported metadata")
    if manifest["scope"] != "production-images" or manifest["operation"] != "prepare":
        raise ValueError("Only separately approved image publication is supported")
    app = manifest["application"]
    if (
        not isinstance(app, dict)
        or set(app) != {"source_sha"}
        or not re.fullmatch(r"[0-9a-f]{40}", str(app["source_sha"]))
    ):
        raise ValueError("Image source must be one exact reviewed application commit")
    for key in ("recipes", "existing_images"):
        if not isinstance(manifest[key], dict) or set(manifest[key]) != set(KINDS):
            raise ValueError("Only the two named application images are supported")
    for kind in KINDS:
        recipe = manifest["recipes"][kind]
        if (
            not isinstance(recipe, dict)
            or set(recipe) != {"path", "sha256"}
            or recipe["path"] != RECIPES[kind]
            or not re.fullmatch(r"[0-9a-f]{64}", str(recipe["sha256"]))
        ):
            raise ValueError(
                "Docker recipes must bind the exact supported source files"
            )
        expected = manifest["existing_images"][kind]
        if expected is not None and not DIGEST.fullmatch(str(expected)):
            raise ValueError("Recovery must name the exact existing immutable digest")
    return app["source_sha"]


def verify_local_image(reply, config_digest, source):
    if not isinstance(reply, list) or len(reply) != 1:
        raise ValueError("Local image identity is absent or ambiguous")
    image = reply[0]
    labels = image.get("Config", {}).get("Labels", {}) or {}
    if (
        image.get("Id") != config_digest
        or not DIGEST.fullmatch(str(config_digest))
        or image.get("Os") != "linux"
        or image.get("Architecture") != "arm64"
        or labels.get("org.opencontainers.image.revision") != source
        or labels.get("org.opencontainers.image.source") != SOURCE
    ):
        raise ValueError("Local image source, platform or config digest differs")


def publisher_trust():
    """Review-only trust for the existing protected production environment.

    AWS validates audience, immutable repository IDs, main and environment.
    The reusable workflow separately verifies immutable
    workflow identity, main ref and exact caller SHA before assuming this role.
    No new OIDC provider, shared trust, or human credential is introduced.
    """
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {
                    "Federated": f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
                },
                "Action": "sts:AssumeRoleWithWebIdentity",
                "Condition": {
                    "StringEquals": {
                        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                        "token.actions.githubusercontent.com:repository_id": "1315697868",
                        "token.actions.githubusercontent.com:repository_owner_id": "209829096",
                        "token.actions.githubusercontent.com:ref": "refs/heads/main",
                        "token.actions.githubusercontent.com:environment": "synergie-app-production",
                        "token.actions.githubusercontent.com:sub": "repo:Synergie-ITCI@209829096/programme-management-platform@1315697868:environment:synergie-app-production",
                    }
                },
            }
        ],
    }


def publisher_policy():
    """Review-only policy; never creates/attaches a role or obtains a token.

    ECR action resource support follows AWS's service-authorization reference.
    GetAuthorizationToken has no resource type; all repository actions are named.
    """
    repositories = [
        f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/synergie/fieldzilla/production/{kind}"
        for kind in KINDS
    ]
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RegionalRegistryAuthentication",
                "Effect": "Allow",
                "Action": ["ecr:GetAuthorizationToken"],
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:RequestedRegion": REGION}},
            },
            {
                "Sid": "OnlyNamedProductionImages",
                "Effect": "Allow",
                "Action": [
                    "ecr:DescribeRepositories",
                    "ecr:BatchGetImage",
                    "ecr:BatchCheckLayerAvailability",
                    "ecr:InitiateLayerUpload",
                    "ecr:UploadLayerPart",
                    "ecr:CompleteLayerUpload",
                    "ecr:PutImage",
                ],
                "Resource": repositories,
                "Condition": {"StringEquals": {"aws:RequestedRegion": REGION}},
            },
        ],
    }


class Publisher:
    def __init__(self, manifest, configs, *, aws, docker, authorize, journal: Path):
        self.source = validate_request(manifest)
        if (
            not isinstance(configs, dict)
            or set(configs) != set(KINDS)
            or any(not DIGEST.fullmatch(str(value)) for value in configs.values())
        ):
            raise ValueError("Both exact built image config digests are required")
        self.manifest = manifest
        self.configs = configs
        self.aws = aws
        self.docker = docker
        self.authorize = authorize
        self.ready = False
        self.acknowledged = {}
        self.stream = journal.open("x", encoding="utf-8")
        os.chmod(journal, 0o600)
        self.record("started", source=self.source)

    def record(self, event, **metadata):
        self.stream.write(
            json.dumps({"event": event, **metadata}, sort_keys=True) + "\n"
        )
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def close(self):
        self.stream.close()

    def repository(self, kind):
        return "synergie/fieldzilla/production/" + kind

    def read_image(self, kind):
        # A typed BatchGetImage ImageNotFound is absence; missing/inaccessible,
        # malformed and all other failure types remain blockers.
        reply = self.aws(
            "ecr",
            "batch-get-image",
            {
                "registryId": ACCOUNT,
                "repositoryName": self.repository(kind),
                "imageIds": [{"imageTag": self.source}],
                "acceptedMediaTypes": sorted(MEDIA),
            },
        )
        images, failures = reply.get("images"), reply.get("failures", [])
        if (
            images == []
            and len(failures) == 1
            and failures[0].get("failureCode") == "ImageNotFound"
            and failures[0].get("imageId") == {"imageTag": self.source}
        ):
            return None
        if not isinstance(images, list) or len(images) != 1 or failures:
            raise ValueError(
                "Registry image readback is absent, inaccessible or ambiguous"
            )
        image = images[0]
        identity = image.get("imageId", {})
        raw = image.get("imageManifest", "")
        if not isinstance(raw, str) or len(raw) > 1024 * 1024:
            raise ValueError("Registry manifest is unavailable or oversized")
        digest = "sha256:" + hashlib.sha256(raw.encode()).hexdigest()
        body = json.loads(raw)
        if not isinstance(body, dict):
            raise TypeError("Registry image manifest must be an object")
        if (
            image.get("registryId") != ACCOUNT
            or image.get("repositoryName") != self.repository(kind)
            or identity.get("imageTag") != self.source
            or identity.get("imageDigest") != digest
            or body.get("schemaVersion") != 2
            or body.get("mediaType") not in MEDIA
            or body.get("config", {}).get("digest") != self.configs[kind]
            or not isinstance(body.get("layers"), list)
            or any(
                not isinstance(layer, dict)
                or not DIGEST.fullmatch(str(layer.get("digest")))
                or "urls" in layer
                for layer in body["layers"]
            )
        ):
            raise ValueError("Registry source tag, manifest or image config differs")
        return digest

    def preflight(self):
        self.ready = False
        self.authorize()
        identity = self.aws("sts", "get-caller-identity", {})
        if identity.get("Account") != ACCOUNT or not re.fullmatch(
            rf"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE}/[A-Za-z0-9+=,.@_-]+",
            identity.get("Arn", ""),
        ):
            raise ValueError(
                "Only the approved named image-publisher identity may proceed"
            )
        for kind in KINDS:
            verify_local_image(
                self.docker("inspect", self.configs[kind]),
                self.configs[kind],
                self.source,
            )
            repo = self.aws(
                "ecr",
                "describe-repositories",
                {"registryId": ACCOUNT, "repositoryNames": [self.repository(kind)]},
            )
            rows = repo.get("repositories", [])
            if (
                len(rows) != 1
                or rows[0].get("repositoryUri") != REGISTRY + "/" + kind
                or rows[0].get("registryId") != ACCOUNT
                or rows[0].get("repositoryName") != self.repository(kind)
                or rows[0].get("imageTagMutability") != "IMMUTABLE"
            ):
                raise ValueError("Named immutable registry repository differs")
            if self.read_image(kind) != self.manifest["existing_images"][kind]:
                raise ValueError(
                    "Registry state differs from the exact approved recovery/request"
                )
        self.ready = True
        self.record("preflight_passed")

    def publish(self, consume):
        if not self.ready:
            raise ValueError("Publication requires a successful same-engine preflight")
        self.ready = False
        self.authorize()
        consume()
        missing = [
            kind for kind in KINDS if self.manifest["existing_images"][kind] is None
        ]
        if missing:
            # Adapter must obtain ECR password through private stdin, never
            # arguments/logs, using an ephemeral Docker config; never run images.
            self.authorize()
            self.docker("login", REGISTRY.split("/", 1)[0])
        for kind in KINDS:
            self.authorize()
            current = self.read_image(kind)
            if current != self.manifest["existing_images"][kind]:
                raise ValueError("Registry state changed after preflight; no overwrite")
            if current is None:
                target = REGISTRY + "/" + kind + ":" + self.source
                self.docker("tag", self.configs[kind], target)
                self.record("push_started", image=kind)
                self.authorize()
                self.docker("push", target)
                current = self.read_image(kind)
                if current is None:
                    raise ValueError("Push is not acknowledged by the registry")
            self.acknowledged[kind] = current
            self.record(
                "image_acknowledged",
                image=kind,
                digest=current,
                config=self.configs[kind],
            )
        return {
            "status": "REGISTRY_IMAGES_ACKNOWLEDGED_NOT_DEPLOYED",
            "source_sha": self.source,
            "digests": dict(self.acknowledged),
        }
