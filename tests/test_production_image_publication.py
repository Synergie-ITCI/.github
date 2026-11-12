"""Image publisher boundaries with fake ECR/Docker; not registry execution proof."""

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from image_publication import Publisher, publisher_policy, validate_request


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.source = "a" * 40
        self.config_blobs = {"api": "sha256:" + "b" * 64, "admin-web": "sha256:" + "c" * 64}
        self.configs = {
            kind: self.image(kind)["imageId"]["imageDigest"]
            for kind in self.config_blobs
        }
        self.request = {
            "operation": "prepare",
            "scope": "production-images",
            "application": {"source_sha": self.source},
            "caller_sha": "d" * 40,
            "base_sha": "d" * 40,
            "central_tag": "pr-qa-v1-rc235",
            "central_sha": "e" * 40,
            "promotion_pr": 712,
            "expires_at": "2026-11-10T20:00:00Z",
            "review_authorizations": {},
            "qa_evidence": {},
            "recipes": {
                kind: {"path": "apps/" + kind + "/Dockerfile", "sha256": "f" * 64}
                for kind in self.configs
            },
            "existing_images": {kind: None for kind in self.configs},
        }
        self.images = {kind: None for kind in self.configs}
        self.calls = []
        self.account = "918870682888"
        self.role = "arn:aws:sts::918870682888:assumed-role/SynergieFieldzillaProductionImagePublisher/test"
        self.failure = None
        self.mutable = False
        self.bad_platform = False
        self.bad_failure_code = False
        self.consumed = 0
        self.authorized = 0

    def image(self, kind):
        body = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {"digest": self.config_blobs[kind]},
            "layers": [{"digest": "sha256:" + "f" * 64}],
        }
        raw = json.dumps(body)
        return {
            "registryId": "918870682888",
            "repositoryName": "synergie/fieldzilla/production/" + kind,
            "imageId": {
                "imageTag": self.source,
                "imageDigest": "sha256:" + hashlib.sha256(raw.encode()).hexdigest(),
            },
            "imageManifest": raw,
        }

    def aws(self, service, action, request):
        self.calls.append((service, action))
        if service == "sts":
            return {"Account": self.account, "Arn": self.role}
        self.assertEqual(service, "ecr")
        if action == "describe-repositories":
            name = request["repositoryNames"][0]
            return {
                "repositories": [
                    {
                        "registryId": "918870682888",
                        "repositoryName": name,
                        "repositoryUri": "918870682888.dkr.ecr.ap-south-1.amazonaws.com/"
                        + name,
                        "imageTagMutability": "MUTABLE"
                        if self.mutable
                        else "IMMUTABLE",
                    }
                ]
            }
        self.assertEqual(action, "batch-get-image")
        kind = request["repositoryName"].rsplit("/", 1)[1]
        if self.images[kind] is not None:
            return {"images": [self.images[kind]], "failures": []}
        return {
            "images": [],
            "failures": [
                {
                    "imageId": {"imageTag": self.source},
                    "failureCode": "ImageInaccessible"
                    if self.bad_failure_code
                    else "ImageNotFound",
                }
            ],
        }

    def docker(self, operation, *args):
        self.calls.append(("docker", operation))
        if operation == "inspect":
            return [
                {
                    "Id": args[0],
                    "Os": "linux",
                    "Architecture": "amd64" if self.bad_platform else "arm64",
                    "Config": {
                        "Labels": {
                            "org.opencontainers.image.revision": self.source,
                            "org.opencontainers.image.source": "https://github.com/Synergie-ITCI/programme-management-platform",
                        }
                    },
                }
            ]
        if operation == "push":
            kind = args[0].rsplit("/", 1)[1].split(":", 1)[0]
            self.images[kind] = self.image(kind)
            if self.failure == "lost_ack":
                raise RuntimeError("synthetic acknowledgement loss")
        self.assertIn(operation, {"inspect", "login", "tag", "push"})

    def authorize(self):
        self.authorized += 1
        if self.failure == "expired_after_api" and self.images["api"] is not None:
            raise ValueError("synthetic approval expired")

    def consume(self):
        self.consumed += 1
        if self.failure == "consume":
            raise ValueError("synthetic consumed elsewhere")

    def engine(self, folder):
        return Publisher(
            self.request,
            self.configs,
            aws=self.aws,
            docker=self.docker,
            authorize=self.authorize,
            journal=Path(folder) / "journal",
        )

    def test_registry_acknowledges_both_exact_images_without_deployment(self):
        self.assertNotEqual(self.configs["api"], self.config_blobs["api"])
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.preflight()
                result = engine.publish(self.consume)
                self.assertEqual(set(result["digests"]), {"api", "admin-web"})
                self.assertEqual(
                    result["status"], "REGISTRY_IMAGES_ACKNOWLEDGED_NOT_DEPLOYED"
                )
                self.assertEqual(self.consumed, 1)
                self.assertEqual(self.calls.count(("docker", "push")), 2)
                self.assertTrue(
                    all(
                        service in {"sts", "ecr", "docker"} for service, _ in self.calls
                    )
                )
                with self.assertRaises(ValueError):
                    engine.publish(self.consume)
                self.assertEqual(self.consumed, 1)
            finally:
                engine.close()

    def test_wrong_identity_platform_mutable_repo_or_inaccessible_image_fails_before_consumption(
        self,
    ):
        for attr, value in [
            ("account", "000000000000"),
            ("role", self.role.replace("ImagePublisher", "ApplicationDeploy")),
            ("bad_platform", True),
            ("mutable", True),
            ("bad_failure_code", True),
        ]:
            previous = getattr(self, attr)
            with self.subTest(attr=attr), tempfile.TemporaryDirectory() as folder:
                setattr(self, attr, value)
                engine = self.engine(folder)
                try:
                    with self.assertRaises(ValueError):
                        engine.preflight()
                    with self.assertRaises(ValueError):
                        engine.publish(self.consume)
                    self.assertEqual(self.consumed, 0)
                    self.assertNotIn(("docker", "push"), self.calls)
                finally:
                    engine.close()
            setattr(self, attr, previous)

    def test_lost_push_acknowledgement_never_retries(self):
        self.failure = "lost_ack"
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.preflight()
                with self.assertRaises(RuntimeError):
                    engine.publish(self.consume)
                self.assertEqual(self.calls.count(("docker", "push")), 1)
                self.assertIsNotNone(self.images["api"])
                self.assertEqual(engine.acknowledged, {})
                with self.assertRaises(ValueError):
                    engine.publish(self.consume)
            finally:
                engine.close()

    def test_expired_authority_after_first_ack_preserves_partial_receipt_and_stops(
        self,
    ):
        self.failure = "expired_after_api"
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.preflight()
                with self.assertRaises(ValueError):
                    engine.publish(self.consume)
                self.assertEqual(set(engine.acknowledged), {"api"})
                self.assertIsNone(self.images["admin-web"])
                self.assertEqual(self.calls.count(("docker", "push")), 1)
            finally:
                engine.close()

    def test_explicit_exact_recovery_reuses_existing_api_without_repush(self):
        self.images["api"] = self.image("api")
        self.request["existing_images"]["api"] = self.images["api"]["imageId"][
            "imageDigest"
        ]
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.preflight()
                engine.publish(self.consume)
                self.assertEqual(self.calls.count(("docker", "push")), 1)
            finally:
                engine.close()

    def test_unexpected_existing_tag_or_tampered_manifest_is_not_overwritten(self):
        self.images["api"] = self.image("api")
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                with self.assertRaises(ValueError):
                    engine.preflight()
                self.assertNotIn(("docker", "push"), self.calls)
                self.request["existing_images"]["api"] = self.images["api"]["imageId"][
                    "imageDigest"
                ]
                self.images["api"]["imageManifest"] += " "
                with self.assertRaises(ValueError):
                    engine.preflight()
                self.assertNotIn(("docker", "push"), self.calls)
            finally:
                engine.close()

    def test_retagged_manifest_with_different_config_is_not_accepted(self):
        image = self.image("api")
        body = json.loads(image["imageManifest"])
        body["config"]["digest"] = "sha256:" + "0" * 64
        image["imageManifest"] = json.dumps(body)
        image["imageId"]["imageDigest"] = "sha256:" + hashlib.sha256(
            image["imageManifest"].encode()
        ).hexdigest()
        self.images["api"] = image
        self.request["existing_images"]["api"] = image["imageId"]["imageDigest"]
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                with self.assertRaises(ValueError):
                    engine.preflight()
                self.assertEqual(self.consumed, 0)
            finally:
                engine.close()

    def test_approval_consumption_failure_prevents_login_and_push(self):
        self.failure = "consume"
        with tempfile.TemporaryDirectory() as folder:
            engine = self.engine(folder)
            try:
                engine.preflight()
                with self.assertRaises(ValueError):
                    engine.publish(self.consume)
                self.assertNotIn(("docker", "login"), self.calls)
                self.assertNotIn(("docker", "push"), self.calls)
            finally:
                engine.close()

    def test_request_cannot_select_another_scope_recipe_or_inject_commands(self):
        baseline = copy.deepcopy(self.request)
        for key, value in [("scope", "staging"), ("operation", "rollout")]:
            request = copy.deepcopy(baseline)
            request[key] = value
            with self.assertRaises(ValueError):
                validate_request(request)
        request = copy.deepcopy(baseline)
        request["recipes"]["api"]["path"] = "../Dockerfile"
        with self.assertRaises(ValueError):
            validate_request(request)
        request = copy.deepcopy(baseline)
        request["command"] = ["synthetic-rejected"]
        with self.assertRaises(ValueError):
            validate_request(request)

    def test_policy_is_named_ecr_only_with_no_runtime_or_iam_write(self):
        policy = publisher_policy()
        token, repositories = policy["Statement"]
        self.assertEqual(token["Action"], ["ecr:GetAuthorizationToken"])
        self.assertEqual(token["Resource"], "*")
        self.assertEqual(
            token["Condition"], {"StringEquals": {"aws:RequestedRegion": "ap-south-1"}}
        )
        self.assertEqual(
            repositories["Resource"],
            [
                "arn:aws:ecr:ap-south-1:918870682888:repository/synergie/fieldzilla/production/"
                + kind
                for kind in self.configs
            ],
        )
        self.assertTrue(
            all(action.startswith("ecr:") for action in repositories["Action"])
        )
        self.assertFalse(
            any(
                "Delete" in action or "Policy" in action
                for action in repositories["Action"]
            )
        )
