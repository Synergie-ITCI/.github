"""Deterministic engine checks; these do not count as an AWS rehearsal."""

import copy
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts/fieldzilla-production"))
from application_executor import Aws, ExecutionError, Executor

spec = importlib.util.spec_from_file_location(
    "plan_fixture", Path(__file__).with_name("test_production_application_plan.py")
)
fixture = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fixture)


class Cloud:
    def __init__(self, manifest):
        self.manifest = manifest
        self.calls = []
        self.services = {}
        self.writers = []
        self.bad_digest = False
        self.bad_role = False
        self.bad_snapshot = False
        self.registers = 0

    def __call__(self, service, action, request):
        self.calls.append((service, action, copy.deepcopy(request)))
        if action == "get-caller-identity":
            role = (
                "OtherRole"
                if self.bad_role
                else "SynergieFieldzillaProductionApplicationDeploy"
            )
            return {
                "Account": "918870682888",
                "Arn": "arn:aws:sts::918870682888:assumed-role/" + role + "/test",
            }
        if action == "describe-images":
            kind = request["repositoryName"].split("/")[-1]
            return {
                "imageDetails": [
                    {
                        "imageDigest": "changed"
                        if self.bad_digest
                        else self.manifest["application"][kind + "_digest"]
                    }
                ]
            }
        if action == "describe-db-snapshots":
            return {
                "DBSnapshots": [
                    {
                        "Status": "creating" if self.bad_snapshot else "available",
                        "SnapshotType": "manual",
                        "Encrypted": True,
                        "DBInstanceIdentifier": "fieldzilla-production",
                    }
                ]
            }
        if action == "describe-services":
            name = request["services"][0]
            if name not in self.services:
                return {"services": [], "failures": [{"reason": "MISSING"}]}
            return {"services": [self.services[name]]}
        if action == "list-tasks":
            return {"taskArns": self.writers}
        if action == "describe-clusters":
            return {
                "clusters": [
                    {
                        "clusterArn": "arn:aws:ecs:ap-south-1:918870682888:cluster/fieldzilla-production",
                        "status": "ACTIVE",
                        "runningTasksCount": len(self.writers),
                        "pendingTasksCount": 0,
                    }
                ]
            }
        if action == "register-task-definition":
            self.registers += 1
            return {
                "taskDefinition": {
                    "taskDefinitionArn": "arn:aws:ecs:ap-south-1:918870682888:task-definition/"
                    + request["family"]
                    + ":1"
                }
            }
        if action == "create-service":
            self.services[request["serviceName"]] = {
                **request,
                "status": "ACTIVE",
                "clusterArn": "arn:aws:ecs:ap-south-1:918870682888:cluster/fieldzilla-production",
                "runningCount": 0,
                "pendingCount": 0,
            }
            return {}
        if action == "update-service":
            self.services[request["service"]].update(request)
            return {}
        raise AssertionError((service, action))


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manifest = {
            "scope": "production",
            "container_instance_arn": "arn:aws:ecs:ap-south-1:918870682888:container-instance/fieldzilla-production/"
            + "d" * 32,
            "application": fixture.manifest(),
            "snapshot_id": "approved-snapshot",
            "prior_tasks": {"api": None, "admin-web": None},
        }
        self.cloud = Cloud(self.manifest)
        self.authorizations = 0

    def authorize(self):
        self.authorizations += 1

    def engine(self, authorize=None):
        e = Executor(
            self.manifest,
            aws=self.cloud,
            authorize=authorize or self.authorize,
            journal=Path(self.temp.name) / "journal.jsonl",
            sleep=lambda _: None,
        )
        self.addCleanup(e.close)
        return e

    def test_prepare_pins_three_tasks_and_two_zero_count_services(self):
        e = self.engine()
        e.prepare()
        self.assertEqual(self.cloud.registers, 3)
        self.assertEqual(len(self.cloud.services), 2)
        self.assertTrue(
            all(s["desiredCount"] == 0 for s in self.cloud.services.values())
        )
        self.assertEqual(self.authorizations, 5)
        tokens = [
            request["clientToken"]
            for _, action, request in self.cloud.calls
            if action == "create-service"
        ]
        self.assertTrue(all(len(token) <= 36 for token in tokens))
        self.assertEqual(len(set(tokens)), 2)
        self.assertFalse(any(action == "run-task" for _, action, _ in self.cloud.calls))

    def test_wrong_role_digest_snapshot_or_writer_stops_before_registration(self):
        for attr in ("bad_role", "bad_digest", "bad_snapshot", "writers"):
            with self.subTest(attr=attr), tempfile.TemporaryDirectory() as folder:
                cloud = Cloud(self.manifest)
                setattr(cloud, attr, ["writer"] if attr == "writers" else True)
                e = Executor(
                    self.manifest,
                    aws=cloud,
                    authorize=self.authorize,
                    journal=Path(folder) / "journal",
                    sleep=lambda _: None,
                )
                try:
                    with self.assertRaises(ExecutionError):
                        e.prepare()
                    self.assertEqual(cloud.registers, 0)
                finally:
                    e.close()

    def test_changed_prior_state_stops_before_registration(self):
        self.manifest["prior_tasks"]["api"] = "expected-but-missing"
        with self.assertRaises(ExecutionError):
            self.engine().prepare()
        self.assertEqual(self.cloud.registers, 0)

    def test_quiet_cluster_readback_fails_closed(self):
        for changes in (
            {"pendingTasksCount": 1},
            {"runningTasksCount": None},
            {"pendingTasksCount": False},
            {
                "clusterArn": "arn:aws:ecs:ap-south-1:918870682888:cluster/fieldzilla-staging"
            },
            {"status": "INACTIVE"},
        ):
            with self.subTest(changes=changes), tempfile.TemporaryDirectory() as folder:
                cloud = Cloud(self.manifest)

                def read(service, action, request, cloud=cloud, changes=changes):
                    reply = cloud(service, action, request)
                    if action == "describe-clusters":
                        reply["clusters"][0].update(changes)
                    return reply

                e = Executor(
                    self.manifest,
                    aws=read,
                    authorize=self.authorize,
                    journal=Path(folder) / "journal",
                    sleep=lambda _: None,
                )
                try:
                    with self.assertRaises(ExecutionError):
                        e.prepare()
                    self.assertEqual(cloud.registers, 0)
                finally:
                    e.close()

    def test_expired_authorization_prevents_every_mutation(self):
        def reject():
            raise ValueError("approval expired")

        with self.assertRaises(ValueError):
            self.engine(authorize=reject).prepare()
        self.assertEqual(self.cloud.registers, 0)

    def test_existing_journal_cannot_be_replayed(self):
        self.engine()
        with self.assertRaises(FileExistsError):
            self.engine()

    def test_staging_or_wrong_rehearsal_credentials_rejected(self):
        self.manifest["scope"] = "staging"
        with self.assertRaises(ValueError):
            self.engine()
        self.manifest["scope"] = "production-rehearsal"
        with self.assertRaises(ValueError):
            self.engine()

    def test_adapter_forbids_secret_reads_listener_and_iam_changes(self):
        for service, action in (
            ("secretsmanager", "get-secret-value"),
            ("iam", "put-role-policy"),
            ("elbv2", "modify-rule"),
            ("rds", "restore-db-instance-from-db-snapshot"),
        ):
            with self.assertRaises(ExecutionError):
                Aws()(service, action, {})

    def test_recovery_only_stops_owned_services_and_never_restores_database(self):
        e = self.engine()
        e.prepare()
        e.start()
        e.hold_for_recovery()
        self.assertTrue(
            all(s["desiredCount"] == 0 for s in self.cloud.services.values())
        )
        self.assertFalse(
            any(
                service == "rds" and action != "describe-db-snapshots"
                for service, action, _ in self.cloud.calls
            )
        )
        records = [json.loads(line) for line in e.journal.read_text().splitlines()]
        self.assertEqual(records[-1]["event"], "recovery_requested")


class TaskCloud(Cloud):
    def __init__(self, manifest):
        super().__init__(manifest)
        self.started = {}
        self.counter = 0
        self.revisions = manifest["database"]["before"]
        self.wrong_role = False
        self.wrong_image = False

    def __call__(self, service, action, request):
        if action == "run-task":
            self.calls.append((service, action, copy.deepcopy(request)))
            self.counter += 1
            task_id = f"{self.counter:032x}"
            arn = (
                "arn:aws:ecs:ap-south-1:918870682888:task/fieldzilla-production/"
                + task_id
            )
            if "overrides" not in request:
                self.revisions = self.manifest["database"]["after"]
            self.started[arn] = {
                "taskArn": arn,
                "taskDefinitionArn": request["taskDefinition"],
                "lastStatus": "STOPPED",
                "containers": [
                    {
                        "exitCode": 0,
                        "imageDigest": "changed"
                        if self.wrong_image
                        else self.manifest["application"]["api_digest"],
                    }
                ],
            }
            return {"tasks": [{"taskArn": arn}]}
        if action == "describe-tasks":
            self.calls.append((service, action, copy.deepcopy(request)))
            return {"tasks": [self.started[request["tasks"][0]]]}
        if action == "get-log-events":
            facts = {
                "database": self.manifest["database"]["name"],
                "role": "unexpected"
                if self.wrong_role
                else self.manifest["database"]["role"],
                "superuser": False,
                "bypassrls": False,
                "revisions": self.revisions,
            }
            return {"events": [{"message": "FZ_DB_ATTESTATION=" + json.dumps(facts)}]}
        return super().__call__(service, action, request)


class DatabaseProtocolTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manifest = {
            "scope": "production",
            "container_instance_arn": "arn:aws:ecs:ap-south-1:918870682888:container-instance/fieldzilla-production/"
            + "d" * 32,
            "application": fixture.manifest(),
            "snapshot_id": "approved-snapshot",
            "prior_tasks": {"api": None, "admin-web": None},
            "database": {
                "name": "synthetic",
                "role": "synthetic_migrator",
                "before": [],
                "after": ["20261109_0073"],
            },
        }
        self.cloud = TaskCloud(self.manifest)
        self.engine = Executor(
            self.manifest,
            aws=self.cloud,
            authorize=lambda: None,
            journal=Path(self.temp.name) / "journal",
            sleep=lambda _: None,
        )
        self.addCleanup(self.engine.close)
        self.engine.prepare()

    def test_private_before_migrate_after_protocol_uses_distinct_idempotency_tokens(
        self,
    ):
        self.engine.migrate()
        requests = [r for _, action, r in self.cloud.calls if action == "run-task"]
        self.assertEqual(len(requests), 3)
        self.assertEqual(len({r["clientToken"] for r in requests}), 3)
        self.assertTrue(all(len(r["clientToken"]) <= 64 for r in requests))
        self.assertIn("overrides", requests[0])
        self.assertNotIn("overrides", requests[1])
        self.assertIn("overrides", requests[2])
        self.assertEqual(self.cloud.revisions, ["20261109_0073"])

    def test_wrong_private_db_identity_prevents_migration(self):
        self.cloud.wrong_role = True
        with self.assertRaises(ExecutionError):
            self.engine.migrate()
        self.assertTrue(
            all(
                "overrides" in r
                for _, action, r in self.cloud.calls
                if action == "run-task"
            )
        )

    def test_wrong_executing_digest_prevents_accepting_exit_zero(self):
        self.cloud.wrong_image = True
        with self.assertRaises(ExecutionError):
            self.engine.migrate()
        self.assertEqual(self.cloud.counter, 1)

    def test_unknown_attestation_phase_cannot_launch_a_task(self):
        with self.assertRaises(ExecutionError):
            self.engine.attest_database("anything")
        self.assertEqual(self.cloud.counter, 0)


class RuntimeCloud(Cloud):
    def __init__(self, manifest):
        super().__init__(manifest)
        self.tamper = None
        self.instance = (
            "arn:aws:ecs:ap-south-1:918870682888:container-instance/fieldzilla-production/"
            + "d" * 32
        )

    def __call__(self, service, action, request):
        if action in {
            "list-tasks",
            "describe-tasks",
            "describe-container-instances",
            "describe-target-health",
        }:
            self.calls.append((service, action, copy.deepcopy(request)))
            if action == "list-tasks" and "serviceName" in request:
                return {
                    "taskArns": [
                        "arn:aws:ecs:ap-south-1:918870682888:task/fieldzilla-production/"
                        + ("a" if request["serviceName"].endswith("-api") else "b") * 32
                    ]
                }
            if action == "describe-tasks":
                kind = "api" if request["tasks"][0].endswith("a" * 32) else "admin-web"
                current = self.services["fieldzilla-production-" + kind]
                port = current["loadBalancers"][0]["containerPort"]
                row = {
                    "taskArn": request["tasks"][0],
                    "taskDefinitionArn": current["taskDefinition"],
                    "group": "service:fieldzilla-production-" + kind,
                    "lastStatus": "RUNNING",
                    "desiredStatus": "RUNNING",
                    "containerInstanceArn": self.instance,
                    "containers": [
                        {
                            "name": kind,
                            "lastStatus": "RUNNING",
                            "imageDigest": self.manifest["application"][
                                kind + "_digest"
                            ],
                            "networkBindings": [
                                {
                                    "containerPort": port,
                                    "hostPort": port,
                                    "protocol": "tcp",
                                }
                            ],
                        }
                    ],
                }
                if self.tamper == "digest":
                    row["containers"][0]["imageDigest"] = "wrong"
                if self.tamper == "group":
                    row["group"] = "service:another"
                if self.tamper == "port":
                    row["containers"][0]["networkBindings"][0]["hostPort"] += 1
                if self.tamper == "cluster":
                    row["containerInstanceArn"] = self.instance.replace(
                        "production/", "staging/"
                    )
                return {"tasks": [row]}
            if action == "describe-container-instances":
                return {
                    "containerInstances": [
                        {
                            "containerInstanceArn": self.instance,
                            "status": "ACTIVE",
                            "agentConnected": self.tamper != "agent",
                            "ec2InstanceId": "i-123abc",
                        }
                    ]
                }
            if action == "describe-target-health":
                service_row = next(
                    s
                    for s in self.services.values()
                    if s["loadBalancers"][0]["targetGroupArn"]
                    == request["TargetGroupArn"]
                )
                target = {
                    "Id": "i-123abc",
                    "Port": service_row["loadBalancers"][0]["containerPort"],
                }
                row = {
                    "Target": target,
                    "TargetHealth": {
                        "State": "unhealthy" if self.tamper == "health" else "healthy"
                    },
                }
                if self.tamper == "target":
                    target["Id"] = "i-999"
                return {
                    "TargetHealthDescriptions": [row, row]
                    if self.tamper == "extra-target"
                    else [row]
                }
        return super().__call__(service, action, request)


class RuntimeReadbackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.manifest = {
            "scope": "production",
            "container_instance_arn": "arn:aws:ecs:ap-south-1:918870682888:container-instance/fieldzilla-production/"
            + "d" * 32,
            "application": fixture.manifest(),
            "snapshot_id": "approved-snapshot",
            "prior_tasks": {"api": None, "admin-web": None},
        }
        self.cloud = RuntimeCloud(self.manifest)
        self.engine = Executor(
            self.manifest,
            aws=self.cloud,
            authorize=lambda: None,
            journal=Path(self.temp.name) / "journal",
            sleep=lambda _: None,
        )
        self.addCleanup(self.engine.close)
        self.engine.prepare()
        self.engine.start()
        for row in self.cloud.services.values():
            row["runningCount"] = 1
            row["deployments"] = [
                {
                    "status": "PRIMARY",
                    "rolloutState": "COMPLETED",
                    "taskDefinition": row["taskDefinition"],
                }
            ]

    def test_reads_actual_images_and_exclusive_healthy_targets_without_writes(self):
        before = len(self.cloud.calls)
        result = self.engine.verify_runtime()
        self.assertEqual(set(result), {"api", "admin-web"})
        self.assertFalse(
            any(
                action in {"update-service", "register-task-definition", "run-task"}
                for _, action, _ in self.cloud.calls[before:]
            )
        )
        self.assertIn(
            "authenticated application smoke still required",
            self.engine.journal.read_text(),
        )

    def test_rejects_wrong_artifact_scope_port_host_or_target(self):
        for tamper in (
            "digest",
            "group",
            "port",
            "cluster",
            "agent",
            "health",
            "target",
            "extra-target",
        ):
            with self.subTest(tamper=tamper):
                self.cloud.tamper = tamper
                with self.assertRaises(ExecutionError):
                    self.engine.verify_runtime()

    def test_incomplete_or_competing_rollout_is_not_healthy(self):
        row = self.cloud.services["fieldzilla-production-api"]
        row["deployments"][0]["rolloutState"] = "IN_PROGRESS"
        with self.assertRaises(ExecutionError):
            self.engine.verify_runtime()
        row["deployments"][0]["rolloutState"] = "COMPLETED"
        row["deployments"].append(dict(row["deployments"][0]))
        with self.assertRaises(ExecutionError):
            self.engine.verify_runtime()

    def test_runtime_wait_retries_only_transient_health_not_identity_drift(self):
        sleeps = []
        self.cloud.tamper = "health"

        def settle(seconds):
            sleeps.append(seconds)
            self.cloud.tamper = None

        self.engine.sleep = settle
        before = len(self.cloud.calls)
        self.engine.wait_runtime(attempts=3)
        self.assertEqual(sleeps, [5])
        self.assertFalse(
            any(
                action in {"update-service", "run-task"}
                for _, action, _ in self.cloud.calls[before:]
            )
        )
        self.cloud.tamper = "digest"
        sleeps.clear()
        with self.assertRaises(ExecutionError):
            self.engine.wait_runtime(attempts=3)
        self.assertEqual(sleeps, [])

    def test_runtime_wait_timeout_is_bounded_and_never_rolls_back_the_database(self):
        self.cloud.tamper = "health"
        sleeps = []
        self.engine.sleep = sleeps.append
        with self.assertRaises(ExecutionError):
            self.engine.wait_runtime(attempts=3)
        self.assertEqual(sleeps, [5, 5])
        self.assertIn("runtime_wait_timed_out", self.engine.journal.read_text())
        self.assertFalse(
            any(
                action in {"run-task", "update-service"}
                for _, action, _ in self.cloud.calls[-10:]
            )
        )
