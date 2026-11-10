"""Bounded ECS execution engine for the existing production release lane.

Callers must revalidate the exact GitHub execution approval via authorize before
any mutation. No listener, database restore, secret-value read or IAM write is
implemented. Failure leaves a journal and requires reviewed recovery; restarting
an interrupted invocation is deliberately not an automatic retry mechanism.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from application_plan import ACCOUNT, REGION, render


class ExecutionError(RuntimeError):
    pass


class RuntimeNotReady(ExecutionError):
    """Expected bounded startup delay, never an identity mismatch."""


class Aws:
    """CLI adapter: no shell, no credentials in arguments, no raw error echo."""

    def __call__(
        self, service: str, action: str, request: dict[str, Any]
    ) -> dict[str, Any]:
        allowed = {
            "sts": {"get-caller-identity"},
            "ecr": {"describe-images"},
            "rds": {"describe-db-snapshots"},
            "ecs": {
                "describe-services",
                "describe-clusters",
                "list-tasks",
                "describe-tasks",
                "describe-container-instances",
                "register-task-definition",
                "create-service",
                "update-service",
                "run-task",
            },
            "elbv2": {"describe-target-health"},
            "logs": {"get-log-events"},
        }
        if action not in allowed.get(service, set()):
            raise ExecutionError(
                "AWS action is outside the application executor boundary"
            )
        result = subprocess.run(
            [
                "aws",
                service,
                action,
                "--region",
                REGION,
                "--output",
                "json",
                "--no-cli-pager",
                "--cli-input-json",
                json.dumps(request),
            ],
            env={**os.environ, "AWS_MAX_ATTEMPTS": "1"},
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if result.returncode:
            raise ExecutionError(
                f"AWS {service}/{action} failed; inspect the private journal before retry"
            )
        return json.loads(result.stdout or "{}")


class Executor:
    def __init__(
        self,
        manifest: dict[str, Any],
        *,
        aws: Callable,
        authorize: Callable[[], None],
        journal: Path,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.manifest = manifest
        self.scope = manifest["scope"]
        self.plan = render(manifest["application"], scope=self.scope)
        self.cluster = "fieldzilla-" + self.scope
        self.instance = manifest.get("container_instance_arn", "")
        if not re.fullmatch(
            rf"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/{self.cluster}/[0-9a-f]{{32}}",
            self.instance,
        ):
            raise ExecutionError("The exact target container instance must be approved")
        self.aws = aws
        self.authorize = authorize
        self.sleep = sleep
        self.journal = journal
        # O_EXCL prevents an ambiguous partial execution from being replayed.
        self.stream = journal.open("x", encoding="utf-8")
        os.chmod(journal, 0o600)
        self.digest = hashlib.sha256(
            json.dumps(manifest, sort_keys=True).encode()
        ).hexdigest()
        self.tasks: dict[str, str] = {}
        self.record("started", scope=self.scope, source=self.plan["source_sha"])

    def close(self):
        self.stream.close()

    def record(self, event: str, **fields):
        self.stream.write(json.dumps({"event": event, **fields}) + "\n")
        self.stream.flush()
        os.fsync(self.stream.fileno())

    def mutate(self, action: str, request: dict[str, Any]) -> dict[str, Any]:
        self.authorize()
        self.record("mutation_started", action=action)
        result = self.aws("ecs", action, request)
        self.record("mutation_completed", action=action)
        return result

    def service(self, kind: str) -> dict[str, Any] | None:
        name = self.cluster + "-" + kind
        reply = self.aws(
            "ecs", "describe-services", {"cluster": self.cluster, "services": [name]}
        )
        rows = reply.get("services", [])
        if not rows:
            failures = reply.get("failures", [])
            if failures and all(f.get("reason") == "MISSING" for f in failures):
                return None
            raise ExecutionError("Service lookup failed")
        if (
            len(rows) != 1
            or reply.get("failures")
            or rows[0].get("serviceName") != name
            or rows[0].get("clusterArn", "").rsplit("/", 1)[-1] != self.cluster
            or rows[0].get("status") != "ACTIVE"
        ):
            raise ExecutionError("Unexpected service identity")
        return rows[0]

    def quiet(self):
        for kind in ("api", "admin-web"):
            current = self.service(kind)
            if current and any(
                current.get(key) != 0
                for key in ("desiredCount", "runningCount", "pendingCount")
            ):
                raise ExecutionError("Target service is not stopped")
        reply = self.aws("ecs", "describe-clusters", {"clusters": [self.cluster]})
        rows = reply.get("clusters", [])
        expected = f"arn:aws:ecs:{REGION}:{ACCOUNT}:cluster/{self.cluster}"
        if (
            reply.get("failures")
            or len(rows) != 1
            or rows[0].get("clusterArn") != expected
            or rows[0].get("status") != "ACTIVE"
        ):
            raise ExecutionError("Exact target cluster readback is unavailable")
        # Counts cover standalone and service tasks, including tasks that have
        # not started yet. This is an observation, not an atomic writer fence;
        # the governed execution lane must separately exclude other writers.
        for key in ("runningTasksCount", "pendingTasksCount"):
            count = rows[0].get(key)
            if type(count) is not int or count != 0:
                raise ExecutionError("A target-cluster task can still write")

    def preflight(self):
        identity = self.aws("sts", "get-caller-identity", {})
        role = (
            "SynergieFieldzillaProduction"
            + ("Rehearsal" if self.scope.endswith("rehearsal") else "")
            + "ApplicationDeploy"
        )
        pattern = rf"arn:aws:sts::{ACCOUNT}:assumed-role/{role}/[^/]+"
        if identity.get("Account") != ACCOUNT or not re.fullmatch(
            pattern, identity.get("Arn", "")
        ):
            raise ExecutionError(
                "Execution identity is not the exact scoped deployment role"
            )
        for kind in ("api", "admin-web"):
            reply = self.aws(
                "ecr",
                "describe-images",
                {
                    "repositoryName": "synergie/fieldzilla/production/" + kind,
                    "imageIds": [{"imageTag": self.plan["source_sha"]}],
                },
            )
            rows = reply.get("imageDetails", [])
            if (
                len(rows) != 1
                or rows[0].get("imageDigest")
                != self.manifest["application"][kind + "_digest"]
            ):
                raise ExecutionError("Registry source tag/digest differs")
        if self.scope == "production":
            snapshot = self.aws(
                "rds",
                "describe-db-snapshots",
                {
                    "DBSnapshotIdentifier": self.manifest["snapshot_id"],
                },
            ).get("DBSnapshots", [])
            if (
                len(snapshot) != 1
                or snapshot[0].get("Status") != "available"
                or snapshot[0].get("SnapshotType") != "manual"
                or snapshot[0].get("Encrypted") is not True
                or snapshot[0].get("DBInstanceIdentifier") != "fieldzilla-production"
            ):
                raise ExecutionError(
                    "Exact encrypted manual production snapshot is not Available"
                )
        self.quiet()
        if set(self.manifest["prior_tasks"]) != {"api", "admin-web"}:
            raise ExecutionError("Both exact prior service states must be recorded")
        for request in self.plan["service_preparation"]:
            kind = request["serviceName"].removeprefix(self.cluster + "-")
            current = self.service(kind)
            expected = self.manifest["prior_tasks"][kind]
            if current is None:
                if expected is not None:
                    raise ExecutionError("Expected prior service is missing")
            elif (
                current.get("taskDefinition") != expected
                or current.get("loadBalancers") != request["loadBalancers"]
            ):
                raise ExecutionError("Prior service identity or target group changed")

    def prepare(self):
        self.preflight()
        for definition in self.plan["task_definitions"]:
            kind = definition["containerDefinitions"][0]["name"]
            arn = (
                self.mutate("register-task-definition", definition)
                .get("taskDefinition", {})
                .get("taskDefinitionArn", "")
            )
            if not re.fullmatch(
                rf"arn:aws:ecs:{REGION}:{ACCOUNT}:task-definition/{self.cluster}-{kind}:\d+",
                arn,
            ):
                raise ExecutionError(
                    "Registered task identity differs; stop for manual inspection"
                )
            self.tasks[kind] = arn
            self.record("task_registered", kind=kind, arn=arn)
        for request in self.plan["service_preparation"]:
            kind = request["serviceName"].removeprefix(self.cluster + "-")
            current = self.service(kind)
            expected = self.manifest["prior_tasks"].get(kind)
            if current is not None:
                if (
                    current.get("taskDefinition") != expected
                    or current.get("loadBalancers") != request["loadBalancers"]
                ):
                    raise ExecutionError(
                        "Prior service task or target-group binding differs"
                    )
                self.mutate(
                    "update-service",
                    {
                        "cluster": self.cluster,
                        "service": request["serviceName"],
                        "taskDefinition": self.tasks[kind],
                        "desiredCount": 0,
                    },
                )
            else:
                if expected is not None:
                    raise ExecutionError("Expected prior service is missing")
                self.mutate(
                    "create-service",
                    {
                        **request,
                        "taskDefinition": self.tasks[kind],
                        "clientToken": hashlib.sha256(
                            (self.digest + kind).encode()
                        ).hexdigest()[:36],
                    },
                )
        self.quiet()

    def task(
        self, kind: str, *, command: list[str] | None = None, phase: str = "migration"
    ) -> dict[str, Any]:
        request: dict[str, Any] = {
            "cluster": self.cluster,
            "taskDefinition": self.tasks[kind],
            "count": 1,
            "launchType": "EC2",
            "clientToken": self.digest[:32] + phase,
        }
        if command is not None:
            request["overrides"] = {
                "containerOverrides": [{"name": kind, "command": command}]
            }
        reply = self.mutate("run-task", request)
        rows = reply.get("tasks", [])
        if reply.get("failures") or len(rows) != 1:
            raise ExecutionError("Task did not start; inspect journal without replay")
        arn = rows[0].get("taskArn", "")
        if not re.fullmatch(
            rf"arn:aws:ecs:{REGION}:{ACCOUNT}:task/{self.cluster}/[0-9a-f]+", arn
        ):
            raise ExecutionError("Task ARN differs")
        self.record("task_started", kind=kind, arn=arn)
        for _ in range(120):
            reply = self.aws(
                "ecs", "describe-tasks", {"cluster": self.cluster, "tasks": [arn]}
            )
            tasks = reply.get("tasks", [])
            if reply.get("failures") or len(tasks) != 1:
                raise ExecutionError("Task readback unavailable")
            row = tasks[0]
            if row.get("lastStatus") == "STOPPED":
                containers = row.get("containers", [])
                if (
                    len(containers) != 1
                    or containers[0].get("exitCode") != 0
                    or row.get("taskDefinitionArn") != self.tasks[kind]
                    or containers[0].get("imageDigest")
                    != self.manifest["application"]["api_digest"]
                ):
                    raise ExecutionError(
                        "Task failed; no automatic migration retry or database rollback"
                    )
                self.record("task_succeeded", arn=arn)
                return row
            self.sleep(5)
        raise ExecutionError(
            "Task outcome unresolved; hold writes and inspect, never replay blindly"
        )

    def attest_database(self, phase: str):
        if phase not in {"before", "after"}:
            raise ExecutionError("Unknown database attestation phase")
        self.quiet()
        row = self.task(
            "migration",
            command=["python", "-c", DATABASE_ATTESTATION],
            phase="db-" + phase,
        )
        task_id = row["taskArn"].rsplit("/", 1)[-1]
        request = {
            "logGroupName": "/synergie/fieldzilla/" + self.scope + "/migration",
            "logStreamName": self.plan["source_sha"] + "/migration/" + task_id,
            "startFromHead": True,
        }
        observed = []
        for _ in range(12):
            reply = self.aws("logs", "get-log-events", request)
            for event in reply.get("events", []):
                message = event.get("message", "")
                if message.startswith("FZ_DB_ATTESTATION="):
                    observed.append(json.loads(message.split("=", 1)[1]))
            token = reply.get("nextForwardToken")
            if not token or request.get("nextToken") == token:
                break
            request["nextToken"] = token
        if len(observed) != 1:
            raise ExecutionError("Database attestation is absent or ambiguous")
        expected = self.manifest["database"]
        facts = observed[0]
        if (
            facts.get("database") != expected["name"]
            or facts.get("role") != expected["role"]
            or facts.get("superuser") is not False
            or facts.get("bypassrls") is not False
            or facts.get("revisions") != sorted(expected[phase])
        ):
            raise ExecutionError("Database identity, privilege or revision differs")
        self.record("database_attested", phase=phase, revisions=facts["revisions"])

    def migrate(self):
        self.attest_database("before")
        self.quiet()
        self.task("migration")
        self.attest_database("after")

    def start(self):
        self.quiet()
        for kind in ("api", "admin-web"):
            current = self.service(kind)
            if current is None or current.get("taskDefinition") != self.tasks[kind]:
                raise ExecutionError("Prepared service changed before start")
            self.mutate(
                "update-service",
                {
                    "cluster": self.cluster,
                    "service": self.cluster + "-" + kind,
                    "desiredCount": 1,
                    "taskDefinition": self.tasks[kind],
                },
            )
        # Caller must perform exact task/image/target health and authenticated
        # sync verification before traffic is eligible. Merely starting is not PASS.
        self.record("awaiting_runtime_verification")

    def verify_runtime(self):
        """Read back exact stable tasks and their healthy ALB registrations.

        This is infrastructure evidence only. The caller must separately prove
        normal authentication, evidence delivery and acknowledged sync.
        """
        observed = {}
        for request in self.plan["service_preparation"]:
            kind = request["serviceName"].removeprefix(self.cluster + "-")
            current = self.service(kind)
            if (
                current is None
                or current.get("taskDefinition") != self.tasks[kind]
                or current.get("loadBalancers") != request["loadBalancers"]
                or current.get("desiredCount") != 1
            ):
                raise ExecutionError(
                    "Service changed from the exact requested definition or count"
                )
            if current.get("runningCount") != 1 or current.get("pendingCount") != 0:
                raise RuntimeNotReady("Service is still starting")
            deployments = current.get("deployments", [])
            allowed = {self.tasks[kind], self.manifest["prior_tasks"].get(kind)}
            if not deployments or any(
                row.get("taskDefinition") not in allowed
                or row.get("rolloutState") == "FAILED"
                for row in deployments
            ):
                raise ExecutionError("Failed or unexpected service deployment")
            if (
                len(deployments) != 1
                or deployments[0].get("status") != "PRIMARY"
                or deployments[0].get("rolloutState") != "COMPLETED"
            ):
                raise RuntimeNotReady("Known service rollout is still in progress")
            listing = self.aws(
                "ecs",
                "list-tasks",
                {
                    "cluster": self.cluster,
                    "containerInstance": self.instance,
                    "serviceName": request["serviceName"],
                    "desiredStatus": "RUNNING",
                },
            )
            arns = listing.get("taskArns", [])
            if len(arns) != 1 or listing.get("nextToken"):
                raise ExecutionError("Expected exactly one service task")
            reply = self.aws(
                "ecs", "describe-tasks", {"cluster": self.cluster, "tasks": arns}
            )
            rows = reply.get("tasks", [])
            if reply.get("failures") or len(rows) != 1:
                raise ExecutionError("Running task readback is unavailable")
            task = rows[0]
            containers = task.get("containers", [])
            if (
                task.get("taskArn") != arns[0]
                or task.get("taskDefinitionArn") != self.tasks[kind]
                or task.get("group") != "service:" + request["serviceName"]
                or task.get("lastStatus") != "RUNNING"
                or task.get("desiredStatus") != "RUNNING"
                or len(containers) != 1
                or containers[0].get("name") != kind
                or containers[0].get("lastStatus") != "RUNNING"
                or containers[0].get("imageDigest")
                != self.manifest["application"][kind + "_digest"]
            ):
                raise ExecutionError("Executing task identity, state or image differs")
            instance = task.get("containerInstanceArn", "")
            prefix = (
                f"arn:aws:ecs:{REGION}:{ACCOUNT}:container-instance/{self.cluster}/"
            )
            if (
                instance != self.instance
                or not instance.startswith(prefix)
                or not re.fullmatch("[0-9a-f]+", instance[len(prefix) :])
            ):
                raise ExecutionError("Task host is outside the exact target cluster")
            hosts = self.aws(
                "ecs",
                "describe-container-instances",
                {
                    "cluster": self.cluster,
                    "containerInstances": [instance],
                },
            )
            host_rows = hosts.get("containerInstances", [])
            if (
                hosts.get("failures")
                or len(host_rows) != 1
                or host_rows[0].get("containerInstanceArn") != instance
                or host_rows[0].get("status") != "ACTIVE"
                or host_rows[0].get("agentConnected") is not True
                or not re.fullmatch(
                    r"i-[0-9a-f]+", host_rows[0].get("ec2InstanceId", "")
                )
            ):
                raise ExecutionError("Exact service host cannot be verified")
            bindings = containers[0].get("networkBindings", [])
            expected_port = request["loadBalancers"][0]["containerPort"]
            if (
                len(bindings) != 1
                or bindings[0].get("containerPort") != expected_port
                or bindings[0].get("hostPort") != expected_port
                or bindings[0].get("protocol") != "tcp"
            ):
                raise ExecutionError(
                    "Task port differs from the reviewed bridge-mode binding"
                )
            target = {"Id": host_rows[0]["ec2InstanceId"], "Port": expected_port}
            health = self.aws(
                "elbv2",
                "describe-target-health",
                {
                    "TargetGroupArn": request["loadBalancers"][0]["targetGroupArn"],
                },
            ).get("TargetHealthDescriptions", [])
            if not health:
                raise RuntimeNotReady("Executing service target is not registered yet")
            if len(health) != 1 or health[0].get("Target") != target:
                raise ExecutionError(
                    "Target registration differs from the executing task"
                )
            state = health[0].get("TargetHealth", {}).get("State")
            if state in {"initial", "unhealthy"}:
                raise RuntimeNotReady("Exact service target has not become healthy")
            if state != "healthy":
                raise ExecutionError("Exact service target is in an unexpected state")
            observed[kind] = {"task": arns[0], "digest": containers[0]["imageDigest"]}
        self.record(
            "runtime_artifacts_verified",
            services=observed,
            acceptance="authenticated application smoke still required",
        )
        return observed

    def wait_runtime(self, *, attempts: int = 120):
        """Wait only for expected startup states; identity drift fails immediately."""
        if type(attempts) is not int or not 1 <= attempts <= 120:
            raise ExecutionError(
                "Runtime wait must stay within the bounded ten-minute window"
            )
        for attempt in range(attempts):
            try:
                return self.verify_runtime()
            except RuntimeNotReady:
                if attempt + 1 < attempts:
                    self.sleep(5)
        self.record("runtime_wait_timed_out")
        raise ExecutionError(
            "Runtime did not become healthy; reviewed recovery is required"
        )

    def hold_for_recovery(self):
        # No database operation or automatic previous-image rollback. Accepted
        # writes, receipts, evidence and encryption keys remain in place.
        for kind in ("api", "admin-web"):
            current = self.service(kind)
            if current is not None:
                if current.get("taskDefinition") not in {
                    self.tasks.get(kind),
                    self.manifest["prior_tasks"].get(kind),
                }:
                    raise ExecutionError(
                        "Recovery target changed; stop before scaling an unexpected task"
                    )
                self.mutate(
                    "update-service",
                    {
                        "cluster": self.cluster,
                        "service": self.cluster + "-" + kind,
                        "desiredCount": 0,
                    },
                )
        self.record("recovery_requested", database="preserved; no restore or downgrade")


# The one-off attestor emits metadata only. Exceptions deliberately omit URLs,
# credentials and SQL details from shared logs. No secret values leave ECS.
DATABASE_ATTESTATION = r"""
import asyncio, json, os, sys
async def main():
    from sqlalchemy import text
    from sqlalchemy.ext.asyncio import create_async_engine
    engine = create_async_engine(os.environ["APP_DATABASE_URL"])
    try:
        async with engine.connect() as connection:
            row = (await connection.execute(text("SELECT current_database(), current_user, rolsuper, rolbypassrls FROM pg_roles WHERE rolname=current_user"))).one()
            exists = (await connection.execute(text("SELECT to_regclass('public.alembic_version') IS NOT NULL"))).scalar_one()
            versions = sorted((await connection.execute(text("SELECT version_num FROM public.alembic_version"))).scalars()) if exists else []
            print("FZ_DB_ATTESTATION=" + json.dumps({"database": row[0], "role": row[1], "superuser": row[2], "bypassrls": row[3], "revisions": versions}), flush=True)
    finally:
        await engine.dispose()
try:
    asyncio.run(main())
except Exception:
    print("FZ_DB_ATTESTATION_FAILED", flush=True)
    sys.exit(1)
"""
