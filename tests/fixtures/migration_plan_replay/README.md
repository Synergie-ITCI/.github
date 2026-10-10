# FieldZilla historical replay provenance

These fixtures project observed staging evidence into the prospective v1 format.
The plan files are test plans; they did not exist in those historical commits.
They do not certify historical adoption.

| Transition | Successful staging run | Workflow SHA | Artifact SHA | Source |
| --- | --- | --- | --- | --- |
| 0059→0060 | [37567604112](https://github.com/Synergie-ITCI/programme-management-platform/actions/runs/37567604112) | `fcf75e91d1f0a3554ddcf19ff25fe9779675f0c4` | `b1679598ea9dfbbac3b8244887fc113636169e6f` | Run rollout job image tag and digest evidence; [artifact-to-workflow comparison](https://github.com/Synergie-ITCI/programme-management-platform/compare/b1679598ea9dfbbac3b8244887fc113636169e6f...fcf75e91d1f0a3554ddcf19ff25fe9779675f0c4) |
| 0060→0061 | [37940736156](https://github.com/Synergie-ITCI/programme-management-platform/actions/runs/37940736156) | `a3b6fb2738788f864d26823fb36cda79b7a7face` | `a3b6fb2738788f864d26823fb36cda79b7a7face` | Run rollout job image tag and digest evidence; identical artifact/workflow comparison |

`changed_paths` come from GitHub's base-to-workflow compare for each run. The
image digests and image-only task-definition conclusions come from the successful
rollout job logs. The database heads come from the reviewed migration runner
and staging migration evidence. `0059→0060` is expected to fail because the
artifact-to-workflow diff contains `deploy/staging/project_publish_ecs_migration.py`
and `infra/aws/plan-discovery.tf`.
