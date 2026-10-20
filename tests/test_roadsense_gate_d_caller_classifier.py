"""The deployment-risk exception accepts only the reviewed RoadSense caller shape."""

import importlib.util
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"
spec = importlib.util.spec_from_file_location("roadsense_pr_qa_engine", ENGINE)
engine = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(ENGINE.parent))
sys.modules[spec.name] = engine
spec.loader.exec_module(engine)


def caller(path):
    job_id, central_file, permissions, inputs, approver_only = engine.ROADSENSE_GATE_D_CALLERS[path]
    source = ["name: RoadSense review", "", "on:", "  workflow_dispatch:", "    inputs:"]
    for name in inputs:
        source += [f"      {name}:", "        description: Reviewed exact value", "        required: true", "        type: string"]
    source += ["", "permissions:"]
    source += [f"  {key}: {value}" for key, value in permissions.items()]
    condition = "github.ref == 'refs/heads/main'"
    if approver_only:
        condition += " && github.actor == 'SaurabhVermaIN' && github.actor_id == '52234089'"
    source += ["", "jobs:", f"  {job_id}:", f"    if: {condition}",
               f"    uses: Synergie-ITCI/.github/.github/workflows/{central_file}@roadsense-gate-d-v1",
               "    with:"]
    source += [f"      {target}: ${{{{ inputs.{name} }}}}" for name, target in inputs.items()]
    return "\n".join(source) + "\n"


class CallerClassifierTests(unittest.TestCase):
    def setUp(self):
        self.ctx = SimpleNamespace(event={"repository": {"full_name": "Synergie-ITCI/roadsense-production-dashboard"}})

    def test_all_four_exact_callers_are_reviewable(self):
        for path in engine.ROADSENSE_GATE_D_CALLERS:
            with self.subTest(path=path):
                self.assertTrue(engine.roadsense_gate_d_caller_details(self.ctx, path, caller(path)))

    def test_changed_pin_trigger_permission_and_actor_are_rejected(self):
        path = ".github/workflows/roadsense-controlled-release.yml"
        clean = caller(path)
        for bad in (
            clean.replace("@roadsense-gate-d-v1", "@main"),
            clean.replace("workflow_dispatch:", "push:"),
            clean.replace("  id-token: write", "  id-token: read"),
            clean.replace("github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/development'"),
            clean + "    steps:\n      - run: aws ssm send-command\n",
        ):
            with self.subTest(bad=bad[-80:]):
                self.assertFalse(engine.roadsense_gate_d_caller_details(self.ctx, path, bad))
        approval = ".github/workflows/roadsense-gate-d-approve.yml"
        self.assertFalse(engine.roadsense_gate_d_caller_details(
            self.ctx, approval, caller(approval).replace("52234089", "999")))

    def test_exception_does_not_apply_to_other_repositories(self):
        self.ctx.event["repository"]["full_name"] = "Synergie-ITCI/other"
        path = ".github/workflows/roadsense-controlled-release.yml"
        self.assertFalse(engine.roadsense_gate_d_caller_details(self.ctx, path, caller(path)))


if __name__ == "__main__":
    unittest.main()
