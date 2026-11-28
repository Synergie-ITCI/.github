"""The FieldZilla release exception is limited to reviewed iOS upload bytes."""

import hashlib
import importlib.util
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1]
ENGINE = ROOT / "pr-qa" / "pr_qa.py"
SPEC = importlib.util.spec_from_file_location("fieldzilla_ios_pr_qa_engine", ENGINE)
engine = importlib.util.module_from_spec(SPEC)
sys.path.insert(0, str(ENGINE.parent))
sys.modules[SPEC.name] = engine
SPEC.loader.exec_module(engine)

FIXTURES = ROOT / "tests" / "fixtures" / "fieldzilla-ios-release"
WORKFLOW = engine.FIELDZILLA_IOS_RELEASE_WORKFLOW_PATH
SCRIPT = engine.FIELDZILLA_IOS_RELEASE_SCRIPT_PATH


class FieldZillaIosReleaseClassifierTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / WORKFLOW).parent.mkdir(parents=True)
        (self.root / SCRIPT).parent.mkdir(parents=True)
        shutil.copyfile(FIXTURES / "fieldzilla-ios-testflight.yml", self.root / WORKFLOW)
        shutil.copyfile(FIXTURES / "ios-testflight-release.sh", self.root / SCRIPT)
        self.ctx = SimpleNamespace(
            repo=self.root,
            config={},
            event={"repository": {"full_name": "Synergie-ITCI/programme-management-platform"}},
        )

    def test_exact_reviewed_workflow_and_script_are_recognized(self):
        text = (self.root / WORKFLOW).read_text(encoding="utf-8")
        self.assertEqual(hashlib.sha256(text.encode()).hexdigest(), engine.FIELDZILLA_IOS_RELEASE_WORKFLOW_SHA256)
        self.assertEqual(hashlib.sha256((self.root / SCRIPT).read_bytes()).hexdigest(), engine.FIELDZILLA_IOS_RELEASE_SCRIPT_SHA256)
        self.assertTrue(engine.fieldzilla_ios_release_details(self.ctx, WORKFLOW, text))
        details, paths = engine.classify_safe_deployment_workflows(self.ctx, [WORKFLOW])
        self.assertEqual(paths, {WORKFLOW})
        self.assertIn("FIELDZILLA_IOS_RELEASE", details[0])

    def test_workflow_change_is_rejected(self):
        text = (self.root / WORKFLOW).read_text(encoding="utf-8")
        for changed in (
            text.replace("refs/heads/main", "refs/heads/development"),
            text.replace("environment: fieldzilla-ios-release", "environment: production"),
            text.replace("persist-credentials: false", "persist-credentials: true"),
            text + "\n# unreviewed change\n",
        ):
            with self.subTest(changed=changed[-50:]):
                self.assertFalse(engine.fieldzilla_ios_release_details(self.ctx, WORKFLOW, changed))

    def test_changed_release_workflow_still_fails_deployment_risk(self):
        workflow = self.root / WORKFLOW
        workflow.write_text(workflow.read_text(encoding="utf-8") + "\n# unreviewed change\n", encoding="utf-8")
        details, paths = engine.classify_safe_deployment_workflows(self.ctx, [WORKFLOW])
        self.assertEqual((details, paths), ([], set()))
        self.assertIn("controlled Gate D safe shape", engine.unsafe_deployment_workflow_details(self.ctx, [WORKFLOW])[0])

    def test_script_or_repository_change_is_rejected(self):
        text = (self.root / WORKFLOW).read_text(encoding="utf-8")
        script_path = self.root / SCRIPT
        script_path.write_bytes(script_path.read_bytes() + b"\n# unreviewed change\n")
        self.assertFalse(engine.fieldzilla_ios_release_details(self.ctx, WORKFLOW, text))
        shutil.copyfile(FIXTURES / "ios-testflight-release.sh", script_path)
        self.ctx.event["repository"]["full_name"] = "Synergie-ITCI/other"
        self.assertFalse(engine.fieldzilla_ios_release_details(self.ctx, WORKFLOW, text))
        self.ctx.event["repository"]["full_name"] = "Synergie-ITCI/programme-management-platform"
        self.assertFalse(engine.fieldzilla_ios_release_details(self.ctx, "other.yml", text))


if __name__ == "__main__":
    unittest.main()
