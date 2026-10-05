import importlib.util
import sys
import unittest
from pathlib import Path


REGRESSION_MODULE = Path(__file__).with_name("test_pr_qa_regressions.py")
spec = importlib.util.spec_from_file_location("pr_qa_regressions_for_custom_document", REGRESSION_MODULE)
assert spec and spec.loader
regressions = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = regressions
spec.loader.exec_module(regressions)


class PrQaCustomCertifierDocumentTests(unittest.TestCase):
    def setUp(self):
        self.fixture = regressions.PrQaRegressionTests(methodName="runTest")
        self.fixture.setUp()

    def tearDown(self):
        self.fixture.tearDown()

    @staticmethod
    def add_custom_document(workflow: str) -> str:
        marker = '          runtime-version: "8.2"\n'
        return workflow.replace(
            marker,
            marker + "          ssm-document-name: Synergie-Example-Production-Certify\n",
            1,
        )

    def run_gate(self, release: str):
        repo, base = self.fixture.init_repo("custom-document-" + release.replace(".", "-"))
        workflow = self.fixture.controlled_gate_d_workflow(runtime_release=release)
        self.fixture.write(
            repo / ".github" / "workflows" / "production-deploy.yml",
            self.add_custom_document(workflow),
        )
        self.fixture.commit(repo, "ci: add restricted custom document gate d")
        return self.fixture.run_engine_with_artifacts(repo, base, static_only=True)

    def test_v1_10_custom_document_gate_is_approved(self):
        code, report, report_json, _ = self.run_gate("runtime-certifier-action-v1.10")
        self.assertEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "WARNING")
        self.assertIn("CONTROLLED_PRODUCTION_GATE_D", report)

    def test_unapproved_custom_document_release_is_rejected(self):
        code, report, report_json, _ = self.run_gate("runtime-certifier-action-v1.11")
        self.assertNotEqual(code, 0, report)
        self.assertEqual(report_json["summary"]["gate_statuses"]["Deployment Risk"], "FAIL")


if __name__ == "__main__":
    unittest.main()
