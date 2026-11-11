import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "actions/fieldzilla-production-hosting/verify_bootstrap.py"
spec = importlib.util.spec_from_file_location("verify_rehearsal_bootstrap", SCRIPT)
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


class RehearsalBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.source = root / "source"
        self.live = root / "live"
        self.source.mkdir()
        self.live.mkdir()
        self.ref = bootstrap.REVIEWED_REF.replace("rc238", "rc242")
        self.trust = {
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Condition": {"StringEquals": {
                    "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
                    bootstrap.CLAIM: bootstrap.REVIEWED_REF,
                }},
            }],
        }
        self.sink = {"Statement": [{"Sid": "OnlyRehearsalAttachmentLogs"}]}
        self.write("source", "provisioner-trust.json", self.trust)
        self.write("source", "log-sink-policy.json", self.sink)
        live = copy.deepcopy(self.trust)
        live["Statement"][0]["Condition"]["StringEquals"][bootstrap.CLAIM] = self.ref
        self.write("live", "rehearsal-trust.json", live)
        self.write("live", "rehearsal-log-sink.json", self.sink)

    def write(self, side, name, value):
        path = self.source if side == "source" else self.live
        (path / name).write_text(json.dumps(value))

    def test_exact_new_executor_ref_and_unchanged_sink_pass(self):
        bootstrap.verify(self.source, self.live, self.ref)

    def test_other_trust_claim_or_sink_change_fails(self):
        changed = copy.deepcopy(self.trust)
        values = changed["Statement"][0]["Condition"]["StringEquals"]
        values[bootstrap.CLAIM] = self.ref
        values["token.actions.githubusercontent.com:aud"] = "other"
        self.write("live", "rehearsal-trust.json", changed)
        with self.assertRaisesRegex(ValueError, "provisioner-trust"):
            bootstrap.verify(self.source, self.live, self.ref)

        values["token.actions.githubusercontent.com:aud"] = "sts.amazonaws.com"
        self.write("live", "rehearsal-trust.json", changed)
        self.write("live", "rehearsal-log-sink.json", {"Statement": []})
        with self.assertRaisesRegex(ValueError, "log-sink-policy"):
            bootstrap.verify(self.source, self.live, self.ref)

    def test_unreviewed_source_or_unpinned_executor_fails(self):
        changed = copy.deepcopy(self.trust)
        changed["Statement"][0]["Condition"]["StringEquals"][bootstrap.CLAIM] = self.ref
        self.write("source", "provisioner-trust.json", changed)
        with self.assertRaisesRegex(ValueError, "Reviewed rehearsal trust release"):
            bootstrap.verify(self.source, self.live, self.ref)
        self.write("source", "provisioner-trust.json", self.trust)
        with self.assertRaisesRegex(ValueError, "immutable release"):
            bootstrap.verify(self.source, self.live, self.ref.replace("@refs/tags/", "@refs/heads/"))


if __name__ == "__main__":
    unittest.main()
