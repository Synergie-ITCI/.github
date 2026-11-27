"""LMS resolves to the protected release containing PR #97's exact scope."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from release_pin import resolve_consumer_release


class LmsQaSelectionTests(unittest.TestCase):
    def test_exact_consumer_selection(self):
        manifest = json.loads((ROOT / "policy/framework-releases.json").read_text())
        with patch("release_pin.verify_bound_release") as verify:
            release, entry = resolve_consumer_release(manifest, "Synergie-ITCI/synergielms.com")
        self.assertEqual(release, "pr-qa-v1-rc428")
        self.assertEqual(entry, {"commit": "ab27e209ce8494b71ab64ef734fae65c0dd81e05"})
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[:2], (release, entry["commit"]))


if __name__ == "__main__":
    unittest.main()
