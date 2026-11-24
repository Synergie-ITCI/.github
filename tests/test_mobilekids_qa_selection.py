"""The MobileKids consumer resolves only to the protected rc404 release."""

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pr-qa"))
from release_pin import resolve_consumer_release


class MobileKidsQaSelectionTests(unittest.TestCase):
    def test_exact_consumer_selection(self):
        manifest = json.loads((ROOT / "policy/framework-releases.json").read_text())
        with patch("release_pin.verify_bound_release") as verify:
            release, entry = resolve_consumer_release(
                manifest, "Synergie-ITCI/mobilekids.synergieinsights.in"
            )
        self.assertEqual(release, "pr-qa-v1-rc404")
        self.assertEqual(entry, {"commit": "48e74d0f6e9d82b7cd04e1063b42bbd84c70f118"})
        verify.assert_called_once()
        self.assertEqual(verify.call_args.args[:2], (release, entry["commit"]))


if __name__ == "__main__":
    unittest.main()
