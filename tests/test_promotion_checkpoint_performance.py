"""Fail-closed regression cases for the batched promotion tree lookup."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pr-qa"))
from pr_qa import promotion_direct_tree_equivalent_checkpoint


class PromotionCheckpointPerformanceTests(unittest.TestCase):
    def test_missing_base_and_shallow_history_have_no_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True, capture_output=True)
            for number in (1, 2):
                (source / "file.txt").write_text(str(number))
                subprocess.run(["git", "add", "."], cwd=source, check=True, capture_output=True)
                subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.com",
                                "commit", "-qm", f"commit {number}"], cwd=source, check=True, capture_output=True)
            self.assertEqual(promotion_direct_tree_equivalent_checkpoint(source, "0" * 40), "")
            shallow = root / "shallow"
            subprocess.run(["git", "clone", "-q", "--depth", "1", source.as_uri(), str(shallow)],
                           check=True, capture_output=True)
            shallow_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=shallow, check=True,
                                          capture_output=True, text=True).stdout.strip()
            self.assertEqual(promotion_direct_tree_equivalent_checkpoint(shallow, shallow_head), "")


if __name__ == "__main__":
    unittest.main()
