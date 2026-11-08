"""Exercise the actual bootstrap shell with fake HTTP and real size/hash/tar checks."""

import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIGEST = "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
API = "https://api.github.com/repos/gitleaks/gitleaks/releases/assets/378332058"
DIRECT = "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz"


class BootstrapTransportTests(unittest.TestCase):
    def exercise(self, mode="ok", corrupt=False, truncate=False, version="8.30.1"):
        workflow = (ROOT / ".github/workflows/pr-qa.yml").read_text()
        body = workflow.split(
            "      - name: Install mandatory Gitleaks\n        run: |\n", 1
        )[1].split("      - name: Phase 1 static preflight", 1)[0]
        script = textwrap.dedent(body).strip() + "\n"
        self.assertIn(DIGEST, script)
        self.assertNotIn("--insecure", script)
        self.assertNotIn("Authorization:", script)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            commands = root / "commands"
            binary = root / "bin"
            commands.mkdir()
            binary.mkdir()
            archive = io.BytesIO()
            payload = b"#!/bin/sh\nprintf '8.30.1\\n'\n"
            with tarfile.open(fileobj=archive, mode="w:gz") as tar:
                info = tarfile.TarInfo("gitleaks")
                info.size = len(payload)
                info.mode = 0o755
                tar.addfile(info, io.BytesIO(payload))
            good = archive.getvalue()
            data = good[:-1] + bytes([good[-1] ^ 1]) if corrupt else good
            if truncate:
                data = data[:-1]
            (root / "payload").write_bytes(data)
            # Relocate only paths and public fixture digest/size, never the verification logic.
            script = script.replace(DIGEST, hashlib.sha256(good).hexdigest()).replace(
                "8230402", str(len(good))
            )
            script = script.replace("/tmp/", str(root) + "/").replace(
                "-C /tmp gitleaks", "-C " + str(root) + " gitleaks"
            )
            script = script.replace("/usr/local/bin/gitleaks", str(binary / "gitleaks"))
            checksum = shutil.which("sha256sum")
            gnu_checksum = (
                subprocess.run(
                    [checksum, "--version"], check=False, capture_output=True, text=True
                )
                if checksum
                else None
            )
            if (
                gnu_checksum is None
                or gnu_checksum.returncode != 0
                or "GNU" not in gnu_checksum.stdout
            ):
                script = script.replace(
                    "sha256sum --check --status", "shasum -a 256 --check --status"
                )
            curl = (
                f"#!{sys.executable}\n"
                + textwrap.dedent(r"""
                import json, os, sys
                from pathlib import Path
                args = sys.argv[1:]
                url = next(a for a in args if a.startswith('https://'))
                with open(os.environ['CURL_LOG'], 'a') as output:
                    output.write(json.dumps(args) + '\n')
                if os.environ['CURL_MODE'] == 'fail' or (os.environ['CURL_MODE'] == 'api_fails' and 'api.github.com' in url):
                    sys.exit(22)
                Path(args[args.index('-o') + 1]).write_bytes(Path(os.environ['PAYLOAD']).read_bytes())
                """).lstrip()
            )
            (commands / "curl").write_text(curl)
            (commands / "sudo").write_text(
                '#!/bin/sh\ntouch "$INSTALL_CALLED"\nexec "$@"\n'
            )
            real_tar = shutil.which("tar")
            (commands / "tar").write_text(
                '#!/bin/sh\ntouch "$TAR_CALLED"\nexec "' + real_tar + '" "$@"\n'
            )
            for file in commands.iterdir():
                file.chmod(0o755)
            env = {
                **os.environ,
                "PATH": str(commands)
                + os.pathsep
                + str(binary)
                + os.pathsep
                + os.environ["PATH"],
                "GITLEAKS_VERSION": version,
                "CURL_MODE": mode,
                "CURL_LOG": str(root / "curl.log"),
                "PAYLOAD": str(root / "payload"),
                "TAR_CALLED": str(root / "tar.called"),
                "INSTALL_CALLED": str(root / "install.called"),
            }
            result = subprocess.run(
                ["bash", "-c", script],
                check=False,
                env=env,
                text=True,
                capture_output=True,
                timeout=20,
            )
            calls = (
                [
                    json.loads(line)
                    for line in (root / "curl.log").read_text().splitlines()
                ]
                if (root / "curl.log").exists()
                else []
            )
            return (
                result,
                calls,
                (root / "tar.called").exists(),
                (root / "install.called").exists(),
            )

    def test_api_bytes_verified_before_install(self):
        result, calls, tar, install = self.exercise()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "8.30.1")
        self.assertTrue(tar and install)
        self.assertEqual(len(calls), 1)
        self.assertIn(API, calls[0])
        for flag in ["--retry", "--connect-timeout", "--max-time", "--max-filesize"]:
            self.assertIn(flag, calls[0])

    def test_api_failure_uses_same_official_archive_route(self):
        result, calls, tar, install = self.exercise(mode="api_fails")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            [next(a for a in call if a.startswith("https://")) for call in calls],
            [API, DIRECT],
        )
        self.assertTrue(tar and install)

    def test_both_routes_unavailable_never_install(self):
        result, calls, tar, install = self.exercise(mode="fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 2)
        self.assertFalse(tar or install)

    def test_same_size_tamper_fails_without_fallback_or_extract(self):
        result, calls, tar, install = self.exercise(corrupt=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(calls), 1)
        self.assertFalse(tar or install)

    def test_wrong_size_never_extracts(self):
        result, _, tar, install = self.exercise(truncate=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(tar or install)

    def test_version_change_requires_new_reviewed_pin(self):
        result, calls, tar, install = self.exercise(version="8.30.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(calls or tar or install)


if __name__ == "__main__":
    unittest.main()
