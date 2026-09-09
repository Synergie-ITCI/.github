"""Opt-in host contract tests. All remote commands and HTTP requests are local fakes."""
import contextlib
import copy
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_runtime_certifier import config, mod


def profile():
    return {
        "schema_version": 1,
        "instance_id": "mi-0123456789abcdef0",
        "region": "ap-south-1",
        "target_hostname": "target.example.com",
        "sites": [{"label": "public-site", "hostname": "public.example.com",
                   "https_required": True, "accepted_status": 200,
                   "marker": "<title>Public application</title>"}],
    }


def host_config(**changes):
    values = {"host_profile": "approved", "instance_id": profile()["instance_id"],
              "validation_url": "https://target.example.com/"}
    values.update(changes)
    return config(**values)


class ProfileValidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patcher = mock.patch.object(mod, "HOST_PROFILES", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)

    def load(self, data=None, **changes):
        (self.root / "approved.json").write_text(json.dumps(profile() if data is None else data))
        return mod.load_host_profile(host_config(**changes))

    def test_approved_profile_and_empty_default(self):
        self.assertEqual(self.load(), profile())
        self.assertEqual(config().host_profile, "")

    def test_unknown_path_and_symlink_rejected(self):
        for name in ("unknown", "../approved", "/tmp/approved", "bad\nprofile", "https://example.com"):
            with self.subTest(name=name), self.assertRaises(mod.HostCertificationError):
                self.load(host_profile=name)
        (self.root / "alias.json").symlink_to(self.root / "approved.json")
        with self.assertRaises(mod.HostCertificationError):
            self.load(host_profile="alias")

    def test_instance_region_and_unapproved_target_rejected(self):
        for change in ({"instance_id": "mi-1123456789abcdef0"}, {"region": "eu-west-1"},
                       {"validation_url": "https://unapproved.example.com/"}):
            with self.subTest(change=change), self.assertRaises(mod.HostCertificationError):
                self.load(**change)

    def test_malformed_and_protected_profile_fields(self):
        mutations = [
            lambda p: p.update(extra="database configuration"),
            lambda p: p.update(schema_version=True),
            lambda p: p.update(sites=[]),
            lambda p: p.update(sites=p["sites"] * 9),
            lambda p: p["sites"][0].update(https_required=False),
            lambda p: p["sites"][0].update(accepted_status=302),
            lambda p: p["sites"][0].update(accepted_status=True),
            lambda p: p["sites"][0].update(label="unsafe\nlabel"),
            lambda p: p["sites"][0].update(hostname="127.0.0.1"),
            lambda p: p["sites"][0].update(hostname="admin.internal"),
            lambda p: p["sites"][0].update(hostname="*.example.com"),
            lambda p: p["sites"][0].update(hostname="https://public.example.com/"),
            lambda p: p["sites"][0].update(marker=""),
            lambda p: p["sites"][0].update(marker="a\nb"),
            lambda p: p["sites"][0].update(marker="Authorization: sensitive"),
            lambda p: p["sites"][0].update(marker="https://private.example.com/"),
            lambda p: p["sites"][0].update(marker="a" * 201),
            lambda p: p["sites"][0].update(password="forbidden"),
            lambda p: p["sites"].append(copy.deepcopy(p["sites"][0])),
        ]
        for mutate in mutations:
            data = profile()
            mutate(data)
            with self.subTest(data=data), self.assertRaises(mod.HostCertificationError):
                self.load(data)

    def test_target_cannot_be_a_cohost(self):
        data = profile()
        data["sites"][0]["hostname"] = data["target_hostname"]
        with self.assertRaisesRegex(mod.HostCertificationError, "TARGET_INCLUDED"):
            self.load(data)

    def test_duplicate_json_keys_rejected(self):
        (self.root / "approved.json").write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(mod.HostCertificationError):
            mod.load_host_profile(host_config())

    def test_multiple_callers_use_separate_centrally_bound_profiles(self):
        for target in ("first.example.com", "second.example.com"):
            data = profile()
            data["target_hostname"] = target
            self.assertEqual(self.load(data, validation_url="https://" + target), data)


class HostShellTests(unittest.TestCase):
    def run_probe(self, responses, sites=None, vhost=None, apache_rc=0):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            apache = root / "apache"
            apache.mkdir()
            data = profile()
            if sites:
                data["sites"] = sites
            for index, site in enumerate(data["sites"]):
                (apache / f"site-{index}.conf").write_text(vhost if vhost is not None else
                    '<VirtualHost *:443>\nServerName ' + site["hostname"] + '\nSSLEngine on\n</VirtualHost>\n')
            (root / "responses").write_text(json.dumps(responses))
            (root / "curl").write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
r=Path(os.environ['PROBE_FIXTURE'])
n=int((r/'count').read_text()) if (r/'count').exists() else 0
(r/'count').write_text(str(n+1))
responses=json.loads((r/'responses').read_text())
item=responses[min(n,len(responses)-1)]
args=sys.argv[1:]
assert args[0]=='-q'
assert '--insecure' not in args and '-k' not in args and '-L' not in args
assert args[args.index('--proto')+1]=='=https'
assert args[args.index('--max-time')+1]=='15'
assert args[args.index('--connect-timeout')+1]=='5'
Path(args[args.index('--output')+1]).write_text(item.get('body',''))
print('Authorization: Bearer synthetic-sensitive-value Cookie: private-session',file=sys.stderr)
print(item.get('status','000'),end='')
sys.exit(item.get('rc',0))
''')
            (root / "apache2ctl").write_text(f"#!/bin/sh\nexit {apache_rc}\n")
            (root / "sleep").write_text('#!/bin/sh\nprintf "%s\\n" "$1" >> "$PROBE_FIXTURE/backoff"\n')
            for name in ("curl", "apache2ctl", "sleep"):
                (root / name).chmod(0o700)
            script = mod.build_host_script(data).replace("/etc/apache2/sites-enabled", str(apache))
            env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"],
                       PROBE_FIXTURE=str(root), TMPDIR=str(root))
            result = subprocess.run(["bash", "-c", script], env=env, capture_output=True, text=True, timeout=10)
            count = int((root / "count").read_text()) if (root / "count").exists() else 0
            delays = (root / "backoff").read_text().splitlines() if (root / "backoff").exists() else []
            self.assertFalse(list(root.glob("tmp.*")), "private response file leaked")
            self.assertEqual(result.stderr, "")
            for protected in ("synthetic-sensitive", "Authorization", "Cookie", "private.example", "public.example", "Public application"):
                self.assertNotIn(protected, result.stdout)
            return result, count, delays

    def success(self):
        return {"status": "200", "body": profile()["sites"][0]["marker"]}

    def test_transient_categories_recover(self):
        for rc in (5, 6, 7, 28, 35, 52, 55, 56):
            with self.subTest(rc=rc):
                result, count, delays = self.run_probe([{"rc": rc}, self.success()])
                self.assertEqual(result.returncode, 0, result.stdout)
                self.assertIn("HOST_CERTIFICATION=PASS", result.stdout)
                self.assertEqual((count, delays), (2, ["1"]))

    def test_persistent_failures_exhaust_exactly_three_attempts(self):
        for rc, category in ((6, "DNS"), (7, "CONNECTION"), (28, "TIMEOUT"), (35, "TLS_TRANSPORT")):
            with self.subTest(rc=rc):
                result, count, delays = self.run_probe([{"rc": rc}])
                self.assertEqual(result.returncode, 42)
                self.assertEqual((count, delays), (3, ["1", "2"]))
                self.assertIn("FAILED_REASON=" + category + "_PERSISTENT", result.stdout)

    def test_security_http_content_fail_immediately(self):
        for response, reason in (({"rc": 60}, "TLS_SECURITY"), ({"rc": 90}, "TLS_SECURITY"),
                                 ({"status": "503"}, "HTTP_STATUS"),
                                 ({"status": "200", "body": "private.example synthetic-sensitive-value"}, "CONTENT_MARKER"),
                                 ({"rc": 63}, "CURL_OTHER")):
            with self.subTest(reason=reason):
                result, count, delays = self.run_probe([response])
                self.assertEqual((result.returncode, count, delays), (42, 1, []))
                self.assertIn("FAILED_SITE=public-site", result.stdout)
                self.assertIn("FAILED_REASON=" + reason, result.stdout)

    def test_apache_and_vhost_fail_before_http(self):
        result, count, _ = self.run_probe([self.success()], apache_rc=1)
        self.assertIn("FAILED_REASON=APACHE_CONFIG", result.stdout)
        self.assertEqual(count, 0)
        split = '<VirtualHost *:80>\nServerName public.example.com\n</VirtualHost>\n<VirtualHost *:443>\nServerName another.example.com\nSSLEngine on\n</VirtualHost>'
        result, count, _ = self.run_probe([self.success()], vhost=split)
        self.assertIn("FAILED_REASON=VHOST_NOT_ENABLED", result.stdout)
        self.assertEqual(count, 0)

    def test_all_sites_must_pass(self):
        second = dict(profile()["sites"][0], label="second-site", hostname="second.example.com")
        result, count, _ = self.run_probe([self.success(), {"status": "503"}], sites=profile()["sites"] + [second])
        self.assertEqual(count, 2)
        self.assertIn("FAILED_SITE=second-site", result.stdout)
        self.assertNotIn("HOST_CERTIFICATION=PASS", result.stdout)


class HostContractTests(unittest.TestCase):
    def evidence(self):
        return {"InstanceId": profile()["instance_id"], "CommandId": "command-id", "Status": "Success", "ResponseCode": 0,
                "StandardOutputContent": "DEPLOY_STATE=READY_FROM_ROLLBACK\nHOST_SITE label=public-site status=200 marker=PASS curl=NONE attempt=1\nHOST_CERTIFICATION=PASS\n"}

    def test_exact_pass_evidence(self):
        self.assertEqual(mod.verify_host_evidence(self.evidence(), profile(), "command-id"), "READY_FROM_ROLLBACK")

    def test_retry_evidence_must_be_ordered_and_only_transient(self):
        data = self.evidence()
        data["StandardOutputContent"] = data["StandardOutputContent"].replace("attempt=1", "attempt=2")
        with self.assertRaises(mod.HostCertificationError):
            mod.verify_host_evidence(data, profile(), "command-id")
        data["StandardOutputContent"] = "HOST_SITE label=public-site status=000 marker=NOT_CHECKED curl=DNS attempt=1\n" + data["StandardOutputContent"]
        self.assertEqual(mod.verify_host_evidence(data, profile(), "command-id"), "READY_FROM_ROLLBACK")
        data["StandardOutputContent"] = data["StandardOutputContent"].replace("curl=DNS", "curl=TLS_SECURITY")
        with self.assertRaises(mod.HostCertificationError):
            mod.verify_host_evidence(data, profile(), "command-id")

    def test_real_central_profile_is_valid_and_instance_bound(self):
        approved = mod.load_host_profile(config(
            host_profile="synergieinsights-jkcement", instance_id="mi-04a256fa549e372a8",
            validation_url="https://jkcementypsscholarship.synergieinsights.in/"))
        self.assertEqual(len(approved["sites"]), 1)
        self.assertEqual(approved["sites"][0]["accepted_status"], 200)

    def test_wrong_missing_or_conflicting_evidence_rejected(self):
        for change in ({"InstanceId": "wrong"}, {"CommandId": "replayed"}, {"ResponseCode": -1},
                       {"Status": "InProgress"}, {"StandardOutputContent": "HOST_CERTIFICATION=PASS"}):
            with self.subTest(change=change), self.assertRaises(mod.HostCertificationError):
                mod.verify_host_evidence(dict(self.evidence(), **change), profile(), "command-id")
        for extra in ("HOST_CERTIFICATION=PASS\n", "DEPLOY_STATE=ALREADY_DEPLOYED\n", "FAILED_SITE=public-site\n"):
            data = self.evidence()
            data["StandardOutputContent"] += extra
            with self.assertRaises(mod.HostCertificationError):
                mod.verify_host_evidence(data, profile(), "command-id")

    def test_untrusted_failure_values_never_escape(self):
        data = self.evidence()
        data["StandardOutputContent"] = "HOST_CERTIFICATION=FAIL\nFAILED_SITE=private.example\nFAILED_REASON=secret-value\n"
        with self.assertRaisesRegex(mod.HostCertificationError, "INVALID_EVIDENCE"):
            mod.verify_host_evidence(data, profile(), "command-id")

    def test_optional_action_contract(self):
        action = (mod.HOST_PROFILES.parent / "action.yml").read_text()
        for name in ("host-profile", "host-certification", "failed-site", "failed-reason", "deploy-state", "deployment-required"):
            self.assertIn(name + ":", action)
        self.assertIn("RUNTIME_CERTIFIER_HOST_PROFILE: ${{ inputs.host-profile }}", action)

    def test_all_existing_adapters_and_legacy_outputs_without_profile(self):
        for runtime, version, web in (("php-fpm", "8.3", "apache"), ("static-vite-apache", "vite", "apache"),
                                      ("django-gunicorn-nginx", "django-5.2", "nginx")):
            for state in ("READY_FROM_ROLLBACK", "ALREADY_DEPLOYED"):
                result = {"Status": "Success", "StandardOutputContent": "DEPLOY_STATE=" + state + "\nlegacy diagnostic\n"}
                replies = [subprocess.CompletedProcess([], 0, "command-id"), subprocess.CompletedProcess([], 0, ""),
                           subprocess.CompletedProcess([], 0, json.dumps(result))]
                with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"GITHUB_OUTPUT": directory + "/out"}), \
                     mock.patch.object(mod, "run_command", side_effect=replies), mock.patch.object(mod, "load_host_profile") as loader, \
                     contextlib.redirect_stdout(io.StringIO()) as output:
                    self.assertEqual(mod.certify(config(runtime_kind=runtime, runtime_version=version, web_server=web)), 0)
                    loader.assert_not_called()
                    self.assertEqual(output.getvalue(), result["StandardOutputContent"])
                    required = "false" if state == "ALREADY_DEPLOYED" else "true"
                    self.assertEqual(Path(directory + "/out").read_text(), f"deploy_state={state}\ndeployment_required={required}\n")

    def test_opted_in_api_output_is_allowlisted(self):
        data = self.evidence()
        data["StandardOutputContent"] += "Authorization: private-value\n"
        data["StandardErrorContent"] = "Cookie: private-value"
        replies = [subprocess.CompletedProcess([], 0, "command-id"), subprocess.CompletedProcess([], 0, ""),
                   subprocess.CompletedProcess([], 0, json.dumps(data))]
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {"GITHUB_OUTPUT": directory + "/out"}), \
             mock.patch.object(mod, "load_host_profile", return_value=profile()), \
             mock.patch.object(mod, "run_command", side_effect=replies), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mod.certify(host_config()), 0)
            self.assertEqual(output.getvalue(), "host-certification=PASS\nfailed-site=\nfailed-reason=\n")
            self.assertIn("deploy_state=READY_FROM_ROLLBACK", Path(directory + "/out").read_text())

    def test_main_failure_emits_only_safe_outputs(self):
        with mock.patch.object(mod, "parse_args", return_value=host_config()), \
             mock.patch.object(mod, "certify", side_effect=mod.HostCertificationError("CONTENT_MARKER", "public-site")), \
             mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mod.main(), 1)
            self.assertEqual(output.getvalue(), "host-certification=FAIL\nfailed-site=public-site\nfailed-reason=CONTENT_MARKER\n")

    def test_remote_wrapper_suppresses_legacy_output_and_stops_on_runtime_failure(self):
        for fail in (False, True):
            legacy = "printf 'DEPLOY_STATE=READY_FROM_ROLLBACK\\nAuthorization: synthetic-private-value\\n'\nprintf 'Cookie: synthetic-private-value' >&2\n"
            if fail:
                legacy += "exit 41\n"
            remote_result = None

            def aws(args, **kwargs):
                nonlocal remote_result
                if "send-command" in args:
                    payload_path = args[args.index("--parameters") + 1].removeprefix("file://")
                    command = json.loads(Path(payload_path).read_text())["commands"][0]
                    remote_result = subprocess.run(["bash", "-c", command], capture_output=True, text=True, timeout=10)
                    return subprocess.CompletedProcess(args, 0, "command-id")
                if "wait" in args:
                    return subprocess.CompletedProcess(args, 0, "")
                data = dict(self.evidence(), StandardOutputContent=remote_result.stdout,
                            StandardErrorContent=remote_result.stderr, ResponseCode=remote_result.returncode,
                            Status="Failed" if remote_result.returncode else "Success")
                return subprocess.CompletedProcess(args, 0, json.dumps(data))

            probe = "printf 'HOST_SITE label=public-site status=200 marker=PASS curl=NONE attempt=1\\nHOST_CERTIFICATION=PASS\\n'"
            with mock.patch.object(mod, "load_host_profile", return_value=profile()), \
                 mock.patch.object(mod, "build_remote_script", return_value=legacy), \
                 mock.patch.object(mod, "build_host_script", return_value=probe), \
                 mock.patch.object(mod, "run_command", side_effect=aws), \
                 mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), contextlib.redirect_stdout(io.StringIO()):
                if fail:
                    with self.assertRaisesRegex(mod.HostCertificationError, "RUNTIME_FAILED"):
                        mod.certify(host_config())
                    self.assertNotIn("HOST_SITE", remote_result.stdout)
                else:
                    self.assertEqual(mod.certify(host_config()), 0)
                self.assertNotIn("synthetic-private-value", remote_result.stdout + remote_result.stderr)

    def test_unknown_profile_never_dispatches_ssm(self):
        with mock.patch.object(mod, "parse_args", return_value=host_config(host_profile="unapproved")), \
             mock.patch.object(mod, "run_command") as aws, mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            self.assertEqual(mod.main(), 1)
            aws.assert_not_called()
            self.assertIn("failed-reason=UNKNOWN_PROFILE", output.getvalue())

    def test_aws_exception_is_not_printed(self):
        error = subprocess.CalledProcessError(1, ["aws", "private-value"], stderr="Authorization: sensitive")
        with mock.patch.object(mod, "parse_args", return_value=host_config()), \
             mock.patch.object(mod, "load_host_profile", return_value=profile()), \
             mock.patch.object(mod, "run_command", side_effect=error), \
             mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(mod.main(), 1)
            self.assertEqual(err.getvalue(), "")
            self.assertEqual(out.getvalue(), "host-certification=FAIL\nfailed-site=host-profile\nfailed-reason=SSM_FAILED\n")

    def test_pending_invocation_is_polled_without_resending(self):
        replies = [subprocess.CompletedProcess([], 0, "command-id"), subprocess.CompletedProcess([], 0, ""),
                   subprocess.CompletedProcess([], 0, json.dumps({"Status": "InProgress"})),
                   subprocess.CompletedProcess([], 0, json.dumps(self.evidence()))]
        with mock.patch.object(mod, "load_host_profile", return_value=profile()), \
             mock.patch.object(mod, "run_command", side_effect=replies) as aws, \
             mock.patch.object(mod.time, "sleep") as sleep, \
             mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(mod.certify(host_config()), 0)
            self.assertEqual(sum("send-command" in call.args[0] for call in aws.call_args_list), 1)
            sleep.assert_called_once_with(2)

    def test_invalid_governance_does_not_escape_before_config_construction(self):
        args = ["runtime_certifier.py", "--host-profile", "approved", "--instance-id", profile()["instance_id"],
                "--app-path", "/application", "--validation-url", "https://target.example.com/",
                "--deploy-ref", "a" * 40, "--rollback-ref", "b" * 40, "--runtime-version", "8.3"]
        with mock.patch.object(mod.sys, "argv", args), \
             mock.patch.object(mod, "load_persistent_data_declarations", side_effect=mod.CertifierError("private-value")), \
             mock.patch.dict(os.environ, {"GITHUB_OUTPUT": ""}), \
             contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(mod.main(), 1)
            self.assertEqual(err.getvalue(), "")
            self.assertIn("failed-reason=RUNTIME_FAILED", out.getvalue())
            self.assertNotIn("private-value", out.getvalue())


if __name__ == "__main__":
    unittest.main()
