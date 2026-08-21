#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import fnmatch
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PR_QA_TEMPLATE = ROOT / "examples" / "caller-workflow.yml"
PR_TEMPLATE = ROOT / "examples" / "pull_request_template.md"
CENTRAL_REPO = "Synergie-ITCI/.github"
CENTRAL_POLICY_PATH = "policy/pr-qa-policy.json"
GENERIC_CALLER_CONTEXT = "pr-qa / Pull Request Quality Assurance"
PROFILE_CHOICES = ("auto", "application", "framework", "infrastructure", "library", "documentation")
CRITICALITY_CHOICES = ("auto", "low", "medium", "high", "critical")
VERIFY_STATUSES = {
    "PASS",
    "BLOCKED_ON_ONBOARDING_FILE",
    "BLOCKED_ON_EXISTING_LEGACY_FINDING",
    "WAITING_FOR_HUMAN_APPROVAL",
    "BLOCKED_UNKNOWN",
}


@dataclass
class Finding:
    key: str
    status: str
    detail: str


class CmdError(RuntimeError):
    pass


def run(cmd: list[str], *, cwd: Path | None = None, check: bool = True, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.setdefault("GH_PAGER", "cat")
    env.setdefault("PAGER", "cat")
    env.setdefault("AWS_PAGER", "")
    proc = subprocess.run(
        cmd,
        cwd=str(cwd) if cwd else None,
        text=True,
        input=input_text,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )
    if check and proc.returncode != 0:
        raise CmdError(f"command failed ({proc.returncode}): {' '.join(cmd)}\n{proc.stderr.strip()}")
    return proc


def gh_json(args: list[str]) -> Any:
    proc = run(["gh", *args])
    text = proc.stdout.strip()
    return json.loads(text) if text else None


def require_tools() -> None:
    missing = [name for name in ("git", "gh") if shutil.which(name) is None]
    if missing:
        raise SystemExit("Missing required CLI tool(s): " + ", ".join(missing))
    run(["gh", "auth", "status"])


def validate_repo_slug(repo: str) -> None:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise SystemExit("Repository must be in OWNER/NAME form.")


def clone_repo(repo: str) -> tempfile.TemporaryDirectory[str]:
    tmp = tempfile.TemporaryDirectory(prefix="synergie-governance-")
    run(["gh", "repo", "clone", repo, tmp.name, "--", "--filter=blob:none"])
    return tmp


def branch_exists(repo_dir: Path, branch: str) -> bool:
    proc = run(["git", "ls-remote", "--exit-code", "--heads", "origin", branch], cwd=repo_dir, check=False)
    return proc.returncode == 0


def list_remote_branches(repo_dir: Path) -> set[str]:
    proc = run(["git", "ls-remote", "--heads", "origin"], cwd=repo_dir)
    branches: set[str] = set()
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1].startswith("refs/heads/"):
            branches.add(parts[1].removeprefix("refs/heads/"))
    return branches


def classify_topology(branches: set[str], default_branch: str) -> str:
    has_development = "development" in branches
    has_staging = "staging" in branches
    has_main = "main" in branches
    has_master = "master" in branches
    if {default_branch} == branches or branches <= {default_branch}:
        return "TRUNK_ONLY"
    if has_development and has_staging and has_main:
        return "STANDARD_SYNERGIE_FLOW" if default_branch == "main" else "STANDARD_THREE_STAGE"
    if has_development and has_staging and not has_main:
        return "STANDARD_THREE_STAGE"
    if has_staging and has_main and not has_development:
        return "TWO_STAGE"
    if has_development and has_main and not has_staging:
        return "TWO_STAGE"
    if has_master and (has_development or has_staging):
        return "LEGACY_MAIN_NAMING"
    release_like = [b for b in branches if is_release_environment_branch(b)]
    if release_like:
        return "CUSTOM_RELEASE_TOPOLOGY"
    return "TOPOLOGY_REVIEW_REQUIRED"


def branch_for_bootstrap(branches: set[str], default_branch: str) -> str:
    for candidate in ("development", "develop", "staging", default_branch, "main", "master"):
        if candidate in branches:
            return candidate
    raise CmdError("No suitable existing branch found for onboarding bootstrap.")


def release_topology_branches(branches: set[str], default_branch: str) -> list[str]:
    preferred = ["development", "staging", "main", "master", default_branch]
    ordered: list[str] = []
    for branch in preferred:
        if branch in branches and branch not in ordered:
            ordered.append(branch)
    for branch in sorted(branches):
        if branch not in ordered and is_release_environment_branch(branch):
            ordered.append(branch)
    if not ordered and default_branch in branches:
        ordered.append(default_branch)
    return ordered


def is_release_environment_branch(branch: str) -> bool:
    name = branch.lower()
    if name in {"production", "prod", "uat", "qa"}:
        return True
    return name.startswith(("release/", "release-", "production/", "prod/", "uat/", "qa/"))


def has_gate_c_path(branches: set[str]) -> bool:
    return "staging" in branches and "main" in branches


def checkout_branch(repo_dir: Path, branch: str) -> None:
    run(["git", "fetch", "origin", "--prune"], cwd=repo_dir)
    run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=repo_dir)


def ensure_branch_clean(repo_dir: Path) -> None:
    if run(["git", "status", "--porcelain"], cwd=repo_dir).stdout.strip():
        raise CmdError("Target clone unexpectedly has local changes before onboarding.")


def repo_metadata(repo: str) -> dict[str, Any]:
    data = gh_json(["repo", "view", repo, "--json", "defaultBranchRef,nameWithOwner"])
    return data if isinstance(data, dict) else {}


def central_owner_login() -> str:
    data = gh_json(["api", f"repos/{CENTRAL_REPO}/contents/{CENTRAL_POLICY_PATH}?ref=main"])
    if not isinstance(data, dict) or not data.get("content"):
        raise CmdError("Unable to read central review-policy configuration.")
    try:
        decoded = base64.b64decode(str(data["content"]).replace("\n", "")).decode("utf-8")
        policy = json.loads(decoded)
        return str(policy["governance"]["review_policy"]["owner_review_exception"]["github_login"])
    except Exception as exc:  # fail closed on malformed central policy
        raise CmdError(f"Unable to derive executive release authority from central policy: {exc}") from exc


def workflow_files(repo_dir: Path, ref: str) -> dict[str, str]:
    files: dict[str, str] = {}
    proc = run(["git", "ls-tree", "-r", "--name-only", ref, ".github/workflows"], cwd=repo_dir, check=False)
    if proc.returncode != 0:
        return files
    for rel in proc.stdout.splitlines():
        if not rel.endswith((".yml", ".yaml")):
            continue
        blob = run(["git", "show", f"{ref}:{rel}"], cwd=repo_dir, check=False)
        if blob.returncode == 0:
            files[rel] = blob.stdout
    return files


def repository_files(repo_dir: Path, ref: str) -> list[str]:
    proc = run(["git", "ls-tree", "-r", "--name-only", ref], cwd=repo_dir, check=False)
    if proc.returncode != 0:
        return []
    return [line for line in proc.stdout.splitlines() if line]


def detect_technologies(paths: list[str]) -> list[str]:
    technologies: set[str] = set()
    names = set(paths)
    lower_paths = [p.lower() for p in paths]
    if "composer.json" in names or "artisan" in names or any(p.endswith(".php") for p in lower_paths):
        technologies.add("PHP/Laravel" if "artisan" in names else "PHP")
    if "package.json" in names or any(p.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs")) for p in lower_paths):
        technologies.add("Node/JS/TS")
    if any(p in names for p in ("pyproject.toml", "requirements.txt", "setup.py")) or any(p.endswith(".py") for p in lower_paths):
        technologies.add("Python")
    if "go.mod" in names or any(p.endswith(".go") for p in lower_paths):
        technologies.add("Go")
    if any(p.endswith(".gradle") or p.endswith(".gradle.kts") for p in lower_paths) or "build.gradle" in names:
        technologies.add("Java/Gradle")
    if any(p.endswith((".csproj", ".sln", ".fsproj", ".vbproj")) for p in lower_paths):
        technologies.add(".NET")
    if any(p.endswith(".tf") or p.endswith(".tfvars") for p in lower_paths):
        technologies.add("Terraform")
    if any(Path(p).name.lower().startswith("dockerfile") for p in paths) or any("docker-compose" in p for p in lower_paths):
        technologies.add("Docker")
    if any(p.endswith((".k8s.yml", ".k8s.yaml")) or "/k8s/" in p or "/kubernetes/" in p for p in lower_paths):
        technologies.add("Kubernetes")
    if any(p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")) for p in paths):
        technologies.add("GitHub Actions")
    if any("/migrations/" in p or re.search(r"database/migrations/.+\.(php|sql)$", p, re.IGNORECASE) for p in paths):
        technologies.add("migrations")
    return sorted(technologies)


def deployment_sensitive_source(paths: list[str]) -> bool:
    for path in paths:
        lower = path.lower()
        name = Path(path).name.lower()
        if path.startswith(".github/workflows/") and re.search(r"deploy|release|prod(?:uction)?", name):
            return True
        if re.search(r"(^|/)(deploy|deployment|release|production|prod)(/|[-_.])", lower):
            return True
        if lower.startswith(("k8s/", "kubernetes/", "terraform/", "infra/")):
            return True
        if name.startswith("dockerfile") or "docker-compose" in name:
            return True
    return False


def application_source(paths: list[str]) -> bool:
    names = set(paths)
    lower_paths = [p.lower() for p in paths]
    if "artisan" in names:
        return True
    if any(p.startswith(("app/", "routes/", "public/")) for p in lower_paths):
        return True
    if any(p in {"app.py", "main.py", "manage.py", "server.py"} or p.endswith(("/app.py", "/main.py", "/server.py")) for p in lower_paths):
        return True
    if any(p.startswith("cmd/") and p.endswith(".go") for p in lower_paths):
        return True
    return deployment_sensitive_source(paths)


def library_source(paths: list[str]) -> bool:
    names = set(paths)
    lower_paths = [p.lower() for p in paths]
    package_manifest = any(p in names for p in ("pyproject.toml", "setup.py", "setup.cfg", "go.mod", "package.json"))
    package_layout = any(p.startswith(("src/", "lib/", "pkg/")) for p in lower_paths)
    package_metadata = any(p.endswith((".gemspec", ".nuspec")) for p in lower_paths)
    return (package_manifest and package_layout) or package_metadata


def classify_profile(paths: list[str], technologies: list[str], explicit: str) -> str:
    if explicit != "auto":
        return explicit
    non_docs = [p for p in paths if not re.match(r"(^docs/|.*\.(md|markdown|txt)$)", p, re.IGNORECASE)]
    if not non_docs:
        return "documentation"
    if any(t in technologies for t in ("Terraform", "Kubernetes")) or any(p.startswith(("infra/", "terraform/", "k8s/", "kubernetes/")) for p in paths):
        return "infrastructure"
    if any(p.startswith(("pr-qa/", "policy/", "workflow-templates/")) for p in paths) and "GitHub Actions" in technologies:
        return "framework"
    if library_source(paths) and not application_source(paths):
        return "library"
    return "application"


def classify_criticality(profile: str, technologies: list[str], explicit: str, paths: list[str] | None = None) -> str:
    if explicit != "auto":
        return explicit
    paths = paths or []
    if profile == "documentation":
        return "low"
    if profile == "infrastructure":
        return "high"
    if profile == "application" and deployment_sensitive_source(paths):
        return "high"
    if profile == "application" and any(t in technologies for t in ("Docker", "Kubernetes", "Terraform")):
        return "high"
    return "medium"


def load_prqa_module() -> Any:
    module_path = ROOT / "pr-qa" / "pr_qa.py"
    sys.path.insert(0, str(ROOT / "pr-qa"))
    spec = importlib.util.spec_from_file_location("synergie_pr_qa_rc50", module_path)
    if not spec or not spec.loader:
        raise CmdError("Unable to load central PR-QA module for Gate D classification.")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def rc50_controlled_gate_d(path: str, text: str) -> bool:
    module = load_prqa_module()
    return bool(module.controlled_gate_d_workflow_details(path, text))


def has_branch_under_push(text: str, branch: str) -> bool:
    lower = text.lower()
    for match in re.finditer(r"(?m)^\s*push\s*:\s*$", lower):
        block = lower[match.end(): match.end() + 1200]
        if re.search(rf"(?m)^\s*-\s*['\"]?{re.escape(branch.lower())}['\"]?\s*$", block):
            return True
        if re.search(rf"branches\s*:\s*\[[^\]]*\b{re.escape(branch.lower())}\b", block):
            return True
    return False


def has_actor_restriction(text: str, owner_login: str) -> bool:
    # Conservative textual proof: both actor source and configured owner identity must appear in the workflow.
    return bool(re.search(r"GITHUB_ACTOR|github\.actor", text, re.IGNORECASE) and owner_login in text)


def classify_workflow(path: str, text: str, owner_login: str) -> dict[str, Any]:
    lower = text.lower()
    push_main = has_branch_under_push(text, "main") or has_branch_under_push(text, "master")
    push_staging = has_branch_under_push(text, "staging")
    prodish = bool(re.search(r"\bproduction\b|\bprod[_-]|/prod\b|environment\s*:\s*production", lower))
    prod_auto = push_main and prodish
    staging_only = push_staging and not push_main and not re.search(r"\bprod[_-]|environment\s*:\s*production", lower)
    return {
        "path": path,
        "push_main": push_main,
        "push_staging": push_staging,
        "production_markers": prodish,
        "production_auto_deploy": prod_auto,
        "staging_only": staging_only,
    }


def deployment_audit(repo_dir: Path, owner_login: str, branches: set[str], default_branch: str) -> tuple[list[Finding], list[dict[str, Any]]]:
    findings: list[Finding] = []
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for branch in release_topology_branches(branches, default_branch):
        for path, text in sorted(workflow_files(repo_dir, f"origin/{branch}").items()):
            key = (path, text)
            if key in seen:
                continue
            seen.add(key)
            row = classify_workflow(path, text, owner_login)
            row["gate_d_rc50"] = rc50_controlled_gate_d(path, text)
            row["observed_on"] = branch
            rows.append(row)
    if not rows:
        return [Finding("DEPLOYMENT_WORKFLOWS", "WARNING", "No workflows found on discovered release branches.")], rows

    auto = sorted({r["path"] for r in rows if r["production_auto_deploy"]})
    gates = sorted({r["path"] for r in rows if r["gate_d_rc50"]})
    staging = sorted({r["path"] for r in rows if r["staging_only"]})
    findings.append(Finding("PRODUCTION_AUTO_DEPLOY", "BLOCKED" if auto else "PASS", ", ".join(auto) if auto else "Absent on discovered release branches"))
    findings.append(Finding("GATE_D_IMPLEMENTATION", "PASS", "SHARED with current central PR-QA Deployment Risk classifier."))
    findings.append(Finding("GATE_D_SHAPE", "PASS" if gates else "WARNING", ", ".join(gates) if gates else "No workflow matches the bounded rc50 manual OIDC→SSM Gate D shape."))
    findings.append(Finding("STAGING_DEPLOY", "PASS" if staging else "WARNING", ", ".join(staging) if staging else "No staging-only deploy workflow recognized."))
    return findings, rows


def rulesets(repo: str) -> list[dict[str, Any]]:
    proc = run(["gh", "api", "--paginate", "--slurp", f"repos/{repo}/rulesets?includes_parents=true"], check=False)
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(data, list) and data and all(isinstance(page, list) for page in data):
        return [item for page in data for item in page]
    return data if isinstance(data, list) else []


def ruleset_detail(repo: str, item: dict[str, Any]) -> dict[str, Any] | None:
    rid = item.get("id")
    if not rid:
        return None
    source_type = str(item.get("source_type") or "Repository")
    owner = repo.split("/", 1)[0]
    endpoint = f"orgs/{owner}/rulesets/{rid}" if source_type.lower() == "organization" else f"repos/{repo}/rulesets/{rid}"
    proc = run(["gh", "api", endpoint], check=False)
    if proc.returncode != 0:
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def branch_pattern_matches(pattern: str, branch: str, default_branch: str) -> bool:
    if pattern == "~ALL":
        return True
    if pattern == "~DEFAULT_BRANCH":
        return branch == default_branch
    candidate = f"refs/heads/{branch}"
    if pattern.startswith("refs/heads/"):
        return fnmatch.fnmatch(candidate, pattern)
    return fnmatch.fnmatch(branch, pattern)


def ruleset_applies_to_branch(detail: dict[str, Any], branch: str, default_branch: str) -> bool:
    ref = ((detail.get("conditions") or {}).get("ref_name") or {})
    includes = list(ref.get("include") or ["~ALL"])
    excludes = list(ref.get("exclude") or [])
    included = any(branch_pattern_matches(str(p), branch, default_branch) for p in includes)
    excluded = any(branch_pattern_matches(str(p), branch, default_branch) for p in excludes)
    return included and not excluded


def required_check_contexts(detail: dict[str, Any]) -> list[str]:
    out: list[str] = []
    for rule in detail.get("rules", []) or []:
        if rule.get("type") != "required_status_checks":
            continue
        for check in ((rule.get("parameters") or {}).get("required_status_checks") or []):
            if check.get("context"):
                out.append(str(check["context"]))
    return out


def pull_request_rule(detail: dict[str, Any]) -> dict[str, Any]:
    for rule in detail.get("rules", []) or []:
        if rule.get("type") == "pull_request":
            return dict(rule.get("parameters") or {})
    return {}


def active_ruleset_details(repo: str) -> list[dict[str, Any]]:
    out = []
    for item in rulesets(repo):
        if str(item.get("enforcement")) != "active":
            continue
        detail = ruleset_detail(repo, item)
        if detail:
            detail["_source_type"] = item.get("source_type", "Repository")
            out.append(detail)
    return out


def recent_prs(repo: str, base: str, limit: int = 5) -> list[dict[str, Any]]:
    data = gh_json(["pr", "list", "--repo", repo, "--base", base, "--state", "all", "--limit", str(limit), "--json", "number,headRefOid,updatedAt,state"])
    return data if isinstance(data, list) else []


def check_runs_for_sha(repo: str, sha: str) -> list[dict[str, Any]]:
    proc = run(["gh", "api", f"repos/{repo}/commits/{sha}/check-runs?per_page=100"], check=False)
    if proc.returncode != 0:
        return []
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []
    return list(data.get("check_runs") or []) if isinstance(data, dict) else []


def observed_check_names(repo: str, base: str) -> set[str]:
    names: set[str] = set()
    for pr in recent_prs(repo, base):
        sha = str(pr.get("headRefOid") or "")
        if not sha:
            continue
        for check in check_runs_for_sha(repo, sha):
            name = str(check.get("name") or "")
            if name:
                names.add(name)
    return names


def caller_workflow_text(repo_dir: Path, branch: str) -> str | None:
    proc = run(["git", "show", f"origin/{branch}:.github/workflows/pr-qa.yml"], cwd=repo_dir, check=False)
    if proc.returncode != 0:
        return None
    return proc.stdout


def generic_caller_present(repo_dir: Path, branch: str) -> bool:
    text = caller_workflow_text(repo_dir, branch)
    if text is None:
        return False
    return "uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main" in text and re.search(r"(?m)^\s*pr-qa\s*:\s*$", text) is not None


def expected_prqa_context(repo: str, repo_dir: Path, branch: str) -> tuple[str | None, str]:
    observed = sorted(name for name in observed_check_names(repo, branch) if "Pull Request Quality Assurance" in name)
    if len(observed) == 1:
        return observed[0], "observed from live PR check-runs"
    if len(observed) > 1:
        return None, "multiple PR-QA check contexts observed: " + ", ".join(observed)
    caller = caller_workflow_text(repo_dir, branch)
    if caller is None:
        return GENERIC_CALLER_CONTEXT, "fresh bootstrap fallback; no PR-QA caller workflow exists yet"
    if "uses: Synergie-ITCI/.github/.github/workflows/pr-qa.yml@main" in caller and re.search(r"(?m)^\s*pr-qa\s*:\s*$", caller) is not None:
        return GENERIC_CALLER_CONTEXT, "derived from exact generic caller shape"
    return None, "CUSTOM_CALLER_REQUIRES_REVIEW: existing PR-QA caller is not the supported generic caller shape"


def ruleset_audit(repo: str, repo_dir: Path, default_branch: str, branches: set[str]) -> list[Finding]:
    details = active_ruleset_details(repo)
    if not details:
        return [Finding("RULESETS", "WARNING", "No active rulesets visible through GitHub API.")]
    findings: list[Finding] = []
    for branch in release_topology_branches(branches, default_branch):
        expected, source = expected_prqa_context(repo, repo_dir, branch)
        applicable = [d for d in details if ruleset_applies_to_branch(d, branch, default_branch)]
        contexts = [c for d in applicable for c in required_check_contexts(d)]
        native = [pull_request_rule(d) for d in applicable]
        approval_blockers = []
        for params in native:
            if int(params.get("required_approving_review_count") or 0) > 0:
                approval_blockers.append("native approval count > 0")
            if bool(params.get("require_last_push_approval")):
                approval_blockers.append("last-push approval required")
        if approval_blockers:
            findings.append(Finding(f"RULESET_{branch.upper()}_REVIEWS", "BLOCKED", "; ".join(sorted(set(approval_blockers)))))
        else:
            findings.append(Finding(f"RULESET_{branch.upper()}_REVIEWS", "PASS", "No native approval deadlock detected."))

        if not expected:
            findings.append(Finding(f"RULESET_{branch.upper()}_PRQA", "BLOCKED", source))
            continue
        if expected not in contexts:
            lookalikes = sorted(c for c in contexts if "Pull Request Quality Assurance" in c)
            detail = f"Expected exact context `{expected}` ({source}) is not required."
            if lookalikes:
                detail += " Mismatched PR-QA-like contexts: " + ", ".join(lookalikes)
            findings.append(Finding(f"RULESET_{branch.upper()}_PRQA", "BLOCKED", detail))
        else:
            findings.append(Finding(f"RULESET_{branch.upper()}_PRQA", "PASS", f"Exact required context `{expected}` ({source})."))

        extras = sorted(set(contexts) - {expected})
        if extras:
            findings.append(Finding(f"RULESET_{branch.upper()}_EXTRAS", "WARNING", "Additional required checks retained for manual verification: " + ", ".join(extras)))
    return findings


def install_bootstrap_files(repo_dir: Path, trusted_base: str) -> list[str]:
    targets = {
        ".github/workflows/pr-qa.yml": PR_QA_TEMPLATE.read_text(encoding="utf-8"),
        ".github/pull_request_template.md": PR_TEMPLATE.read_text(encoding="utf-8"),
    }
    changed: list[str] = []
    for rel, content in targets.items():
        path = repo_dir / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        old = path.read_text(encoding="utf-8") if path.exists() else None
        if old != content:
            path.write_text(content, encoding="utf-8")
            changed.append(rel)
    legacy_config = repo_dir / ".github/pr-qa.yml"
    if legacy_config.exists() and run(["git", "cat-file", "-e", f"origin/{trusted_base}:.github/pr-qa.yml"], cwd=repo_dir, check=False).returncode != 0:
        raise CmdError("Refusing to introduce or normalize .github/pr-qa.yml during bootstrap; central immutable defaults are authoritative for fresh onboarding.")
    return changed


def open_or_find_pr(repo: str, head: str, base: str, title: str, body: str) -> int:
    existing = gh_json(["pr", "list", "--repo", repo, "--head", head, "--base", base, "--state", "open", "--json", "number"])
    if existing:
        return int(existing[0]["number"])
    proc = run(["gh", "pr", "create", "--repo", repo, "--head", head, "--base", base, "--title", title, "--body", body])
    m = re.search(r"/pull/(\d+)", proc.stdout)
    if not m:
        raise CmdError("PR created but number could not be parsed.")
    return int(m.group(1))


def watch_pr(repo: str, pr: int) -> None:
    run(["gh", "pr", "checks", str(pr), "--repo", repo, "--watch", "--interval", "30"])


def merge_pr(repo: str, pr: int, method: str) -> None:
    view = gh_json(["pr", "view", str(pr), "--repo", repo, "--json", "headRefOid"])
    sha = view["headRefOid"]
    run(["gh", "pr", "merge", str(pr), "--repo", repo, f"--{method}", "--match-head-commit", sha])


def bootstrap_apply(repo: str, repo_dir: Path, wait: bool, base_branch: str) -> list[Finding]:
    findings: list[Finding] = []
    checkout_branch(repo_dir, base_branch)
    ensure_branch_clean(repo_dir)
    branch = "chore/governance-onboarding"
    run(["git", "checkout", "-B", branch, f"origin/{base_branch}"], cwd=repo_dir)
    changed = install_bootstrap_files(repo_dir, base_branch)
    if changed:
        run(["git", "add", *changed], cwd=repo_dir)
        run(["git", "commit", "-m", "chore(governance): onboard central PR QA"], cwd=repo_dir)
        push = run(["git", "push", "-u", "origin", f"HEAD:{branch}"], cwd=repo_dir, check=False)
        if push.returncode != 0 and "non-fast-forward" in push.stderr.lower():
            raise CmdError("Remote onboarding branch already diverged; refusing to force-push.")
        if push.returncode != 0:
            raise CmdError(push.stderr.strip())
    elif run(["git", "ls-remote", "--exit-code", "--heads", "origin", branch], cwd=repo_dir, check=False).returncode != 0:
        findings.append(Finding("BOOTSTRAP", "PASS", f"PR-QA caller and PR template already present on {base_branch}."))
        return findings

    body = """## Business Purpose\n\nOnboard this repository to the central Synergie PR-QA caller.\n\n## Testing Performed\n\nCentral PR-QA will validate this PR.\n\n## Rollback Strategy\n\nRevert the onboarding commit.\n\n## Linked Issue\n\nhttps://github.com/Synergie-ITCI/.github\n\n## Screenshots\n\nN/A\n\n## Operational Notes\n\nNo application or production deployment changes.\n"""
    pr = open_or_find_pr(repo, branch, base_branch, "chore(governance): onboard central PR QA", body)
    findings.append(Finding("GATE_A_PR", "READY", f"#{pr}"))
    if not wait:
        return findings
    watch_pr(repo, pr)
    findings.append(Finding("GATE_A", "READY", f"PR #{pr} checked; CLI does not auto-merge or auto-approve."))
    return findings


def latest_reviews(repo: str, pr: int) -> dict[str, str]:
    proc = run(["gh", "api", f"repos/{repo}/pulls/{pr}/reviews?per_page=100"], check=False)
    if proc.returncode != 0:
        return {}
    try:
        reviews = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return {}
    latest: dict[str, str] = {}
    if isinstance(reviews, list):
        for review in reviews:
            login = str(((review.get("user") or {}).get("login")) or "")
            state = str(review.get("state") or "").upper()
            if login:
                latest[login] = state
    return latest


def gate_c_status(repo: str, owner_login: str, create: bool, branches: set[str]) -> Finding:
    if not has_gate_c_path(branches):
        return Finding("GATE_C", "PASS", "Not applicable; staging→main topology is not present.")
    title = "chore(governance): complete four-gate onboarding"
    body = """## Business Purpose\n\nPromote the validated staging release candidate to main under Gate C.\n\n## Testing Performed\n\nAutomated PR-QA and staging validation.\n\n## Rollback Strategy\n\nRevert the main promotion if required.\n\n## Linked Issue\n\nhttps://github.com/Synergie-ITCI/.github\n\n## Screenshots\n\nN/A\n\n## Operational Notes\n\nGate C only. Merging this PR must not deploy production; Gate D remains separate.\n"""
    existing = gh_json(["pr", "list", "--repo", repo, "--head", "staging", "--base", "main", "--state", "open", "--json", "number,author,headRefOid"])
    if not existing:
        if not create:
            return Finding("GATE_C", "READY", "No staging→main PR open; create one when release QA is desired.")
        pr = open_or_find_pr(repo, "staging", "main", title, body)
        existing = gh_json(["pr", "view", str(pr), "--repo", repo, "--json", "number,author,headRefOid"])
        existing = [existing]
    pr_info = existing[0]
    pr = int(pr_info["number"])
    author = str(((pr_info.get("author") or {}).get("login")) or "")
    reviews = latest_reviews(repo, pr)
    approved = author == owner_login or reviews.get(owner_login) == "APPROVED"
    checks = check_runs_for_sha(repo, str(pr_info.get("headRefOid") or ""))
    failures = sorted(str(c.get("name")) for c in checks if c.get("conclusion") in {"failure", "cancelled", "timed_out", "action_required"})
    pending = sorted(str(c.get("name")) for c in checks if c.get("status") != "completed")
    if not approved:
        return Finding("GATE_C", "AWAITING", f"PR #{pr} awaiting approval from {owner_login}; tool will never merge Gate C.")
    if failures:
        return Finding("GATE_C", "BLOCKED", f"PR #{pr} has failing checks: {', '.join(failures)}")
    if pending:
        return Finding("GATE_C", "AWAITING", f"PR #{pr} has pending checks: {', '.join(pending)}")
    return Finding("GATE_C", "READY", f"PR #{pr} has owner authorization and no failing/pending checks; manual merge required.")


def onboarding_paths() -> set[str]:
    return {".github/workflows/pr-qa.yml", ".github/pull_request_template.md"}


def pr_changed_files(repo: str, pr: int) -> list[str]:
    data = gh_json(["pr", "view", str(pr), "--repo", repo, "--json", "files"])
    files = data.get("files", []) if isinstance(data, dict) else []
    return [str(item.get("path")) for item in files if item.get("path")]


def pr_files(repo: str, pr: int) -> list[dict[str, Any]]:
    data = gh_json(["pr", "view", str(pr), "--repo", repo, "--json", "files"])
    files = data.get("files", []) if isinstance(data, dict) else []
    return [dict(item) for item in files if item.get("path")]


def latest_prqa_report(repo: str, sha: str) -> dict[str, Any] | None:
    checks = check_runs_for_sha(repo, sha)
    prqa = [c for c in checks if str(c.get("name") or "") == GENERIC_CALLER_CONTEXT]
    if not prqa:
        return None
    run_url = str(prqa[0].get("details_url") or "")
    match = re.search(r"/actions/runs/(\d+)", run_url)
    if not match:
        return None
    with tempfile.TemporaryDirectory(prefix="synergie-prqa-report-") as tmp:
        out = Path(tmp)
        for artifact_name in ("pr-qa-results", "pr-qa-phase-1-results"):
            artifact_dir = out / artifact_name
            artifact_dir.mkdir()
            download = run(["gh", "run", "download", match.group(1), "--repo", repo, "--name", artifact_name, "--dir", str(artifact_dir)], check=False)
            if download.returncode != 0:
                continue
            for candidate in ("pr-quality-report.json", "report.json"):
                path = artifact_dir / candidate
                if path.exists():
                    try:
                        return json.loads(path.read_text(encoding="utf-8"))
                    except json.JSONDecodeError:
                        return None
    return None


def failed_report_entries(report: dict[str, Any]) -> list[dict[str, Any]]:
    results = report.get("results", []) if isinstance(report, dict) else []
    if not isinstance(results, list):
        return []
    failed_entries = []
    for item in results:
        if not isinstance(item, dict):
            continue
        if str(item.get("status") or "").upper() != "FAIL":
            continue
        if item.get("blocking") is False:
            continue
        failed_entries.append(item)
    return failed_entries


def report_entry_text(entry: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("gate", "message", "technology"):
        value = entry.get(key)
        if value:
            parts.append(str(value))
    details = entry.get("details")
    if isinstance(details, list):
        parts.extend(str(item) for item in details)
    elif details:
        parts.append(str(details))
    return "\n".join(parts)


def paths_from_report_text(text: str, known_paths: set[str]) -> set[str]:
    found = {path for path in known_paths if path and path in text}
    for match in re.finditer(r"(?:^|[`'\"\\s])([A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.@+-]+)+)(?:[`'\"\\s:]|$)", text):
        found.add(match.group(1))
    return found


def classify_prqa_failure_attribution(report: dict[str, Any] | None, changed_files: list[str]) -> str:
    if not report:
        return "BLOCKED_UNKNOWN"
    changed = set(changed_files)
    failures = failed_report_entries(report)
    if not failures:
        return "BLOCKED_UNKNOWN"
    texts = [report_entry_text(entry) for entry in failures]
    failed_paths: set[str] = set()
    for text in texts:
        failed_paths.update(paths_from_report_text(text, changed | onboarding_paths()))
    if failed_paths & onboarding_paths() & changed:
        return "BLOCKED_ON_ONBOARDING_FILE"
    lower_text = "\n".join(texts).lower()
    if failed_paths and not (failed_paths & changed):
        return "BLOCKED_ON_EXISTING_LEGACY_FINDING"
    if ("inherited" in lower_text or "pre-existing" in lower_text) and not (failed_paths & changed):
        return "BLOCKED_ON_EXISTING_LEGACY_FINDING"
    return "BLOCKED_UNKNOWN"


def pr_status(repo: str, pr: int, owner_login: str) -> str:
    data = gh_json(["pr", "view", str(pr), "--repo", repo, "--json", "author,baseRefName,headRefName,headRefOid,mergeable"])
    if not isinstance(data, dict):
        return "BLOCKED_UNKNOWN"
    files = [str(item.get("path")) for item in pr_files(repo, pr) if item.get("path")]
    checks = check_runs_for_sha(repo, str(data.get("headRefOid") or ""))
    failures = [c for c in checks if c.get("conclusion") in {"failure", "cancelled", "timed_out", "action_required"}]
    pending = [c for c in checks if c.get("status") != "completed"]
    if failures:
        return classify_prqa_failure_attribution(latest_prqa_report(repo, str(data.get("headRefOid") or "")), files)
    if pending:
        return "BLOCKED_UNKNOWN"
    gate_c = str(data.get("headRefName") or "").lower() == "staging" and str(data.get("baseRefName") or "").lower() == "main"
    if gate_c:
        author = str(((data.get("author") or {}).get("login")) or "")
        reviews = latest_reviews(repo, pr)
        if author != owner_login and reviews.get(owner_login) != "APPROVED":
            return "WAITING_FOR_HUMAN_APPROVAL"
    return "PASS"


def verify(args: argparse.Namespace) -> int:
    require_tools()
    validate_repo_slug(args.repo)
    owner_login = central_owner_login()
    status = pr_status(args.repo, int(args.pr), owner_login)
    print(status)
    return 0 if status == "PASS" else 3


def print_report(repo: str, findings: list[Finding], workflows: list[dict[str, Any]], *, json_mode: bool = False) -> None:
    blockers = [f for f in findings if f.status == "BLOCKED"]
    if json_mode:
        print(json.dumps({"repository": repo, "findings": [asdict(f) for f in findings], "workflows": workflows, "ready": not blockers}, indent=2))
        return
    print(f"REPO: {repo}")
    for f in findings:
        print(f"{f.key:32} {f.status:8} {f.detail}")
    print()
    print("READY:", "YES" if not blockers else "NO")
    if blockers:
        print("BLOCKERS:")
        for f in blockers:
            print(f"- {f.key}: {f.detail}")


def onboard(args: argparse.Namespace) -> int:
    require_tools()
    validate_repo_slug(args.repo)
    meta = repo_metadata(args.repo)
    default_branch = str(((meta.get("defaultBranchRef") or {}).get("name")) or "main")
    owner_login = central_owner_login()
    tmp = clone_repo(args.repo)
    repo_dir = Path(tmp.name)
    try:
        run(["git", "fetch", "origin", "--prune"], cwd=repo_dir)
        findings: list[Finding] = [Finding("STATE", "PASS", "Derived fresh from live GitHub/repository data; no persistent state/cache is used.")]
        branches = list_remote_branches(repo_dir)
        topology = classify_topology(branches, default_branch)
        bootstrap_base = branch_for_bootstrap(branches, default_branch)
        source_ref = f"origin/{default_branch}" if default_branch in branches else f"origin/{bootstrap_base}"
        paths = repository_files(repo_dir, source_ref)
        technologies = detect_technologies(paths)
        profile = classify_profile(paths, technologies, args.profile)
        criticality = classify_criticality(profile, technologies, args.criticality, paths)
        findings.append(Finding("TOPOLOGY", "PASS" if topology != "TOPOLOGY_REVIEW_REQUIRED" else "WARNING", topology))
        findings.append(Finding("BOOTSTRAP_BASE", "PASS", bootstrap_base))
        findings.append(Finding("TECHNOLOGIES", "PASS", ", ".join(technologies) if technologies else "none detected"))
        findings.append(Finding("PROFILE", "PASS", profile))
        findings.append(Finding("CRITICALITY", "PASS", criticality))
        findings.append(Finding("RUNTIME", "PASS", "NOT_VERIFIED"))
        if profile in {"application", "infrastructure"} and criticality in {"high", "critical"} and topology not in {"STANDARD_SYNERGIE_FLOW", "STANDARD_THREE_STAGE"}:
            findings.append(Finding("RELEASE_TOPOLOGY_GAP", "WARNING", "Deployable/high-criticality repository does not expose development→staging→main; remediate separately."))
        if any(f.status == "BLOCKED" for f in findings):
            print_report(args.repo, findings, [], json_mode=args.json)
            return 2

        if args.apply:
            findings.extend(bootstrap_apply(args.repo, repo_dir, args.wait, bootstrap_base))
            run(["git", "fetch", "origin", "--prune"], cwd=repo_dir)

        findings.extend(ruleset_audit(args.repo, repo_dir, default_branch, branches))
        deploy_findings, workflow_rows = deployment_audit(repo_dir, owner_login, branches, default_branch)
        findings.extend(deploy_findings)

        blockers = [f for f in findings if f.status == "BLOCKED"]
        if args.apply and args.wait and not blockers:
            findings.append(gate_c_status(args.repo, owner_login, create=True, branches=branches))
            findings.append(Finding("PRODUCTION", "PASS", "Untouched; CLI has no AWS/SSH/workflow-dispatch production action."))
        elif not args.apply:
            findings.append(gate_c_status(args.repo, owner_login, create=False, branches=branches))

        print_report(args.repo, findings, workflow_rows, json_mode=args.json)
        return 0 if not any(f.status == "BLOCKED" for f in findings) else 3
    finally:
        tmp.cleanup()


def audit(args: argparse.Namespace) -> int:
    args.apply = False
    args.wait = False
    return onboard(args)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="synergie-governance", description="Stateless Synergie repository governance onboarding/audit CLI.")
    sub = p.add_subparsers(dest="command", required=True)
    for name in ("onboard", "audit"):
        sp = sub.add_parser(name)
        sp.add_argument("repo", help="OWNER/REPO")
        sp.add_argument("--json", action="store_true", help="Machine-readable report")
        sp.add_argument("--profile", choices=PROFILE_CHOICES, default="auto", help="Repository profile classification override")
        sp.add_argument("--criticality", choices=CRITICALITY_CHOICES, default="auto", help="Repository criticality classification override")
        if name == "onboard":
            sp.add_argument("--apply", action="store_true", help="Apply deterministic two-file PR-QA bootstrap through normal PRs")
            sp.add_argument("--wait", action="store_true", help="Wait for Gate A checks only; never auto-merges or auto-approves")
    verify_parser = sub.add_parser("verify")
    verify_parser.add_argument("repo", help="OWNER/REPO")
    verify_parser.add_argument("pr", help="Pull request number")
    return p


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "audit":
            return audit(args)
        if args.command == "verify":
            return verify(args)
        return onboard(args)
    except CmdError as exc:
        print(f"BLOCKED: {exc}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    raise SystemExit(main())
