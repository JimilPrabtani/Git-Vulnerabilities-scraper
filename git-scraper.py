"""
Self-contained repo security scanner.

Clones a git repo (bare, local disk only) and scans it for secrets and other
risks across every branch and the full commit history. Uses only the local
`git` binary and the Python standard library -- no GitHub API, no external
network calls beyond the initial `git clone`.
"""

import argparse
import collections
import fnmatch
import html
import json
import math
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass, field

# --------------------------------------------------------------------------
# Config / rule tables
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

MAX_FILE_SIZE = 5_000_000  # bytes; larger blobs are skipped for content scanning

NOISY_ENTROPY_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "go.sum", "composer.lock", "Cargo.lock",
}
NOISY_ENTROPY_SUFFIXES = (".min.js", ".map", ".svg")

DEPENDENCY_FILENAMES = {"requirements.txt", "package.json"}

# (name, severity, compiled regex). Kept intentionally small/curated; swap in
# a bigger rule set (e.g. gitleaks' TOML rules) later if false negatives show up.
SECRET_PATTERNS = [
    ("AWS Access Key ID", "CRITICAL", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key", "CRITICAL",
     re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
    ("GCP service account key", "CRITICAL", re.compile(r'"type":\s*"service_account"')),
    ("Private key block", "CRITICAL",
     re.compile(r"-----BEGIN (RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----")),
    ("GitHub token", "HIGH", re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}")),
    ("Slack token", "HIGH", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe live key", "HIGH", re.compile(r"sk_live_[0-9A-Za-z]{16,}")),
    ("Database connection string with credentials", "CRITICAL",
     re.compile(r"(?i)(postgres(ql)?|mysql|mongodb(\+srv)?)://[^:\s/]+:[^@\s/]+@")),
    ("Slack webhook URL", "MEDIUM", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+")),
    ("JWT", "MEDIUM", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Generic secret assignment", "MEDIUM",
     re.compile(r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"][^'\"\s]{6,}['\"]")),
]

SENSITIVE_FILENAME_PATTERNS = [
    (re.compile(r"(^|/)\.env(\..*)?$", re.I), "HIGH"),
    (re.compile(r"\.pem$", re.I), "HIGH"),
    (re.compile(r"\.pfx$", re.I), "HIGH"),
    (re.compile(r"\.p12$", re.I), "HIGH"),
    (re.compile(r"(^|/)id_rsa$", re.I), "CRITICAL"),
    (re.compile(r"(^|/)id_dsa$", re.I), "CRITICAL"),
    (re.compile(r"(^|/)id_ecdsa$", re.I), "CRITICAL"),
    (re.compile(r"(^|/)id_ed25519$", re.I), "CRITICAL"),
    (re.compile(r"credentials\.json$", re.I), "HIGH"),
    (re.compile(r"(^|/)\.npmrc$", re.I), "MEDIUM"),
    (re.compile(r"(^|/)\.pypirc$", re.I), "MEDIUM"),
    (re.compile(r"(^|/)\.aws/credentials$", re.I), "CRITICAL"),
    (re.compile(r"(^|/)\.kube/config$", re.I), "HIGH"),
    (re.compile(r"terraform\.tfstate$", re.I), "HIGH"),
    (re.compile(r"\.keystore$", re.I), "HIGH"),
    (re.compile(r"(^|/)\.git-credentials$", re.I), "CRITICAL"),
]

ENTROPY_TOKEN_RE = re.compile(r"""[:=]\s*['"]?([A-Za-z0-9+/_=\-]{20,})['"]?""")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
WORKFLOW_PATH_RE = re.compile(r"\.github/workflows/[^/]+\.ya?ml$", re.I)


@dataclass
class Finding:
    severity: str
    category: str
    title: str
    location: str
    evidence: str = ""


# --------------------------------------------------------------------------
# Low-level git helpers
# --------------------------------------------------------------------------

def run_git(git_dir, args, timeout=120):
    result = subprocess.run(
        ["git", "--git-dir", git_dir] + args,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        timeout=timeout,
    )
    return result.stdout


def clone_repo(source, dest):
    subprocess.run(
        ["git", "clone", "--quiet", "--bare", source, dest],
        check=True, capture_output=True, text=True,
    )


def list_branches(git_dir):
    out = run_git(git_dir, ["branch", "--format=%(refname:short)"])
    return [b.strip() for b in out.splitlines() if b.strip()]


def default_branch(git_dir, branches):
    head = run_git(git_dir, ["symbolic-ref", "--short", "HEAD"]).strip()
    if head in branches:
        return head
    for candidate in ("main", "master"):
        if candidate in branches:
            return candidate
    return branches[0] if branches else None


def list_tree(git_dir, branch):
    """Returns [(path, blob_sha), ...] for every file in a branch's tree."""
    out = run_git(git_dir, ["ls-tree", "-r", branch])
    entries = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        meta, path = line.split("\t", 1)
        parts = meta.split()
        if len(parts) != 3:
            continue
        _, obj_type, sha = parts
        if obj_type == "blob":
            entries.append((path, sha))
    return entries


class BlobReader:
    """Wraps `git cat-file --batch` as a single long-lived process so scanning
    thousands of blobs doesn't spawn thousands of subprocesses."""

    def __init__(self, git_dir):
        self.proc = subprocess.Popen(
            ["git", "--git-dir", git_dir, "cat-file", "--batch"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        )

    def read(self, sha):
        self.proc.stdin.write((sha + "\n").encode())
        self.proc.stdin.flush()
        header = self.proc.stdout.readline().decode(errors="replace").strip()
        parts = header.split()
        if len(parts) != 3:
            return None  # missing/ambiguous object
        _, _obj_type, size_str = parts
        size = int(size_str)
        data = self.proc.stdout.read(size)
        self.proc.stdout.read(1)  # trailing newline
        return data

    def close(self):
        try:
            self.proc.stdin.close()
        except Exception:
            pass
        self.proc.wait(timeout=10)


def is_binary(data):
    return b"\x00" in data[:8192]


# --------------------------------------------------------------------------
# Content analysis
# --------------------------------------------------------------------------

def mask_secret(value):
    value = value.strip()
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def shannon_entropy(s):
    if not s:
        return 0.0
    counts = collections.Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def is_noisy_for_entropy(path):
    base = os.path.basename(path)
    if base in NOISY_ENTROPY_NAMES:
        return True
    return base.endswith(NOISY_ENTROPY_SUFFIXES)


def scan_secret_patterns(text, location):
    findings = []
    lines = text.splitlines()
    for name, severity, pattern in SECRET_PATTERNS:
        for lineno, line in enumerate(lines, start=1):
            m = pattern.search(line)
            if m:
                findings.append(Finding(
                    severity=severity, category="secret", title=f"{name} detected",
                    location=f"{location}:{lineno}", evidence=mask_secret(m.group(0)),
                ))
    return findings


def scan_entropy(text, location):
    findings = []
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for m in ENTROPY_TOKEN_RE.finditer(line):
            token = m.group(1)
            if HEX_RE.match(token) and len(token) in (40, 64):
                continue  # almost always a git/content hash, not a secret
            entropy = shannon_entropy(token)
            threshold = 3.0 if HEX_RE.match(token) else 4.3
            if entropy >= threshold:
                findings.append(Finding(
                    severity="MEDIUM", category="entropy",
                    title="Possible high-entropy secret (heuristic, verify manually)",
                    location=f"{location}:{lineno}", evidence=mask_secret(token),
                ))
    return findings


def analyze_workflow(text, location):
    findings = []
    has_pull_request_target = "pull_request_target" in text
    has_pr_head_checkout = re.search(r"ref:\s*\$\{\{\s*github\.event\.pull_request\.head", text) is not None
    if has_pull_request_target and has_pr_head_checkout:
        findings.append(Finding(
            severity="CRITICAL", category="ci-workflow",
            title="pull_request_target combined with checkout of PR head (pwn-request risk)",
            location=location,
            evidence="Untrusted PR code can run with access to repo secrets.",
        ))
    if re.search(r"\$\{\{\s*github\.event\.(issue|pull_request|comment|review|head_commit)\.", text):
        findings.append(Finding(
            severity="MEDIUM", category="ci-workflow",
            title="User-controlled context interpolated in workflow (possible script injection)",
            location=location,
            evidence="Verify this isn't interpolated directly into a run: shell step.",
        ))
    if re.search(r"permissions:\s*write-all", text) or re.search(r"contents:\s*write", text):
        findings.append(Finding(
            severity="MEDIUM", category="ci-workflow",
            title="Workflow grants broad permissions",
            location=location, evidence="",
        ))
    for m in re.finditer(r"uses:\s*([^\s@]+)@([^\s]+)", text):
        action, ref = m.group(1), m.group(2)
        if not re.fullmatch(r"[0-9a-f]{40}", ref):
            findings.append(Finding(
                severity="LOW", category="ci-workflow",
                title=f"Action '{action}' not pinned to a full commit SHA (uses '{ref}')",
                location=location,
                evidence="Mutable tags/branches are a supply-chain risk if the action is compromised.",
            ))
    return findings


def analyze_dependencies(text, path, location):
    findings = []
    base = os.path.basename(path)
    if base == "requirements.txt":
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            if not re.search(r"[=<>~!]=", line):
                findings.append(Finding(
                    severity="LOW", category="dependency",
                    title=f"Unpinned dependency: {line}",
                    location=location,
                    evidence="No version pin -- can't verify against known-vulnerable versions.",
                ))
    elif base == "package.json":
        try:
            data = json.loads(text)
        except ValueError:
            return findings
        for section in ("dependencies", "devDependencies"):
            for name, version in (data.get(section) or {}).items():
                if version in ("*", "latest", ""):
                    findings.append(Finding(
                        severity="LOW", category="dependency",
                        title=f"Unpinned dependency: {name}@{version or '(empty)'}",
                        location=location, evidence="",
                    ))
    return findings


def analyze_blob(path, content, location):
    findings = []
    if content is None or is_binary(content) or len(content) > MAX_FILE_SIZE:
        return findings
    text = content.decode("utf-8", errors="replace")
    findings.extend(scan_secret_patterns(text, location))
    if not is_noisy_for_entropy(path):
        findings.extend(scan_entropy(text, location))
    if WORKFLOW_PATH_RE.search(path.lower()):
        findings.extend(analyze_workflow(text, location))
    if os.path.basename(path) in DEPENDENCY_FILENAMES:
        findings.extend(analyze_dependencies(text, path, location))
    return findings


# --------------------------------------------------------------------------
# Repo-wide passes
# --------------------------------------------------------------------------

def matches_sensitive_filename(path):
    for pattern, severity in SENSITIVE_FILENAME_PATTERNS:
        if pattern.search(path):
            return severity
    return None


def scan_current_trees(git_dir, branches):
    """Content scan of every unique blob reachable from any branch tip.
    Dedupes by blob SHA so identical files across branches are scanned once."""
    blob_locations = collections.defaultdict(set)  # sha -> {(branch, path), ...}
    tree_paths = collections.defaultdict(set)      # branch -> {path, ...}
    all_paths_current = set()

    for branch in branches:
        for path, sha in list_tree(git_dir, branch):
            blob_locations[sha].add((branch, path))
            tree_paths[branch].add(path)
            all_paths_current.add(path)

    findings = []
    reader = BlobReader(git_dir)
    try:
        for sha, locations in blob_locations.items():
            content = reader.read(sha)
            sample_branch, sample_path = sorted(locations)[0]
            branch_list = ", ".join(sorted({b for b, _ in locations}))
            location_label = f"{sample_path} [{branch_list}]"
            for finding in analyze_blob(sample_path, content, location_label):
                findings.append(finding)

            severity = matches_sensitive_filename(sample_path)
            if severity:
                findings.append(Finding(
                    severity=severity, category="sensitive-file",
                    title=f"Sensitive file tracked in repo: {sample_path}",
                    location=location_label,
                    evidence="File type commonly holds credentials/keys.",
                ))
    finally:
        reader.close()

    return findings, tree_paths, all_paths_current


def scan_history_diffs(git_dir):
    """Streams `git log --all -p` and scans added lines for secrets, catching
    credentials that were committed then later removed but remain in history."""
    findings = []
    proc = subprocess.Popen(
        ["git", "--git-dir", git_dir, "log", "--all", "-p", "--no-color", "--unified=0"],
        stdout=subprocess.PIPE, text=True, encoding="utf-8", errors="replace",
    )
    current_commit = "?"
    current_file = "?"
    try:
        for raw_line in proc.stdout:
            line = raw_line.rstrip("\n")
            if line.startswith("commit "):
                current_commit = line.split()[1][:12]
                continue
            if line.startswith("diff --git"):
                m = re.search(r" b/(.+)$", line)
                if m:
                    current_file = m.group(1)
                continue
            if line.startswith("+++") or line.startswith("---"):
                continue
            if line.startswith("+"):
                added = line[1:]
                location = f"{current_file} (commit {current_commit})"
                for name, severity, pattern in SECRET_PATTERNS:
                    m = pattern.search(added)
                    if m:
                        findings.append(Finding(
                            severity=severity, category="history-secret",
                            title=f"{name} found in commit history (possibly since removed)",
                            location=location, evidence=mask_secret(m.group(0)),
                        ))
    finally:
        proc.stdout.close()
        proc.wait(timeout=300)
    return findings


def scan_commit_messages(git_dir):
    findings = []
    out = run_git(git_dir, ["log", "--all", "--format=%H%x1f%s%x1e"], timeout=300)
    for record in out.split("\x1e"):
        record = record.strip()
        if not record or "\x1f" not in record:
            continue
        commit_hash, subject = record.split("\x1f", 1)
        for name, severity, pattern in SECRET_PATTERNS:
            m = pattern.search(subject)
            if m:
                findings.append(Finding(
                    severity=severity, category="history-secret",
                    title=f"{name} found in a commit message",
                    location=f"commit {commit_hash[:12]}", evidence=mask_secret(m.group(0)),
                ))
    return findings


def scan_ever_added_filenames(git_dir, all_paths_current):
    findings = []
    out = run_git(git_dir, ["log", "--all", "--diff-filter=A", "--name-only", "--format="], timeout=300)
    seen = set()
    for path in out.splitlines():
        path = path.strip()
        if not path or path in seen:
            continue
        seen.add(path)
        severity = matches_sensitive_filename(path)
        if not severity:
            continue
        if path in all_paths_current:
            continue  # already reported by scan_current_trees with full content scan
        findings.append(Finding(
            severity=severity, category="sensitive-file-history",
            title=f"Sensitive file was committed and later removed: {path}",
            location=path,
            evidence="Still recoverable from git history; rotate any credentials it held.",
        ))
    return findings


def audit_gitignore(git_dir, branch, branch_paths):
    findings = []
    gitignore_content = None
    try:
        entries = dict(list_tree(git_dir, branch))
        if ".gitignore" in entries:
            reader = BlobReader(git_dir)
            try:
                data = reader.read(entries[".gitignore"])
            finally:
                reader.close()
            if data is not None:
                gitignore_content = data.decode("utf-8", errors="replace")
    except Exception:
        pass

    if gitignore_content is None:
        findings.append(Finding(
            severity="INFO", category="gitignore",
            title="No .gitignore file found on default branch",
            location=branch, evidence="",
        ))
        return findings

    patterns = [
        line.strip() for line in gitignore_content.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]

    for path in branch_paths:
        if not matches_sensitive_filename(path):
            continue
        base = os.path.basename(path)
        ignored = any(
            fnmatch.fnmatch(path, p) or fnmatch.fnmatch(base, p) or fnmatch.fnmatch(path, f"*/{p}")
            for p in patterns
        )
        if ignored:
            findings.append(Finding(
                severity="HIGH", category="gitignore",
                title=f"Sensitive file tracked despite matching a .gitignore pattern: {path}",
                location=branch,
                evidence="Likely force-added with `git add -f` -- was probably not meant to be committed.",
            ))
        else:
            findings.append(Finding(
                severity="INFO", category="gitignore",
                title=f"No .gitignore rule covers sensitive file: {path}",
                location=branch, evidence="",
            ))
    return findings


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def sort_findings(findings):
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.category, f.location))


def print_console_report(repo_label, findings):
    findings = sort_findings(findings)
    counts = collections.Counter(f.severity for f in findings)
    print(f"\n=== Scan results for {repo_label} ===")
    print(f"Total findings: {len(findings)}  "
          + "  ".join(f"{sev}:{counts.get(sev, 0)}" for sev in SEVERITY_ORDER))
    for f in findings:
        evidence = f" -- {f.evidence}" if f.evidence else ""
        print(f"[{f.severity:8}] {f.category:22} {f.title} ({f.location}){evidence}")


def write_json_report(path, repo_label, findings):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"repo": repo_label, "findings": [asdict(f) for f in sort_findings(findings)]}, fh, indent=2)


def write_html_report(path, repo_label, findings):
    rows = []
    for f in sort_findings(findings):
        rows.append(
            "<tr class='sev-{sev}'><td>{sev}</td><td>{cat}</td><td>{title}</td>"
            "<td>{loc}</td><td>{ev}</td></tr>".format(
                sev=html.escape(f.severity), cat=html.escape(f.category),
                title=html.escape(f.title), loc=html.escape(f.location),
                ev=html.escape(f.evidence),
            )
        )
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>Scan report: {html.escape(repo_label)}</title>
<style>
body {{ font-family: sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
td, th {{ border: 1px solid #ccc; padding: 6px 10px; text-align: left; font-size: 14px; }}
.sev-CRITICAL {{ background: #ffd6d6; }}
.sev-HIGH {{ background: #ffe6cc; }}
.sev-MEDIUM {{ background: #fff8cc; }}
.sev-LOW {{ background: #e6f2ff; }}
.sev-INFO {{ background: #f0f0f0; }}
</style></head>
<body>
<h1>Scan report: {html.escape(repo_label)}</h1>
<p>{len(findings)} findings</p>
<table>
<tr><th>Severity</th><th>Category</th><th>Title</th><th>Location</th><th>Evidence</th></tr>
{''.join(rows)}
</table>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------------

def scan_repo(source, out_dir, keep_clone):
    if shutil.which("git") is None:
        print("git is not installed or not on PATH.")
        return

    repo_label = source
    clone_dir = tempfile.mkdtemp(prefix="git_scraper_")
    try:
        print(f"Cloning {source} ...")
        clone_repo(source, clone_dir)
    except subprocess.CalledProcessError as e:
        print(f"Failed to clone {source}: {e.stderr.strip()}")
        shutil.rmtree(clone_dir, ignore_errors=True)
        return

    try:
        branches = list_branches(clone_dir)
        if not branches:
            print(f"No branches found in {source}.")
            return
        branch = default_branch(clone_dir, branches)
        print(f"Found {len(branches)} branch(es): {', '.join(branches)}")

        findings = []

        print("Scanning current file trees across all branches ...")
        tree_findings, tree_paths, all_paths_current = scan_current_trees(clone_dir, branches)
        findings.extend(tree_findings)

        print("Scanning .gitignore coverage ...")
        findings.extend(audit_gitignore(clone_dir, branch, tree_paths.get(branch, set())))

        print("Scanning full commit history for removed-but-not-forgotten secrets ...")
        findings.extend(scan_history_diffs(clone_dir))
        findings.extend(scan_commit_messages(clone_dir))
        findings.extend(scan_ever_added_filenames(clone_dir, all_paths_current))

        os.makedirs(out_dir, exist_ok=True)
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", repo_label.rstrip("/").rsplit("/", 1)[-1]) or "repo"
        json_path = os.path.join(out_dir, f"{safe_name}.json")
        html_path = os.path.join(out_dir, f"{safe_name}.html")
        write_json_report(json_path, repo_label, findings)
        write_html_report(html_path, repo_label, findings)

        print_console_report(repo_label, findings)
        print(f"\nReports written to:\n  {json_path}\n  {html_path}")
    finally:
        if keep_clone:
            print(f"Clone kept at: {clone_dir}")
        else:
            shutil.rmtree(clone_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="Self-contained git repo secret/vulnerability scanner.")
    parser.add_argument("--repo", action="append", default=[], help="Repo URL or local path to scan (repeatable).")
    parser.add_argument("--list-file", help="File with one repo URL/path per line.")
    parser.add_argument("--out", default="scan-reports", help="Directory to write JSON/HTML reports to.")
    parser.add_argument("--keep-clone", action="store_true", help="Don't delete the temporary clone after scanning.")
    args = parser.parse_args()

    repos = list(args.repo)
    if args.list_file:
        with open(args.list_file, "r", encoding="utf-8") as fh:
            repos.extend(line.strip() for line in fh if line.strip() and not line.strip().startswith("#"))

    if not repos:
        raw = input("Enter repo URL(s) or local path(s), comma-separated: ").strip()
        repos = [r.strip() for r in raw.split(",") if r.strip()]

    if not repos:
        print("No repos to scan.")
        sys.exit(1)

    for source in repos:
        scan_repo(source, args.out, args.keep_clone)


if __name__ == "__main__":
    main()
