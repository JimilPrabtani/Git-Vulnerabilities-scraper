# Git Vulnerabilities Scraper

A self-contained Python security scanner for Git repositories.

This tool performs an offline-first security analysis by cloning a repository as a **bare clone** and scanning:

- all branches
- current file trees
- full commit history (including removed secrets)
- commit messages
- sensitive filenames and `.gitignore` coverage
- basic GitHub Actions workflow risks
- dependency pinning hygiene

> It uses only the local `git` binary + Python standard library.  
> No GitHub API and no external network calls except the initial `git clone`.

---

## Features

- **Multi-branch scanning** across all reachable branch tips
- **Secret detection** using curated regex rules (AWS keys, GitHub tokens, private key blocks, DB URIs, etc.)
- **Entropy-based detection** for potential hardcoded secrets
- **History diff scanning** to find secrets that were committed and later removed
- **Commit message scanning** for leaked credentials in commit subjects
- **Sensitive file detection** (`.env`, `id_rsa`, `.aws/credentials`, `.git-credentials`, etc.)
- **`.gitignore` audit** for tracked sensitive files
- **GitHub Actions workflow checks**, including:
  - `pull_request_target` + PR head checkout risk
  - user-controlled context interpolation
  - broad permissions
  - unpinned actions (not pinned to full 40-char SHA)
- **Dependency hygiene checks**:
  - unpinned `requirements.txt` entries
  - wildcard/latest package versions in `package.json`
- Report output in **JSON** and **HTML**

---

## Requirements

- Python 3.8+ (recommended)
- Git installed and available in `PATH`

Check git availability:

```bash
git --version
```

---

## Installation

Clone this repository:

```bash
git clone https://github.com/JimilPrabtani/Git-Vulnerabilities-scraper.git
cd Git-Vulnerabilities-scraper
```

No third-party Python dependencies are required.

---

## Usage

Main script:

```bash
python git-scraper.py --repo <repo_url_or_local_path>
```

### Scan one repository

```bash
python git-scraper.py --repo https://github.com/owner/repo.git
```

### Scan multiple repositories (repeatable `--repo`)

```bash
python git-scraper.py \
  --repo https://github.com/owner/repo1.git \
  --repo https://github.com/owner/repo2.git
```

### Scan repositories from a file

Create `repos.txt` (one repo URL/path per line):
```txt
https://github.com/owner/repo1.git
https://github.com/owner/repo2.git
# comments are ignored
```

Run:

```bash
python git-scraper.py --list-file repos.txt
```

### Set output directory

```bash
python git-scraper.py --repo https://github.com/owner/repo.git --out scan-reports
```

### Keep temporary bare clone

By default, temporary clone is deleted after scan. Keep it for debugging:

```bash
python git-scraper.py --repo https://github.com/owner/repo.git --keep-clone
```

### Interactive mode (if no `--repo` / `--list-file`)

If no source is provided, the script prompts:

```text
Enter repo URL(s) or local path(s), comma-separated:
```

---

## CLI Options

- `--repo` (repeatable): repository URL or local path to scan
- `--list-file`: file containing one repo URL/path per line
- `--out`: output directory for reports (default: `scan-reports`)
- `--keep-clone`: do not delete temporary bare clone directory

---

## Output

For each scanned repository, the tool creates:

- `scan-reports/<repo_name>.json`
- `scan-reports/<repo_name>.html`

It also prints a console summary with total findings and severity counts.

### Severity levels

- `CRITICAL`
- `HIGH`
- `MEDIUM`
- `LOW`
- `INFO`

### Finding categories (examples)

- `secret`
- `entropy`
- `history-secret`
- `sensitive-file`
- `sensitive-file-history`
- `ci-workflow`
- `dependency`
- `gitignore`

---

## What the scanner checks

### 1) Current trees across all branches
Scans unique blobs across branch tips for:
- known secret patterns
- high-entropy token candidates
- workflow misconfigurations
- dependency pinning issues
- sensitive filenames currently tracked

### 2) Full commit history
Scans `git log --all -p` added lines to detect secrets that may no longer exist in current files but remain in history.

### 3) Commit messages
Scans commit subjects for secret-like strings.

### 4) Sensitive file history
Finds files that match sensitive filename patterns and were added at any point in history, even if later removed.

### 5) `.gitignore` coverage
Reports whether sensitive tracked files are ignored or not ignored on the default branch.

---

## Security notes

- Evidence values are masked before reporting.
- This tool is best for **triage** and **early detection**, not a complete security audit.
- Findings may include false positives/false negatives; manual verification is required.

---

## Limitations

- Pattern-based + heuristic approach (not CVE resolution against lockfile graphs)
- No GitHub Advisory API usage
- Very large blobs are skipped for content scanning (`MAX_FILE_SIZE = 5,000,000 bytes`)
- Binary files are not content-scanned

---

## Example

```bash
python git-scraper.py \
  --repo https://github.com/some-org/some-repo.git \
  --out scan-reports
```

Then open:
- `scan-reports/some-repo.json`
- `scan-reports/some-repo.html`

---

## Responsible Use

Only scan repositories you own or are authorized to assess.

---

## Author

**JimilPrabtani**  
GitHub: [@JimilPrabtani](https://github.com/JimilPrabtani)

---

## License

Add your license here (e.g., MIT).  
If not yet added, create a `LICENSE` file and update this section.
