# Quick Start Guide

A short, practical guide to running the tool. For every flag, the language list and the GitHub API details, see the [README](README.md). For the detection and placement rules, see [docs/how-it-works.md](docs/how-it-works.md).

## What this tool does

It adds Veracode SAST, SCA and IaC/Secrets scanning to a repository's existing GitHub Actions workflow, after the build, without changing the existing jobs. It works on one local workflow file or across a whole org, and commits the change to a branch (`veracode/integration`) for you to test in a PR. Nothing is written to the default branch.

-----

## 1. Prerequisites

| Requirement | Details |
|---|---|
| Python 3.10 or newer | Check with `python --version` |
| PyYAML | `pip install -r requirements.txt` |
| GitHub access | A token or `gh` login (see step 2) |
| Veracode API credentials | An [API ID and key](https://docs.veracode.com/r/c_api_credentials3), and an [SCA agent token](https://docs.veracode.com/r/Manage_agents_and_scans) for SCA |
| GitHub Actions | Enabled in the repos, with `actions/*` and `veracode/*` actions allowed |

-----

## 2. Authenticate to GitHub

The tool uses the first token it finds: `--token-command`, then `GH_TOKEN`, then `GITHUB_TOKEN`, then `gh auth token`.

**Option A: GitHub CLI**

```bash
gh auth login -s workflow
```

**Option B: environment variable**

```bash
# macOS / Linux
export GH_TOKEN=ghp_your_token_here

# Windows PowerShell
$env:GH_TOKEN="ghp_your_token_here"
```

Permissions:

| Token | Needs |
|---|---|
| Classic PAT | `repo` and `workflow` scopes |
| Fine-grained PAT or GitHub App | **Contents** and **Workflows** read/write, **Metadata** read. Optional: **Secrets** read (secrets pre-check), **Administration** read (Actions policy pre-check). |
| `--dry-run` / `--detect-only` | Read access only |

- If your org uses SAML SSO, authorize the token for the org.
- For large orgs, use a GitHub App: it gets up to 15,000 calls/hour on GitHub Enterprise Cloud, compared with 5,000 for a PAT. App tokens last 1 hour, so pass `--token-command` with a command that prints a fresh one.
- **GitHub Enterprise Server:** `export GITHUB_API_URL=https://ghe.example.com/api/v3`. The `veracode/*` actions must be available on the instance.

-----

## 3. Add the Veracode secrets

Add these as repository or organization Actions secrets:

| Secret | Required |
|---|---|
| `VERACODE_API_ID`, `VERACODE_API_KEY` | Yes |
| `SRCCLR_API_TOKEN` | For SCA |
| `VERACODE_APP_NAME` | No. The application profile defaults to `org/repo`. |

Missing secrets don't stop the tool. They're listed as a TODO in the commit message.

-----

## 4. Install

```bash
git clone https://github.com/ancient-cthulhu/Veracode-Pipeline-Inject.git
cd Veracode-Pipeline-Inject
pip install -r requirements.txt
```

> On macOS/Linux, use `python3` if `python` isn't found.

-----

## 5. Run it (4 steps)

Replace `my-org` with your org. A target can be `my-org`, `my-org/repo`, `my-org/api-*`, or several separated by commas.

### Step 1: See which scans apply (no workflow read or changed)

```bash
python veracode_inject.py --target my-org --detect-only --report scans.csv
```

The `sast`, `sca` and `iac` columns show the decision, and the `*_reason` columns explain it. Fix exceptions in a [config file](#configuration).

### Step 2: Dry run (no changes made)

```bash
python veracode_inject.py --target my-org --dry-run --no-diff --report plan.csv
```

This runs the pre-checks (secrets, Actions policy, build detection) and prints the plan for every repo. Drop `--no-diff` to see the exact workflow diff. Skipped rows say why, and the `notes` column shows where the tool picked between equally likely workflows or build jobs.

### Step 3: Canary

```bash
python veracode_inject.py --target my-org --limit 20 --report rollout.csv
```

This stops after 20 repos have a commit on `veracode/integration`. In a few of them, read the TODO list in the commit message, open a PR from the branch, and check the run.

### Step 4: Everything else

```bash
python veracode_inject.py --target my-org --report rollout.csv --resume --quiet
```

-----

## 6. If the run stops partway

The report is written row by row. To continue, re-run the same command with `--resume`. Repos already completed in that report are skipped.

```bash
python veracode_inject.py --target my-org --report rollout.csv --resume
```

- Only rows from the same mode are skipped, so a dry-run report doesn't skip repos in a real run.
- An expired token stops the run with exit code 3. Re-run with `--resume`, and use `--token-command` for long runs.
- Rate limits don't stop the run: the tool waits and continues.

-----

## Configuration

Flags cover the whole run. A config file adds per-repo overrides ([full example](examples/veracode-inject.yml)):

```yaml
defaults:
  pipeline: true          # Pipeline Scan on branch pushes and PRs
  policy: true            # Policy Scan on the default branch
  iac: "on"               # on | artifacts | off
repos:
  "my-org/payments-*":    # glob on org/repo; later matches win
    workflow: build.yml
    build_job: package
    artifact_path: ["dist/*.war"]
```

```bash
python veracode_inject.py --target my-org --config veracode-inject.yml --dry-run
```

Command-line flags override the config.

-----

## Common options

| I want to... | Add this |
|---|---|
| Preview only, change nothing | `--dry-run` (`--no-diff` hides the diff) |
| Only see which scans apply | `--detect-only` |
| Work on a local workflow file | `--file .github/workflows/ci.yml` |
| Skip some repos | `--exclude "my-org/legacy-*"` |
| Only the Policy Scan, no PR scans | `--policy` |
| Pick the workflow or build job | `--workflow ci.yml`, `--build-job package` |
| Set the build output path | `--artifact-path "dist/*.war"` |
| Gate branch pushes on severity | `--branch-fail-on-severity "Very High, High"` |
| IaC/Secrets only where there's infrastructure code | `--iac artifacts` |
| Use another branch name | `--branch veracode/scans` |
| Pin actions to commit SHAs | `--pin-sha` |
| Undo | `--remove` |
| Log every API call | `--debug` |
| See every option | `--help` or the [README](README.md#cli-reference) |

-----

## Good to know

- **Additive only.** Every addition sits between `# >>> veracode-pipeline-inject` markers. The tool checks that your jobs parse exactly as before, and it never commits a file that fails this check.
- **Safe to re-run.** An unchanged repo gives no new commit. Hand edits inside a managed block (for example a fixed `path:`) are kept.
- **Branch safety.** The tool only updates its branch when every commit on it is the tool's. Otherwise the repo is skipped (`--force` overrides).
- **Build first.** SAST for compiled languages needs the build in the workflow. If the tool can't find it, SAST is off and the TODO says what's missing. Some languages need a specific build: see [languages with special packaging](README.md#languages-with-special-packaging).
- **Pushes to the branch don't run the workflow** unless it triggers on all pushes. Open a PR from the branch to test.
- **Throughput.** GitHub allows about 250 changed repos an hour (2 writes each). A dry run of about 1,000 repos an hour is possible with a PAT.
- **Packaging warnings never fail the build.** Check the **Veracode SAST prepare** job log.

-----

## Troubleshooting

| Error message | Fix |
|---|---|
| `token scopes ... cannot write workflow files` | `gh auth refresh -s workflow`, or add the `workflow` scope |
| `Stopped: GitHub rejected the token` | The token expired. Re-run with `--resume`, and use `--token-command` for GitHub App tokens. |
| `Stopped: the same error on 10 repositories in a row (HTTP 403 ...)` | The token lacks a permission (the message names it). Fix it, then `--resume`. |
| `skipped (several candidate workflows ...)` / `(several jobs ...)` | `--workflow` / `--build-job`, or set them per repo in the config |
| `skipped (already runs Veracode in ...)` | Keep the existing steps, or `--force` to add the managed jobs too |
| `branch ... has N commit(s) not made by this tool` | Use `--branch` with another name, or `--force` |
| `FAIL actions policy: only local actions allowed` | Allow `actions/*` and `veracode/*` in **Settings > Actions > General** |
| SAST `off` with a TODO about a build | Add the build to the workflow, or pass `--build-job` and `--artifact-path` |
| Packaging warning `No scannable build output found` | Fix `path:` in **Upload build output for Veracode** on the branch |
| Run is slow or pauses | Normal. The tool waits to stay within GitHub's rate limits. |

All messages: [README troubleshooting](README.md#troubleshooting).

-----

## Need help?

This is a community tool, not an official Veracode product, and it isn't covered by Veracode Technical Support. When asking for help, share:

- The `--report` CSV
- The exact command you ran
- The output of `--dry-run` for the affected repo
