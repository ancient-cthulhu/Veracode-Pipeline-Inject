# Veracode Pipeline Inject

> **Community tool.** Not an official Veracode product and not covered by Veracode Technical Support. Use it at your own discretion.

Checks which Veracode scans make sense for each repository, then adds SAST, SCA and IaC/Secrets scanning to its existing GitHub Actions workflow, after the build, without changing the existing jobs. Works on a local file or across an org, and commits the result to a new branch for testing. How it decides: [docs/how-it-works.md](docs/how-it-works.md).

**Start here:** [Quick start](#quick-start) · [What gets added](#what-gets-added) · [How it works](docs/how-it-works.md) · [Example config](examples/veracode-inject.yml) · [Troubleshooting](#troubleshooting)

## Why use it

- **Per-repo scan selection, with the reason shown.** Language and manifest detection, adapted from [Workflow-App-per-Lang-Override](https://github.com/ancient-cthulhu/Workflow-App-per-Lang-Override), decides SAST, SCA and IaC per repo. It ignores stubs, tooling config, vendored code and framework scaffolding. It names unsupported languages instead of adding scans that would fail, and it runs SCA on a Windows runner for Windows-only .NET builds. `--detect-only` reports this across an org without changing anything.
- **Additive only.** It adds one upload step to the build job and appends its own jobs. After every injection it checks that the parsed workflow is unchanged apart from those additions, and it never commits a file that fails this check.
- **Uses the official Veracode actions:** Pipeline Scan, Upload and Scan, agent-based SCA, and IaC/Secrets scanning. There's nothing to download or host.
- **Pick the SAST scans per repo.** By default you get the [pipeline-examples](https://github.com/ancient-cthulhu/pipeline-examples) strategy: Pipeline Scan on branch pushes and PRs (gated on `Veracode Recommended Very High`), and Policy Scan on the default branch. `--pipeline`, `--policy` and `--sandboxes` choose which ones run; `--sandboxes` adds a sandbox scan for each PR into the default branch. SCA runs on PRs and merges to the default branch, IaC/Secrets on every run, and neither blocks the build.
- **Packaging checks on every run:** missing `.pdb` files, classes compiled without debug info, test code in the build output, minified-only JavaScript, and files over the upload limit. Each shows as a warning with a link to the packaging guide and never fails the build.
- **Safe at scale.** Targets can be `org`, `org/repo` or `org/pattern*`. `--dry-run` runs the pre-checks (secrets, Actions policy, build detection) and shows the diff. Changes go to a branch (`veracode/integration` by default) and the commit message lists what the repo owner still needs to do. Re-runs are idempotent, and `--remove` undoes the change exactly.

> [!NOTE]
> Rolling out across a whole org without editing any workflow files? The [Veracode GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning) handles that centrally. This tool adds the scans to the repo's own workflow.

## Quick start

```bash
git clone https://github.com/ancient-cthulhu/Veracode-Pipeline-Inject.git
cd Veracode-Pipeline-Inject
pip install -r requirements.txt          # PyYAML; Python 3.10+
gh auth login -s workflow                # or export GH_TOKEN (repo + workflow scopes)
python veracode_inject.py --target my-org --dry-run
```

Writing a workflow file needs a token with the `repo` and `workflow` scopes; a fine-grained token needs **Contents** and **Workflows** read/write. `--dry-run` only needs read access. The token comes from `GH_TOKEN`, then `GITHUB_TOKEN`, then `gh auth token`. For GitHub Enterprise Server, set `GITHUB_API_URL` (for example `https://ghe.example.com/api/v3`).

## Examples

Which scans make sense in each repo, without touching workflows (CSV with the reasons):

```bash
python veracode_inject.py --target my-org --detect-only --report scans.csv
```

Dry run of a whole org: pre-checks and plan for every repo, no diffs, plus a CSV report:

```bash
python veracode_inject.py --target my-org --dry-run --no-diff --report plan.csv
```

Some repos in one org, all repos in another, skipping a few:

```bash
python veracode_inject.py --target "my-org/payments-*,other-org" --exclude "my-org/payments-legacy" --dry-run
```

Commit to the `veracode/integration` branch in every matching repo:

```bash
python veracode_inject.py --target "my-org/payments-*"
```

Policy scan on the default branch plus a sandbox scan for every PR into it, without Pipeline Scan:

```bash
python veracode_inject.py --target "my-org/payments-*" --policy --sandboxes
```

One repo, with the build job, the build output and a stricter branch gate set by hand:

```bash
python veracode_inject.py --target my-org/api --build-job package --artifact-path "dist/*.war" \
  --branch-fail-on-severity "Very High, High"
```

Per-repo settings from a config file ([example](examples/veracode-inject.yml)):

```bash
python veracode_inject.py --target my-org --config veracode-inject.yml
```

A local workflow file, edited in place (the language detection reads the file's repository):

```bash
python veracode_inject.py --file .github/workflows/maven.yml --dry-run
python veracode_inject.py --file .github/workflows/maven.yml
```

Undo, either on the branch or locally:

```bash
python veracode_inject.py --target my-org/api --remove
python veracode_inject.py --file .github/workflows/maven.yml --remove
```

Real output: `--detect-only` against public repositories:

```text
== flutter-team-archive/gallery: detected
   SAST  on   languages: Ruby; not scanned: Dart (no Pipeline Scan support); ignored C, C++, Kotlin, Swift (tooling/scaffolding files only)
   SCA   off  off: no supported dependency manifest (only pubspec.lock, pubspec.yaml, not resolvable on their own)
   IaC   on   no IaC files, kept on for secret scanning

== ShareX/ShareX: detected
   SAST  on   languages: C#
   SCA   on   manifests: ShareX.Avalonia.csproj, ShareX.HelpersLib.csproj, ShareX.HistoryLib.csproj, ShareX.Icons.csproj, ShareX.ImageEditor.App.csproj (dotnet)
   IaC   on   no IaC files, kept on for secret scanning
   SCA runner: windows-latest (Windows build signals: ShareX.HelpersLib/ShareX.HelpersLib.csproj (Windows-only project))

== terraform-aws-modules/terraform-aws-vpc: detected
   SAST  off  off: no Pipeline Scan language (found HCL)
   SCA   off  off: no supported dependency manifest
   IaC   on   artifacts: main.tf, outputs.tf, variables.tf, versions.tf
```

Real output: a dry run against two public repositories (no admin access, so secrets and the Actions policy can't be read):

```text
== dotnet-architecture/eShopOnWeb: would_change
   SAST  on   languages: C#
   SCA   on   manifests: ApplicationCore.csproj, BlazorAdmin.csproj, BlazorShared.csproj, FunctionalTests.csproj, Infrastructure.csproj (dotnet)
   IaC   on   artifacts: .dockerignore, Dockerfile, appservice.bicep, appserviceplan.bicep
   workflow: .github/workflows/dotnetcore.yml | SAST binary (build: .NET build) | SCA on | IaC on
   PASS  workflow: .github/workflows/dotnetcore.yml
   WARN  secrets: cannot list secrets (needs admin access); check them manually
   WARN  actions policy: cannot read Actions permissions; check manually
   PASS  build: job `build`, step "Build with dotnet"
   INFO  note: .NET: scan a `dotnet publish` output with .pdb files for best results
   INFO  branch: veracode/integration will be created
   TODO  Make sure these Actions secrets exist: VERACODE_API_ID, VERACODE_API_KEY, SRCCLR_API_TOKEN (https://docs.veracode.com/r/t_create_api_creds)
   TODO  Check the build output path in step "Upload build output for Veracode" (job `build`): it uses the .NET build defaults. Packaging guide: https://docs.veracode.com/r/compilation_packaging

== spring-projects/spring-petclinic: skipped (several candidate workflows (.github/workflows/gradle-build.yml, .github/workflows/maven-build.yml); set `workflow` in the config or --workflow)
   SAST  on   languages: Java
   SCA   on   manifests: build.gradle, pom.xml, settings.gradle (java)
   IaC   on   artifacts: Dockerfile, docker-compose.yml, k8s/db.yml, k8s/petclinic.yml

Summary: skipped 1, would_change 1
```

The diff it shows for GitHub's Maven starter workflow (excerpt):

```diff
     - name: Build with Maven
       run: mvn -B package --file pom.xml
+    # >>> veracode-pipeline-inject >>> managed block: re-run the tool to update it
+    - name: Upload build output for Veracode
+      uses: actions/upload-artifact@v7
+      with:
+        name: veracode-build-${{ strategy.job-index }}
+        path: |
+          **/target/*.jar
+          **/target/*.war
+          **/target/*.ear
+          !**/target/*-sources.jar
+          !**/target/*-javadoc.jar
+          !**/target/*-tests.jar
+        if-no-files-found: warn
+        retention-days: 3
+    # <<< veracode-pipeline-inject <<< 5c87562f7d4e
```

## What gets added

| Added | Runs when | Does |
|---|---|---|
| Step `Upload build output for Veracode` in the build job | After the build step | Uploads the build output. It's skipped if the job already uploads its build output, and it never fails the build (`if-no-files-found: warn`). |
| Job `veracode-prepare` | After the build job, except on fork PRs | Collects the scan units: each `.jar`/`.war`/`.ear`/`.apk`, one zip of `.dll`/`.exe`/`.pdb` files, and a source zip for JS/TS, Python, Go, PHP and Ruby. Runs the packaging checks. |
| Job `veracode-pipeline-scan` (`--pipeline`, default) | Push to a non-default branch, or a pull request | One Pipeline Scan per unit. On PRs, the `pr_gate_policy` policy is the gate. On branch pushes any flaw fails the job, unless `branch_fail_on_severity` is set. |
| Job `veracode-policy-scan` (`--policy`, default) | Push to the default branch | Upload and Scan of all units into the application profile `VERACODE_APP_NAME` (or `org/repo`). Never cancelled once started. |
| Job `veracode-sandbox-scan` (`--sandboxes`) | Pull request into the default branch | Upload and Scan into a sandbox named after the PR's source branch (created if missing). A newer commit replaces an unfinished scan in that sandbox. Submits the scan without waiting for results. |
| Job `veracode-sca` | PRs into the default branch, and pushes to it | Agent-based SCA. Non-blocking unless `sca_blocking` is set. Runs on `windows_runner` when the repo has a Windows-only .NET/C++ build. |
| Job `veracode-iac` | Every run (all pushes and PRs), except fork PRs | IaC and secrets scan of the checkout. Non-blocking unless `iac_blocking` is set. |

The tool adds only the jobs that apply: SAST when a supported language and a build are found, SCA when a dependency manifest is found, and IaC/Secrets always (or only with IaC files when `--iac artifacts` is set). The reason for each decision is printed, written to the CSV report and included in the commit message ([rules](docs/how-it-works.md#1-which-scans-apply)). Each addition sits between `# >>> veracode-pipeline-inject` and `# <<<` markers.

### Secrets

| Secret | Required | Notes |
|---|---|---|
| `VERACODE_API_ID` | Yes | [API credentials](https://docs.veracode.com/r/t_create_api_creds), preferably an API service account |
| `VERACODE_API_KEY` | Yes | |
| `SRCCLR_API_TOKEN` | For SCA | [SCA agent token](https://docs.veracode.com/r/t_sc_cli_agent) |
| `VERACODE_APP_NAME` | No | Application profile name. Defaults to `org/repo` |

Repository or organization secrets both work. Fork PRs don't receive secrets, so the Veracode jobs skip them.

## After the branch is created

1. Read the TODO list in the commit message on `veracode/integration`.
2. Add any missing secrets.
3. If the build writes its output somewhere else, fix the `path:` in **Upload build output for Veracode** on the branch. The tool keeps your edit (see [Managed blocks](docs/how-it-works.md#managed-blocks)).
4. Open a PR from the branch into the default branch. The PR run executes the selected PR scans: the Pipeline Scan gate and/or the sandbox scan, plus SCA.
5. Check the **Veracode SAST prepare** log for packaging warnings, then merge. The first push to the default branch runs the policy scan.

## Targets and flags

| Target | Meaning |
|---|---|
| `my-org` | Every non-archived, non-fork repository the token can see. Works for user accounts too. |
| `my-org/api` | One repository |
| `my-org/api-*` | Glob on the repository name (`*`, `?`, `[...]`). Wildcards aren't supported in the owner. |
| `a,b` or repeated `--target` | Several targets. Duplicates are merged. |

| Flag | Default | Description |
|---|---|---|
| `--target` / `--file` | | Targets on GitHub, or one local workflow file (one of the two is required) |
| `--detect-only` | off | Only report which scans apply and why. No workflow is read or changed. |
| `--dry-run` | off | Run the pre-checks and show diffs without writing anything |
| `--no-diff` | off | With `--dry-run`, print the plan and checks only |
| `--branch` | `veracode/integration` | Branch to commit to. It's created from the default branch if it doesn't exist. |
| `--workflow` | auto | Workflow file name or glob to change |
| `--build-job`, `--build-step` | auto | Job (and step) that builds the code |
| `--artifact-path` | from the build tool | `upload-artifact` path line. Repeatable, and `!pattern` excludes. |
| `--pr-gate-policy` | `Veracode Recommended Very High` | Policy for PR Pipeline Scans. Empty disables the gate. |
| `--branch-fail-on-severity` | any flaw | For example `"Very High, High"` for branch-push Pipeline Scans |
| `--runner` | `ubuntu-latest` | `runs-on` for the Veracode jobs. Needs `bash`, `python3` and `git`. |
| `--pipeline`, `--policy`, `--sandboxes` | pipeline + policy | Which SAST scans to add. Passing any of them selects exactly those. |
| `--sast` / `--sca` | `auto` | `auto`, `on` or `off` |
| `--iac` | `on` | `on` (every repo: secret scanning), `artifacts` (only repos with IaC/container files), or `off` |
| `--windows-runner` | `windows-latest` | `runs-on` for SCA in Windows-only .NET/C++ repos. `off` keeps `--runner`. |
| `--deep-dotnet` | off | Read up to 5 .NET project files per repo to find Windows-only builds, even without a weak signal |
| `--sca-blocking`, `--iac-blocking` | off | Fail the run on findings |
| `--config` | | YAML file with defaults and per-repo overrides |
| `--pin-sha` | off | Pin the actions to commit SHAs (targets only) |
| `--remove` | off | Remove the managed blocks |
| `--force` | off | Overwrite hand-edited managed blocks, or add the jobs next to existing Veracode steps |
| `--exclude`, `--include-forks` | | Filter the repositories that an org or pattern target matches |
| `--report` | | CSV report of every repository with plan, TODOs and the reason for each scan (targets only) |
| `--source-dir`, `--out` | | Local mode: repo root for detection, and output file |

### Config file

```yaml
defaults:
  branch: veracode/integration
  pr_gate_policy: Veracode Recommended Very High
  branch_fail_on_severity: ""        # empty = any flaw fails branch pushes
  runner: ubuntu-latest
  sast: auto                         # auto | on | off
  pipeline: true                     # Pipeline Scan: branch pushes + PRs
  policy: true                       # Policy Scan: pushes to the default branch
  sandboxes: false                   # Sandbox scan: PRs into the default branch
  sca: auto
  iac: "on"                          # on | artifacts | off
  windows_runner: windows-latest     # SCA runner for Windows-only .NET/C++ builds; "off" disables
  sca_blocking: false
  iac_blocking: false
  retention_days: 3
repos:
  "my-org/payments-*":               # glob on org/repo; later matches win
    workflow: build.yml
    build_job: package
    artifact_path: ["dist/*.war"]
```

Command-line flags override the config.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every repository was committed, is already up to date, would change (dry run) or was detected (`--detect-only`) |
| 1 | At least one repository was skipped or failed. The output says why. |
| 2 | Usage, config or detection error |
| 3 | GitHub API error, such as authentication or no access |

## Troubleshooting

| What you see | Why | Fix |
|---|---|---|
| `skipped (several candidate workflows ...)` | More than one workflow builds the code | `--workflow ci.yml`, or `workflow:` per repo in the config |
| `skipped (several jobs build the code ...)` | More than one job in the workflow builds the code | `--build-job <id>`, or `build_job:` in the config |
| `skipped (already runs Veracode in ...)` | The repo already has Veracode steps | Keep them, or use `--force` to add the managed jobs as well |
| `skipped (a managed block was edited by hand ...)` | Someone changed a block on the branch, for example its `path:` | That edit is kept. Use `--force` to regenerate the block. |
| `token scopes ... cannot write workflow files` | The token is missing `workflow` | `gh auth refresh -s workflow` |
| `FAIL actions policy: only local actions allowed` | The org or repo policy blocks marketplace actions | Allow `actions/*` and `veracode/*` in **Settings > Actions > General** |
| Packaging warning `No scannable build output found` | The upload path matched nothing | Fix `path:` in **Upload build output for Veracode** |
| Packaging warning `No .pdb files` | .NET built without symbols | Publish with portable PDBs ([.NET packaging](https://docs.veracode.com/r/compilation_net)) |
| `veracode-policy-scan` rejected | A previous scan for the profile is still running | Wait for it to finish, or cancel it in the Veracode Platform |
| `veracode-sandbox-scan` fails to create the sandbox | The application profile has reached its sandbox limit | Delete sandboxes of merged or closed PRs in the Veracode Platform. Sandboxes aren't removed automatically. |
| `SAST off ... below 200 bytes (stub)` | The language has under 200 bytes of code, so it's treated as a stub | `--sast on` if it really is the application |
| `SCA off ... only Gemfile` (or `global.json`, `pubspec.yaml`) | That manifest isn't resolvable by the agent setup on its own | `--sca on` to force it |
| SAST `off` with a TODO about a build step | Compiled language, but no Maven, Gradle, sbt, Ant, dotnet, msbuild or make step was found | `--build-job` plus `--artifact-path` |

## Files

| File | Purpose |
|---|---|
| `veracode_inject.py` | The tool (single file) |
| `examples/veracode-inject.yml` | Example config |
| `docs/how-it-works.md` | Detection, placement, packaging checks, managed blocks |
| `requirements.txt` | PyYAML |
