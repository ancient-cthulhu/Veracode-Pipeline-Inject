# Veracode Pipeline Inject

> **Community tool.** Not an official Veracode product and not covered by Veracode Technical Support. Use it at your own discretion.

> See [QUICKSTART.md](QUICKSTART.md) for the fastest setup path.

Checks which Veracode scans make sense for each repository, then adds SAST, SCA and IaC/Secrets scanning to its existing GitHub Actions workflow, after the build, without changing the existing jobs. Works on a local file or across an org, and commits the result to a new branch for testing. How it decides: [docs/how-it-works.md](docs/how-it-works.md).

## Why use it

- **Per-repo scan selection, with the reason shown.** Language and manifest detection, adapted from [Workflow-App-per-Lang-Override](https://github.com/ancient-cthulhu/Workflow-App-per-Lang-Override), decides SAST, SCA and IaC per repo. It ignores stubs, tooling config, vendored code and framework scaffolding, and names unsupported languages instead of adding scans that would fail.
- **Additive only.** One upload step in the build job, plus its own jobs at the end. After every injection it checks that the client's jobs parse exactly as before, and never commits a file that fails this check.
- **Official Veracode actions:** Pipeline Scan, Upload and Scan, agent-based SCA, and IaC/Secrets scanning. Nothing to download or host.
- **[pipeline-examples](https://github.com/ancient-cthulhu/pipeline-examples) strategy by default:** Pipeline Scan on branch pushes and PRs (gated on `Veracode Recommended Very High`), Policy Scan on the default branch, SCA on PRs and merges, IaC/Secrets on every run.
- **Packaging checks on every run**, as warnings with a link to the packaging guide. They never fail the build.
- **Safe at scale.** Dry runs, a canary limit, resumable reports, rate-limit handling, idempotent re-runs, and `--remove` to undo.

> [!NOTE]
> Rolling out across a whole org without editing any workflow files? The [Veracode GitHub Workflow Integration](https://docs.veracode.com/r/GitHub_Workflow_Integration_for_Repo_Scanning) handles that centrally. This tool adds the scans to the repo's own workflow.

## Supported languages

Checked against Veracode's [Static Analysis supported languages](https://docs.veracode.com/r/r_supported_table) and [Pipeline Scan supported languages](https://docs.veracode.com/r/Pipeline_Scan_Supported_Languages).

| Language | Scanned from | Pipeline Scan | Policy Scan |
|---|---|---|---|
| Java, Kotlin, Scala, Groovy (incl. Grails, Android) | JAR/WAR/EAR/APK from Maven, Gradle, sbt, Ant or Grails | ✓ | ✓ |
| C#, VB.NET, ASP.NET, C++/CLI | `dotnet build`/`publish` or `msbuild` output with PDBs | ✓ | ✓ |
| C, C++ | make/CMake/Ninja binaries, or `.i`/`.ii` preprocessed source | ✓ | ✓ |
| Swift, Objective-C | `xcodebuild archive` + gen-ir (macOS job) | ✓ | ✓ |
| Ruby on Rails | Veracode RubyGem (`veracode prepare`) | ✓ | ✓ |
| ColdFusion | WAR from `cfcompile` (set `artifact_path`) | ✓ | ✓ |
| JavaScript, TypeScript, Vue (incl. React Native, Ionic) | Source | ✓ | ✓ |
| Python, PHP, Apex, COBOL | Source | ✓ | ✓ |
| Go | Source, one module per upload | ✓ | ✓ |
| Dart/Flutter | `flutter build apk --debug` | | ✓ |
| Perl, PL/SQL, T-SQL, Classic ASP, RPG, Visual Basic 6 | Source | | ✓ |

When a repo only has Policy Scan languages, only the Policy Scan is added. Not supported by Veracode SAST and reported as such: F#, Rust, Elixir, Svelte, CoffeeScript, VBA.

### Languages with special packaging

| Language | What the tool does | What you may need to do |
|---|---|---|
| Swift, Objective-C | Counts only with an Xcode project. Finds `xcodebuild ... archive` and zips each `.xcarchive`. | Add a macOS job that archives a Debug build with `DEBUG_INFORMATION_FORMAT=dwarf-with-dsym`, then runs [gen-ir](https://docs.veracode.com/r/compilation_apple_platforms). Swift packages without an Xcode project aren't scanned. |
| Dart/Flutter | Counts only for a Flutter app with `android/` or `ios/`. Finds `flutter build apk/ipa`. | Build with `--debug`. App bundles (`.aab`) aren't accepted ([Flutter packaging](https://docs.veracode.com/r/Dart_and_Flutter_Application_Packaging)). |
| Ruby | Counts only for Rails (`config/application.rb`). Finds `veracode prepare` and uploads `tmp/veracode-*.zip`. | Add the [Veracode RubyGem](https://docs.veracode.com/r/compilation_ruby) step in a job where the app can boot, with `config.cache_classes` and `config.eager_load` set to `false`. |
| Go | Packages one module (the shallowest `go.mod`) with `go mod vendor`, and leaves Go out of the shared source zip. | Scan the other modules (listed in the TODO) in their own application profiles. Remove `replace` directives. One upload should build one executable ([Go packaging](https://docs.veracode.com/r/compilation_go)). |
| C, C++ | Needs a make/CMake/Ninja/vcxproj build. No default output path. | Set `artifact_path` to binaries built with debug symbols, or to `.i`/`.ii` files plus `veracode.json` ([preprocessed source](https://docs.veracode.com/r/C_Cplus_preprocessed_source_packaging)). |
| Xamarin, .NET MAUI | Treated as .NET: uploads the build's DLL/EXE/PDB. | Build Debug and scan one target platform per profile. MAUI expects a flat zip of DLL and PDB files: set `artifact_path` to one platform's output ([MAUI](https://docs.veracode.com/r/NET_MAUI_Application_Packaging), [Xamarin](https://docs.veracode.com/r/compilation_xamarin)). |
| Cordova/PhoneGap | Scanned as JavaScript source. | Veracode expects the compiled APK or IPA: build it with `--debug` and set `artifact_path` ([Cordova](https://docs.veracode.com/r/compilation_phonegap)). |
| ColdFusion | Detected; no build is inferred. | Compile with `cfcompile -deploy`, package a WAR, and set `artifact_path` ([ColdFusion](https://docs.veracode.com/r/compilation_CF)). |
| Classic ASP | Scanned alone. With other languages in the repo, it's left out of the shared upload and a TODO is added. | Scan it in its own application profile. Veracode advises against uploading it with other languages or DLL/EXE files. |
| PL/SQL, T-SQL, VB6 | Count only with `.pkb`/`.pks`/`.pck`, a `.sqlproj`, or a `.vbp`/`.vbg` project | Plain `.sql` files need `sast: on` |
| Apex | Counts only with Salesforce project files (`sfdx-project.json`, `force-app/`, ...) | Nothing |

## What gets added

| Added | Runs when | Does |
|---|---|---|
| Step `Upload build output for Veracode` in the build job | After the build step | Uploads the build output. Skipped if the job already uploads it, and never fails the build (`if-no-files-found: warn`). |
| Job `veracode-prepare` | After the build job, except on fork PRs | Builds the scan units: each `.jar`/`.war`/`.ear`/`.apk`/`.ipa`/`.zip`, one zip per `.xcarchive`, one zip of `.dll`/`.exe`/`.pdb` files, preprocessed C/C++, a source zip, and the Go module. Runs the packaging checks. |
| Job `veracode-pipeline-scan` (`--pipeline`, default) | Push to a non-default branch, or a pull request | One Pipeline Scan per unit. PRs gate on `pr_gate_policy`; branch pushes fail on any flaw unless `branch_fail_on_severity` is set. |
| Job `veracode-policy-scan` (`--policy`, default) | Push to the default branch | Upload and Scan of all units into the application profile `VERACODE_APP_NAME` (or `org/repo`). Never cancelled once started. |
| Job `veracode-sca` | PRs into the default branch, and pushes to it | Agent-based SCA. Non-blocking unless `sca_blocking`. Runs on `windows_runner` for Windows-only .NET/C++ builds. |
| Job `veracode-iac` | Every run, except fork PRs | IaC and secrets scan of the checkout. Non-blocking unless `iac_blocking`. |

Only the jobs that apply are added. The reason for each decision is printed, written to the report and included in the commit message ([rules](docs/how-it-works.md#1-which-scans-apply)).

### Secrets

| Secret | Required | Notes |
|---|---|---|
| `VERACODE_API_ID` | Yes | [API credentials](https://docs.veracode.com/r/c_api_credentials3), preferably an API service account |
| `VERACODE_API_KEY` | Yes | |
| `SRCCLR_API_TOKEN` | For SCA | [SCA agent token](https://docs.veracode.com/r/Manage_agents_and_scans) |
| `VERACODE_APP_NAME` | No | Application profile name. Defaults to `org/repo`. |

Repository or organization secrets both work. Fork PRs don't receive secrets, so the Veracode jobs skip them.

### After the branch is created

1. Read the TODO list in the commit message on `veracode/integration`, and add any missing secrets.
2. If the build writes its output somewhere else, fix the `path:` in **Upload build output for Veracode** on the branch. The tool keeps that edit ([managed blocks](docs/how-it-works.md#5-managed-blocks)).
3. Open a PR from the branch into the default branch. The PR run executes the Pipeline Scan gate and SCA.
4. Check the **Veracode SAST prepare** log for packaging warnings, then merge. The first push to the default branch runs the Policy Scan.

## Example output

`--detect-only` against public repositories:

```text
== exelban/stats: detected
   SAST  on   languages: C, C++, Objective-C, Python, Swift
   SCA   off  off: no supported dependency manifest (only Makefile, not resolvable on their own); Makefile builds with Xcode (macOS); the agent's Make build runs on Linux
   IaC   on   no IaC files, kept on for secret scanning

== git/git: detected
   SAST  on   languages: C, C++, JavaScript, Perl (Policy Scan only), Python; not scanned: Rust (not supported by Veracode SAST)
   SCA   on   manifests: Makefile (c/c++ make)
   IaC   on   no IaC files, kept on for secret scanning

== jekyll/jekyll: detected
   SAST  on   languages: JavaScript; not scanned: CoffeeScript (not supported by Veracode SAST), Ruby (not a Rails app; Veracode scans Ruby on Rails only)
   SCA   on   manifests: Gemfile (ruby)
   IaC   on   artifacts: Dockerfile

== terraform-aws-modules/terraform-aws-vpc: detected
   SAST  off  off: no language Veracode SAST supports (found HCL)
   SCA   off  off: no supported dependency manifest
   IaC   on   artifacts: main.tf, outputs.tf, variables.tf, versions.tf
```

A dry run (`--dry-run --no-diff`) against a Rails app:

```text
== discourse/discourse: would_change
   SAST  on   languages: JavaScript, Ruby, TypeScript
   SCA   on   manifests: Gemfile, Gemfile.lock, package.json, pnpm-lock.yaml (javascript, ruby)
   IaC   on   no IaC files, kept on for secret scanning
   workflow: .github/workflows/tests.yml | SAST source (after build) [pipeline+policy] | SCA on | IaC on
   INFO  build: source-code SAST after `build`
   INFO  branch: veracode/integration will be created
   TODO  SAST for Ruby needs the Veracode RubyGem: `veracode prepare` in a job where the Rails app can boot (writes tmp/veracode-*.zip) in this workflow. Re-run with --build-job/--artifact-path (https://docs.veracode.com/r/compilation_ruby)
```

The diff for GitHub's Maven starter workflow (excerpt):

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

## CLI reference

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
| `--branch` | `veracode/integration` | Branch to commit to. Created from the default branch if it doesn't exist. |
| `--workflow` | auto | Workflow file name or glob to change |
| `--build-job`, `--build-step` | auto | Job (and step) that builds the code |
| `--artifact-path` | from the build tool | `upload-artifact` path line. Repeatable; `!pattern` excludes. |
| `--pr-gate-policy` | `Veracode Recommended Very High` | Policy for PR Pipeline Scans. Empty disables the gate. |
| `--branch-fail-on-severity` | any flaw | For example `"Very High, High"` for branch-push Pipeline Scans |
| `--runner` | `ubuntu-latest` | `runs-on` for the Veracode jobs. Needs `bash`, `python3` and `git`. |
| `--pipeline`, `--policy` | both | Which SAST scans to add. Passing one selects only that one. |
| `--sast` / `--sca` | `auto` | `auto`, `on` or `off` |
| `--iac` | `on` | `on` (every repo: secret scanning), `artifacts` (only repos with IaC/container files), or `off` |
| `--windows-runner` | `windows-latest` | `runs-on` for SCA in Windows-only .NET/C++ repos. `off` keeps `--runner`. |
| `--deep-dotnet` | off | Read up to 5 .NET project files per repo to find Windows-only builds |
| `--sca-blocking`, `--iac-blocking` | off | Fail the run on findings |
| `--config` | | YAML file with defaults and per-repo overrides |
| `--pin-sha` | off | Pin the actions to commit SHAs (targets only) |
| `--remove` | off | Remove the managed blocks |
| `--strict` | off | Skip repos where several workflows or build jobs rank equally, instead of picking the first and noting it |
| `--force` | off | Overwrite hand-edited managed blocks, add the jobs next to existing Veracode steps, or add to a branch with other commits |
| `--exclude`, `--include-forks` | | Filter the repositories that an org or pattern target matches |
| `--report` | | CSV report, written row by row (targets only) |
| `--resume` | off | With `--report`: skip repositories already completed in that report and append to it |
| `--limit` | | Stop after changing N repositories (canary) |
| `--token-command` | | Command that prints a GitHub token. Run at the start and again when the token expires. |
| `--writes-per-hour` | 500 | Content-creating requests per hour. Lower it when other automation shares the account. |
| `--quiet` | off | One line per repository |
| `--debug` | off | Log every API request (never the token) and print tracebacks for internal errors |
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

Command-line flags override the config. Example: [examples/veracode-inject.yml](examples/veracode-inject.yml).

## GitHub API use

| Per repository | Calls |
|---|---|
| `--detect-only` | 1 REST + 1 GraphQL |
| `--dry-run` | About 4 REST + 1 GraphQL, whatever the number of workflow files |
| Real run | The same, plus 2 writes for each repo that changes |

The summary and the report's `api_calls` column show the real cost. If GraphQL isn't available (older GHES, a proxy), the tool falls back to REST, which costs one call per workflow file.

| Limit | Value | Effect |
|---|---|---|
| REST | 5,000/hour (PAT), up to 15,000/hour (GitHub App on GHEC) | About 1,000 repos/hour for a dry run with a PAT |
| GraphQL | Separate hourly budget | 1 point per repo |
| Content creation | 80 a minute, 500 an hour | About **250 changed repos/hour** at most |

How the client reacts:

| Situation | Behavior |
|---|---|
| Primary limit nearly used, or 403/429 with `remaining: 0` | Waits until `x-ratelimit-reset` (using the server's clock) |
| Secondary limit | Waits `Retry-After`, else 60 s doubling to 15 minutes, with jitter |
| 5xx, timeouts, dropped connections | Up to 3 retries |
| 401 | With `--token-command`, gets a new token and retries once; otherwise stops (exit 3) |
| 403 permission, 404, 422 | Not retried. A 403 names the missing permission. The same 403 on 10 repos in a row stops the run (exit 3). |
| A retried write that already succeeded | Verified on the branch instead of being reported as failed |

Requests are serial: the hourly and content-creation limits bound a run, and parallel workers would only hit secondary limits.

**GitHub Enterprise Server:** set `GITHUB_API_URL=https://ghe.example.com/api/v3` (`GITHUB_GRAPHQL_URL` overrides the derived GraphQL URL). If rate limiting is disabled on the server, `/rate_limit` answers 404, and the tool says so. `--pin-sha` resolves SHAs on github.com without sending the GHES token there.

**Security:**
- The token is only sent to `GITHUB_API_URL` and is never printed, logged or written to reports.
- Repository content is parsed with PyYAML's safe loader and never executed. Alias bombs are rejected.
- The tool writes only to its own branch.
- Injected jobs have `permissions: contents: read`, skip fork PRs, and pass secrets only through `with:`/`env:`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Every repository was committed, is up to date, would change (dry run) or was detected |
| 1 | At least one repository was skipped or failed. The output says why. |
| 2 | Usage, config or detection error |
| 3 | GitHub API error: authentication failed, the token expired mid-run, or the same 403 hit 10 repositories in a row (re-run with `--resume`) |
| 130 | Interrupted (Ctrl+C). Re-run with `--resume`. |

## Troubleshooting

| What you see | Why | Fix |
|---|---|---|
| `note: Workflow X picked over Y` | Several workflows ranked equally; the tool took the first | Check it on the branch, or set `workflow:` per repo in the config |
| `note: Build job X picked over Y` | Several jobs build the code; Linux and non-release jobs win | `build_job:` in the config |
| `skipped (several candidate workflows ...)` / `(several jobs ...)` | Same as the two notes, with `--strict` | `--workflow` / `--build-job`, or per repo in the config |
| `skipped (only reusable workflows ...)` | `workflow_call` workflows only get the secrets their callers pass | `workflow:` set to the caller workflow |
| `skipped (already runs Veracode in ...)` | The repo already has Veracode steps | Keep them, or `--force` to add the managed jobs too |
| `skipped (a managed block was edited by hand ...)` | Someone changed a block on the branch | The edit is kept. `--force` regenerates the block. |
| `token scopes ... cannot write workflow files` | The token is missing `workflow` | `gh auth refresh -s workflow` |
| `branch ... has N commit(s) not made by this tool` | Someone else uses the branch | `--branch` with another name, or `--force` |
| `... differs from main outside the managed blocks` | The workflow changed on the default branch after the tool's branch was made | Merge the default branch into the tool's branch, delete the branch, or `--force` |
| `failed (repository not found or no access)` | Misspelled `org/repo`, or the token can't see it | Fix the target. The rest of the run continues. |
| `Stopped: GitHub rejected the token` | The token expired (GitHub App tokens last 1 hour) | `--resume`, and `--token-command` for long runs |
| `Stopped: the same error on 10 repositories in a row (HTTP 403 ...)` | The token lacks a permission everywhere | Fix the token, then `--resume` |
| `... pacing writes (500 content-creating requests an hour)` | GitHub's content-creation limit | Expected on large rollouts |
| `... GraphQL API unavailable; using REST only` | The server or a proxy rejects GraphQL | Nothing; the run continues over REST |
| `FAIL actions policy: only local actions allowed` | The policy blocks marketplace actions | Allow `actions/*` and `veracode/*` in **Settings > Actions > General** |
| SAST `off` with a TODO about a build | Compiled language, but no matching build in the workflow | Add the build ([special packaging](#languages-with-special-packaging)), or `--build-job` plus `--artifact-path` |
| `not scanned: Ruby (not a Rails app ...)`, `Swift (no Xcode project ...)`, `Dart (not a Flutter mobile app ...)` | Veracode scans only those project types | Nothing to do |
| `SAST off ... below 200 bytes (stub)` | Under 200 bytes of code is treated as a stub | `--sast on` if it really is the application |
| `TODO N Go modules; only X is scanned` | Veracode takes one Go module per upload | Scan the listed modules in their own application profiles |
| `SCA off ... only Podfile` (or `global.json`, `Cargo.toml`, `pubspec.yaml`) | The agent doesn't support it, or can't resolve it on Linux (`Podfile` needs `Podfile.lock`) | `--sca on` to force it |
| `SCA off ... Makefile has no gcc/g++/clang/CMake build or no clean target` | The agent's C/C++ scan builds with that Makefile | Add them, or `--sca on` with `SRCCLR_MAKE_CLEAN_TARGET` / `SRCCLR_MAKE_BUILD_TARGET` ([C/C++ requirements](https://docs.veracode.com/r/Find_vulnerabilities_in_Cplus)) |
| Packaging warning `No scannable build output found` | The upload path matched nothing | Fix `path:` in **Upload build output for Veracode** |
| Packaging warning `No .pdb files` | .NET built without symbols | Publish with portable PDBs ([.NET packaging](https://docs.veracode.com/r/compilation_net)) |
| Packaging warning `go.mod uses replace directives` | Veracode can't resolve them | Remove them for the scan |
| `veracode-policy-scan` rejected | A previous scan for the profile is still running | Wait for it, or cancel it in the Veracode Platform |

## Files

| File | Purpose |
|---|---|
| `veracode_inject.py` | The tool (single file) |
| `QUICKSTART.md` | Setup and first run |
| `docs/how-it-works.md` | Detection, placement, packaging, managed blocks, branch rules |
| `examples/veracode-inject.yml` | Example config |
| `requirements.txt` | PyYAML |
