# How it works

For each repository (or for the local file with `--file`), the tool goes through these steps:

1. **Detect** which scans apply, from the default branch's file tree, file sizes and GitHub language stats. `--detect-only` stops here.
2. **Read** the workflows under `.github/workflows/`. If the branch already exists, it reads them from the branch, so edits made there are kept.
3. **Choose** the workflow to change, and the build job and step in it.
4. **Plan** what to add: the SAST mode, the upload step, the jobs, and the TODOs.
5. **Inject** the additions as text, then check that the client's jobs parse exactly as before.
6. **Pre-check** the secrets, the Actions policy and the branch state.
7. **Write:** create the branch if needed and commit the file with a TODO list in the message. With `--dry-run`, it prints the diff instead and writes nothing.

## 1. Which scans apply

Detection runs first, on the default branch, before any workflow is read. `--detect-only` stops here. The rules are a standalone copy adapted from [Workflow-App-per-Lang-Override](https://github.com/ancient-cthulhu/Workflow-App-per-Lang-Override), so both tools follow the same rules (differences listed below).

**Languages** combine GitHub Linguist byte counts and an extension scan of the tree:

| Rule | Effect |
|---|---|
| Under 200 bytes of a language | Treated as a stub. It doesn't enable SAST, and the reason names it (`below 200 bytes (stub): Java 195 B`). |
| Vendored and build paths (`node_modules/`, `vendor/`, `dist/`, `build/`, `target/`, `bin/`, `obj/`, virtualenvs, ...) | Ignored. `env/` and `external/` are ignored for languages only. |
| Generated and minified files (`.min.js`, `.d.ts`, `.pb.go`, `.designer.cs`, ...) | Ignored |
| Tooling config (`webpack.config.js`, `jest.config.ts`, `build.gradle.kts`, ...) | Not counted. A language made only of these is reported as `ignored ... (tooling/scaffolding files only)`. |
| Framework scaffolding (`android/`, `ios/`, ... next to `pubspec.yaml`, `metro.config.js`, `capacitor.config.*` or `ionic.config.json`) | Not counted, so a Flutter, React Native or Ionic app doesn't enable Kotlin, Swift or C++ |
| Ambiguous extensions | `.m` needs Apple project files, `.h` needs C/C++ sources, Apex files need Salesforce files, VB6 files (and `.cls` without Salesforce files) need a `.vbp`/`.vbg`, and `.pls`/`.prc`/`.fnc` need a `.pkb`/`.pks`/`.pck` |

**Decisions:**

| Scan | On when | Off (reason shown) when |
|---|---|---|
| SAST | Any language in the [README table](../README.md#supported-languages), in the project shape Veracode scans: Swift/Objective-C with an Xcode project, Dart in a Flutter mobile app, Ruby in a Rails app, C/C++ with Makefile/CMake/Meson/Ninja/vcxproj, T-SQL with a `.sqlproj` | Only unsupported languages (F#, Rust, Elixir, Svelte, CoffeeScript, VBA, HCL, ...), or supported languages outside those shapes. The reason names each one. |
| SCA | Anything the [SCA agent supports](https://docs.veracode.com/r/Agent_Based_Scans): Java/Kotlin (Maven, Gradle, Ant/Ivy, jars), Scala (sbt), JavaScript/TypeScript (npm, Yarn, pnpm, Bower), Python (pip, Pipenv, Poetry, `pyproject.toml`), Go (modules, dep, Glide, GoDep, GoVendor, Trash), PHP (Composer), Ruby (Bundler: `Gemfile`), Swift/Objective-C (CocoaPods: `Podfile.lock`), .NET (project files, `packages.config`), C/C++ (Make: a makefile with gcc/g++/clang/CMake and a `clean` target, read to confirm) | Only supporting files (`global.json`, `Directory.Build.props`, `setup.cfg`, `.sln`, `gradlew`, `Podfile` without its lock file, ...), ecosystems the agent doesn't support (`Cargo.toml`, `pubspec.yaml`, `mix.exs`, `Package.swift`, Conan, vcpkg), or a makefile that drives Xcode or lacks the compiler string or `clean` target. A C/C++ Make build in a Windows-only repo stays off (the agent builds with Make on Linux). Build-tool wrapper jars don't count. |
| IaC/Secrets | Always (`--iac on`), because secrets can be anywhere | `--iac artifacts`: only when Terraform, Dockerfiles, Helm/Kubernetes, CloudFormation/SAM, Bicep, Pulumi or Ansible files exist (YAML/JSON counts under `infra/`, `k8s/`, `deploy/`, ...). `--iac off`: never. |
| SCA runner | `windows_runner` when the repo has Windows-only .NET/C++ signals (`packages.config`, WebForms files, `.vcxproj`, `.sqlproj`, ...), or when a project file declares `net4x`, `*-windows`, WPF or WinForms | Weak signals (`App.xaml`, `web.config`, `.vbproj`) trigger a read of up to 5 project files (`--deep-dotnet` reads them always). SDK-style `net8.0` stays on Linux, MAUI's OS-conditioned TFMs don't count, and Windows-like files in a repo without .NET/C++ code don't count. |

- **Truncated trees** (very large repos) fail open: SAST and SCA stay on, and the reason says so.
- **Overrides:** `sast: on|off` and `sca: on|off` (per repo in the config) override detection, and the reason records that.
- If no scan applies, the repo is skipped with `no scan applies to this repository`.

**Differences from Workflow-App-per-Lang-Override**, because this tool scans the client's own build output instead of the integration's autopackager build:

- Windows only changes the SCA job's runner. SAST packaging runs on Linux, after the client's own build.
- There's no per-repo `veracode.yml`. The decision is applied directly in the workflow.
- SCA also turns on for Ruby (Bundler), Swift/Objective-C (CocoaPods with `Podfile.lock`) and C/C++ (Make), which the agent supports.
- SAST also covers Swift/Objective-C, Dart/Flutter, Ruby on Rails and the Policy Scan-only languages, because the client's own workflow can produce what Veracode needs (on a macOS runner, with the RubyGem, ...).

## Scans and events

| Scan | Flag / config key | Runs on |
|---|---|---|
| Pipeline Scan | `--pipeline` / `pipeline` (default on) | Pushes to non-default branches, and pull requests. PRs gate on `pr_gate_policy`; branch pushes fail on any flaw or on `branch_fail_on_severity`. |
| Policy Scan (Upload and Scan) | `--policy` / `policy` (default on) | Pushes to the default branch, which includes merges |
| SCA (agent) | `sca` | Pull requests into the default branch, and pushes to it |
| IaC/Secrets | `iac` | Every run |

- Passing `--pipeline` or `--policy` on the command line selects exactly those; the other is off. With none of them, the config (or the defaults) applies.
- Pipeline Scan doesn't support Dart, Perl, PL/SQL, T-SQL, Classic ASP, RPG or VB6. When the scan only covers those, the Pipeline Scan job is left out (with `--pipeline` alone, SAST is off).
- `veracode-prepare` only runs on events where at least one selected SAST scan runs.
- Fork PRs are skipped by every job, because they don't receive secrets.
- The policy upload submits the scan and returns; results appear in the Veracode Platform.

## 2. Choosing the workflow

| Rule | Result |
|---|---|
| `--workflow` / `workflow:` | That file. Matching zero or several files skips the repo. |
| A file that already has managed blocks | That file, so a re-run updates it |
| Another workflow already uses Veracode | Skip, unless `--force` |
| Otherwise | Files triggered by `push` or `pull_request`, excluding reusable (`workflow_call`) workflows, which only get the secrets their callers pass. The tool prefers, in order: not a utility workflow (CodeQL, release, deploy, docs, lint, translations, Copilot setup, dependency review, OS- or tool-specific checks, ...), contains the build (for compiled languages), has build or test jobs, has both triggers, has a CI-like name (`ci`, `build`, `test`, `maven`, ...), and runs on Linux. On a tie it picks the one with the most build/test jobs, then the first by name, and adds a note. `--strict` skips instead. |

## 3. Finding the build

| Build tool | Matched command | Default upload path |
|---|---|---|
| Maven | `mvn`/`mvnw` with `package`, `install`, `verify` or `deploy` | `**/target/*.jar`, `*.war`, `*.ear`, without `-sources`/`-javadoc`/`-tests` jars |
| Gradle | `gradle`/`gradlew` with `build`, `assemble*`, `jar`, `war`, `bootJar`, `shadowJar` (also the `arguments:` of the Gradle action) | `**/build/libs/*.jar`, `*.war`, `**/build/outputs/apk/**/*.apk`, without `-plain`/`-sources`/`-javadoc` jars |
| sbt | `sbt ... package`/`assembly` | `**/target/scala-*/*.jar` |
| Ant | `ant` | `**/dist/**/*.jar`, `*.war`, `*.ear` |
| .NET publish | `dotnet publish` | The `-o` folder when it's a literal (relative to `working-directory`); otherwise `**/bin/**/publish/**` dll/exe/pdb |
| .NET build | `dotnet build`, `msbuild` | `**/bin/**/*.dll`, `*.exe`, `*.pdb` |
| Grails | `grails`/`grailsw` with `assemble`, `war` or `package` | `**/build/libs/*.war`, `*.jar` |
| Flutter | `flutter build apk`, `appbundle` or `ipa` | `**/build/app/outputs/flutter-apk/*.apk`, `**/build/ios/ipa/*.ipa`. A TODO asks for `--debug`, and for an APK instead of an app bundle. |
| Xcode | `xcodebuild ... archive` | `**/*.xcarchive/**`. A TODO asks for gen-ir when no step runs it. |
| Veracode RubyGem | `veracode prepare` | `**/tmp/veracode-*.zip` |
| Native | `make`, `cmake --build`, `ninja` | No default. A `TODO-set-your-build-output-path` placeholder goes in, plus a TODO. |

- Only builds for the languages found count: a Java repo with a `make` step uses Maven or Gradle when there is one. Languages whose build is missing get a TODO naming what they need.
- Jobs that call reusable workflows (`uses:` at job level) are skipped, because steps can't be added to them.
- If several jobs build the code, the tool prefers a job named `build`/`package`/`compile`/`ci`, then one without a job-level `if:`, then one on Linux, then one that isn't a release/deploy job. A remaining tie takes the first in the file and adds a note (`--strict` skips instead); `build_job` sets it.
- Inside the build job, the **last** matching step counts, so `dotnet publish` after `dotnet build` wins.
- If the job already uploads an artifact after the build (one that isn't a test report or log), the tool downloads that artifact instead of adding its own upload step.
- Matrix builds: every leg uploads `veracode-build-<job-index>`. The prepare job merges them, so files with the same name are scanned once.

For source-code SAST, the upload step isn't added. The prepare job checks out the repo and zips it with `git archive` after the job that installs or tests the code, preferring a job named `build`, then `test`.

Binary and source scans are combined (`binary+source`) when the repo also has a first-party JS/Python/Go/PHP project (a `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod` or `composer.json`), or Apex, COBOL, PL/SQL, T-SQL, Classic ASP, VB6 or RPG code. Vendored static JavaScript, or Perl and Python build scripts, in a .NET or Java app don't count; the plan notes what was left out.

## 4. Scan units and packaging checks

`veracode-prepare` builds the units in `veracode-units/`:

| Input | Unit |
|---|---|
| Each `.jar`, `.war`, `.ear`, `.apk`, `.aab`, `.ipa`, `.zip` | One unit each (renamed `-1`, `-2` on name clashes) |
| Each `.xcarchive` folder | One zip with the archive folder at its root |
| `.i`/`.ii` files and `veracode.json` | One `veracode-cpp-preprocessed.zip`, keeping the folder layout |
| `.dll`, `.exe`, `.pdb`, `.so`, `.dylib` and their siblings | One `veracode-binaries.zip`, keeping the folder layout |
| Source mode | One `veracode-source.zip` from `git archive HEAD`, without Go and (when other languages are present) Classic ASP files |
| Go | One `veracode-go-<module>.zip`: the shallowest module, with other modules removed and `go mod vendor` run |

Pipeline Scan runs once per unit (matrix). Upload and Scan uploads them all as one build.

| Check (warning only) | Fix |
|---|---|
| No scannable build output | Fix the upload `path:` |
| `.dll`/`.exe` without any `.pdb` | Build with portable PDBs ([.NET packaging](https://docs.veracode.com/r/compilation_net)) |
| Test assemblies in the output | Exclude test projects from the path |
| Jar classes without `LineNumberTable` | Compile with `-g` ([Java packaging](https://docs.veracode.com/r/compilation_java)) |
| Test classes inside a jar | Package without tests |
| `node_modules/` committed, or only minified JS | Scan the unminified source ([JS packaging](https://docs.veracode.com/r/compilation_jscript)) |
| `.xcarchive` without dSYMs | Archive a Debug build with `dwarf-with-dsym` and run gen-ir ([Apple packaging](https://docs.veracode.com/r/compilation_apple_platforms)) |
| `.i`/`.ii` files without `veracode.json` | Add `veracode.json` ([preprocessed source](https://docs.veracode.com/r/C_Cplus_preprocessed_source_packaging)) |
| `replace` directives in `go.mod`, `go mod vendor` failed, or Go missing on the runner | Remove the directives. On a self-hosted `--runner`, install Go (GitHub-hosted Ubuntu runners have it) ([Go packaging](https://docs.veracode.com/r/compilation_go)) |
| A unit larger than 2 GB | Split it ([upload limits](https://docs.veracode.com/r/c_static_overview)) |

## 5. Managed blocks

Everything the tool adds sits between two comment lines:

```yaml
    # >>> veracode-pipeline-inject >>> managed block: re-run the tool to update it
    ...
    # <<< veracode-pipeline-inject <<< 5c87562f7d4e
```

The value at the end is a hash of the block's content.

- **Re-run:** the tool removes the blocks and adds them again, so an unchanged repo gives an identical file and no commit.
- **Hand edits:** if the content no longer matches the hash (for example, someone fixed `path:` on the branch), the tool leaves the repo alone so the edit survives. `--force` regenerates the block.
- **Remove:** `--remove` deletes the blocks and returns the original file byte for byte.
- **Safety check:** after injecting, both versions are parsed. The client's jobs, triggers and settings must be identical except for the one upload step. If they aren't, nothing is written.

Line endings (LF/CRLF), indentation, comments and anchors in the client's file aren't changed. Only whole lines are inserted.

## Branch rules

| Situation | What the tool does |
|---|---|
| Branch doesn't exist | Creates it from the head of the default branch and commits the workflow change |
| Branch exists; all its commits are from this tool; workflow matches the default branch outside the managed blocks | Regenerates the blocks. No commit if nothing changed. |
| Branch has commits from anyone else | Skips the repo (`--force` adds to the branch anyway) |
| Workflow on the branch differs from the default branch outside the managed blocks | Skips the repo. `--force` rebuilds the file from the default branch's version. |
| A managed block was edited on the branch | Skips the repo so the edit survives (`--force` regenerates the block) |
| Branch name equals the default branch, or is not a valid ref | Skips the repo. Nothing is ever written to the default branch. |
| Branch created by someone else during the run, or the file changed between read and write | Marks the repo `failed`; re-running fixes it |

## 6. Pre-checks (`--dry-run` shows them)

| Check | PASS | WARN / FAIL |
|---|---|---|
| Secrets | `VERACODE_API_ID`, `VERACODE_API_KEY` (and `SRCCLR_API_TOKEN` when SCA is on) found as repo or org secrets | WARN: missing secrets (added to the TODOs), or the secrets couldn't be listed without admin access |
| Actions policy | All actions allowed, or `veracode/*` and `actions/*` allowed | FAIL: Actions is disabled or only local actions are allowed, and the repo is skipped. WARN: a selected-actions policy that doesn't list `veracode/*` |
| Triggers | `push` and `pull_request` | TODO when both are missing. A note when one is missing. |
| Concurrency | No workflow-level cancel | TODO when `cancel-in-progress: true` could cancel a policy upload |
| Token | Has the `repo` and `workflow` scopes (classic) | Error before any write |

## Worked examples

All come from read-only `--dry-run` / `--detect-only` runs against public repositories:

| Repository | Workflow chosen | Plan | Why |
|---|---|---|---|
| `dotnet-architecture/eShopOnWeb` | `dotnetcore.yml` | SAST binary after job `build` (`dotnet build`), SCA, IaC | C# with a `dotnet build` step. The `wwwroot` JS has no `package.json`, so no source zip. |
| `gin-gonic/gin` | `gin.yml` | SAST source after job `test`, SCA, IaC | Go is a source language. `trivy-scan.yml` also runs on push, but `gin.yml` has a test job. |
| `juice-shop/juice-shop` | `ci.yml` | SAST source after job `frontend-test`, SCA, IaC | TypeScript. A test job is preferred over `lint`. |
| `spring-projects/spring-petclinic` | `gradle-build.yml` | SAST binary after job `build` (Gradle), SCA, IaC | `gradle-build.yml` and `maven-build.yml` tie; the first by name wins with a note. `--workflow maven-build.yml` picks the Maven one. |
| `ShareX/ShareX` | detection only | SAST, SCA on `windows-latest`, IaC | `App.xaml` triggered a project-file read, and `ShareX.HelpersLib.csproj` targets Windows |
| `jekyll/jekyll` | detection only | SAST (JavaScript), SCA (Bundler), IaC | Ruby isn't scanned because it isn't a Rails app; CoffeeScript isn't supported |
| `discourse/discourse` | `tests.yml` | SAST source after job `build`, SCA, IaC, plus a TODO for `veracode prepare` | Rails app: Ruby needs the Veracode RubyGem step |
| `git/git` | `main.yml` | SAST binary (native build), SCA (C/C++ Make), IaC | The root `Makefile` has a compiler string and a `clean` target. Perl, Python and JS are build scripts, noted as not in the scan. |
| `exelban/stats` | detection only | SAST, no SCA, IaC | Xcode project, so Swift/Objective-C count. The `Makefile` drives `xcodebuild`, so the agent's Linux Make build can't run. |
| `open-telemetry/opentelemetry-go` | `ci.yml` | SAST source (root Go module), SCA, IaC, plus a TODO listing the other 29 modules | Veracode takes one Go module per upload |
| `terraform-aws-modules/terraform-aws-vpc` | detection only | IaC only | Only HCL, so no SAST and no SCA |

## When a setting can't apply

| Setting | Ignored when |
|---|---|
| `artifact_path` | SAST mode is `source`, or the tool reuses an existing artifact (setting it turns reuse off) |
| `build_step` | `build_job` isn't set |
| `branch_fail_on_severity` | Pull requests. Those use `pr_gate_policy`. |
| `sca_blocking` | SCA is off |
| `--pin-sha`, `--report` | `--file` mode |
| `windows_runner` | SCA is off, or the repo has no confirmed Windows-only signal |
| Everything except detection settings | `--detect-only` |
| `--source-dir`, `--out` | `--target` mode |

## Choosing flags

| Goal | Use |
|---|---|
| See which scans make sense, org-wide | `--target org --detect-only --report scans.csv` |
| See what would happen across an org | `--target org --dry-run --no-diff --report plan.csv` |
| IaC/Secrets only where there's infrastructure code | `--iac artifacts` |
| Keep SCA on Linux for every repo | `--windows-runner off` |
| Fix one repo the auto-detection skipped | `repos:` entry with `workflow` / `build_job` / `artifact_path` |
| Gate branch pushes on severity, not on every flaw | `--branch-fail-on-severity "Very High, High"` |
| Only the compliance record, no PR scans | `--policy` |
| Make SCA or IaC block merges | `--sca-blocking` / `--iac-blocking` |
| Self-hosted runners | `--runner` (the label needs bash, python3 and git) |
| Strict supply-chain policy | `--pin-sha` |
| Undo | `--remove` |
