# GitHub API use, rate limits and scale

This page covers how the tool uses the GitHub API, how it handles rate limits and errors, which token to use, and what to expect in large organizations. The numbers come from runs against real public repositories and a simulated organization.

## Calls per repository

| Step | Call | When |
|---|---|---|
| Snapshot | 1 GraphQL query: languages, the head of the default branch and of `veracode/integration`, and every workflow file on both | Always (`--detect-only` asks for languages only) |
| File list | `GET /git/trees/<default>?recursive=1` | Always |
| Project files | `GET /contents/<path>` | Only for C/C++ makefiles and weak Windows .NET signals (0–5, usually 0) |
| Branch ownership | `GET /compare/<default>...<branch>` | Only when the branch already exists |
| Secrets | `GET /actions/organization-secrets`, then `/actions/secrets` only if something is still missing | Not with `--detect-only` |
| Actions policy | `GET /actions/permissions` (+ `/selected-actions` when the policy is "selected") | Not with `--detect-only` |
| Write | `POST /git/refs` (new branch) and `PUT /contents/<workflow>` | Only for repositories that change |

Per run: one `GET /rate_limit` (checks the token without using budget), the target lookups (one per explicit repo, or one per 100 repos of an org), and 6 calls for `--pin-sha`.

### Before and after

Each workflow file used to be one REST call. Real repositories have many: across 256 popular repositories the mean is 13.3 workflow files, the 90th percentile 33, and the maximum 228.

| Mode | Before (REST calls per repo) | After |
|---|---|---|
| `--detect-only` | 2 REST | 1 REST + 1 GraphQL |
| `--dry-run` | 7 + one per workflow file (~20 on average) | ~4 REST + 1 GraphQL |
| First real run | ~20, plus 2 writes | ~4 REST + 1 GraphQL, plus 2 writes |
| Re-run (branch exists) | ~19 | ~5 REST + 1 GraphQL |

Measured on 15 real public repositories (dry run, same results field for field):

| | REST only (before) | GraphQL snapshot (after) |
|---|---|---|
| API calls | 372 | 77 |
| Wall time | 176 s | 80 s |
| `openclaw/openclaw` (136 workflow files) | 138 calls, 78 s | 4 calls, 27 s |

On a simulated org of 293 repositories with the real workflow-count distribution, calls per repo went from 17.6 to 4.3 (dry run) and from 20.0 to 5.9 (real run).

GraphQL has its own hourly budget, separate from REST, and this query costs 1 point. When GraphQL isn't available (an older GHES schema, a proxy, an error), the tool falls back to REST for that repository, or for the rest of the run if the query is rejected. Workflow text from GraphQL is only used when it hashes to the file's git blob ID; anything else (truncated, binary, or not byte-identical) is read over REST, so the bytes the tool edits are always exact.

## Throughput

GitHub's limits decide how fast a run can go, not latency:

| Limit | Value | Effect |
|---|---|---|
| REST budget | 5,000/hour (PAT), up to 15,000/hour (GitHub App on GitHub Enterprise Cloud) | About 1,000 repos/hour for a dry run with a PAT |
| GraphQL budget | 5,000–10,000 points/hour, separate | 1 point per repo |
| Content creation | 80 a minute and 500 an hour (secondary limit) | Each changed repo needs 2 writes, so about **250 changed repos/hour** at most |
| Server time | 90 s of request time per minute (secondary limit) | Serial requests can't exceed it |

Rough durations for 2,000 repositories: `--detect-only` about 40 minutes, `--dry-run` about 2 hours with a PAT (less with a GitHub App), and a real run about 8 hours when every repository changes, set by the 250 changes/hour limit. Run long rollouts from a CI job or a server, with `--report` and `--resume`.

### Why requests are serial

The tool doesn't run repositories in parallel. A run is bounded by the hourly budget and the content-creation limit, which parallel workers don't raise. GitHub also limits request time per minute and concurrent requests, so parallel workers would hit secondary limits and slow the run down. On GHES with rate limiting disabled, parallelism could help; it isn't implemented.

## Rate limits and retries

| Situation | What the client does |
|---|---|
| Primary limit almost used (`x-ratelimit-remaining` < 25) | Waits for `x-ratelimit-reset` before the next request. REST (`core`) and GraphQL are tracked separately. |
| 403/429 primary limit (`remaining: 0`) | Waits until `x-ratelimit-reset`, using the server's `Date` header so a skewed local clock doesn't matter |
| 403/429 secondary limit or abuse detection | Waits `Retry-After` if present, else until the reset if `remaining` is 0, else 60 s doubling to 15 minutes (with jitter) |
| GraphQL `RATE_LIMITED` error | Same as a primary limit |
| 5xx, timeouts, dropped connections | Up to 3 retries, 2/4/8 s plus jitter |
| 401 | Not retried. With `--token-command`, the tool gets a new token and retries once. |
| 403 permission, 404, 422 | Not retried. A 403 shows which permission the token is missing (`x-accepted-github-permissions`). |
| Content-creating requests | At least 1 s apart, at most 80 a minute and `--writes-per-hour` (default 500) an hour |

Every request is bounded: at most 12 rate-limit waits of at most about an hour each, and 3 transient retries. Waits are printed, counted, and shown in the summary:

```text
API calls: 77 (63 REST + 14 GraphQL, 5.1 per repo); writes 0, retries 0, rate-limit waits 0 (0s waiting); elapsed 1m19s
API budget left: core 4986/5000, graphql 4986/5000 (resets 15:36)
```

`--debug` logs every request (method, path, status, time, remaining budget). It never logs the token or request bodies.

### Writes that may have succeeded

A write that times out or gets a 5xx is retried. If the first attempt actually succeeded, the retry fails, and the tool checks GitHub instead of reporting a failure:

- Branch creation answers 422 "already exists": the tool continues if the branch points at the expected commit, and otherwise reports `failed`.
- The file update answers 409: the tool reads the file on the branch. If it holds exactly the new content, the repo is `committed` ("verified on the branch"); otherwise `failed`.

Either way, re-running is safe: the branch rules (see [how it works](how-it-works.md#branch-rules)) never add a second commit with the same change.

## Tokens

| Token | Use it for | Notes |
|---|---|---|
| Classic PAT (`repo`, `workflow`) | Small rollouts | 5,000 calls/hour, shared with everything else that uses that account |
| Fine-grained PAT | Small rollouts with least privilege | Repository permissions below |
| GitHub App installation token | Large orgs | Up to 15,000 calls/hour on GitHub Enterprise Cloud. Tokens last 1 hour: use `--token-command`. |

Permissions for a fine-grained PAT or a GitHub App:

| Permission | Access | Needed for |
|---|---|---|
| Metadata | Read | Everything |
| Contents | Read and write | Reading the code and workflows; creating the branch and the commit |
| Workflows | Read and write | Changing files under `.github/workflows` |
| Secrets | Read | The secrets pre-check (optional: without it the check becomes a TODO) |
| Administration | Read | The Actions policy pre-check (optional: without it the check is a warning) |

`--dry-run` and `--detect-only` need read access only.

`--token-command` runs a command (without a shell) that prints a token, at the start and again when GitHub answers 401. For example, with a script that mints a GitHub App installation token:

```bash
python veracode_inject.py --target my-org --report rollout.csv --resume \
  --token-command "python mint_app_token.py --app-id 12345 --key app.pem --org my-org"
```

The command's output is never printed or logged.

## GitHub Enterprise Server

- Set `GITHUB_API_URL=https://ghe.example.com/api/v3`. The GraphQL endpoint is derived (`/api/graphql`); `GITHUB_GRAPHQL_URL` overrides it.
- If rate limiting is disabled on the server, `/rate_limit` answers 404 and the tool says so; nothing else changes.
- `--pin-sha` resolves the action SHAs on github.com without sending the GHES token there. The `veracode/*` actions must be available to the GHES instance (GitHub Connect or a synced copy).

## Resume

- The report is written row by row and synced to disk. A row cut off by a crash is dropped on `--resume`.
- Each row records the run's `mode` (`detect`, `dry-run`, `write`, `remove`, `remove-dry-run`). `--resume` only skips repositories completed in the same mode, so resuming a dry-run report in a real run changes the repositories instead of skipping them.
- The `api_calls` and `seconds` columns show the cost of each repository.
- Reports from older versions still resume; new rows keep the old columns.
- If the same 403 error hits 10 repositories in a row, the run stops (exit 3) instead of spending the budget on the rest: the token, not the repositories, is the problem. Fix it and re-run with `--resume`.

## Security

- **Token:** sent only in the `Authorization` header, only to `GITHUB_API_URL`. Redirects to another host or to plain HTTP drop the header. A non-local `http://` API URL prints a warning; other schemes are rejected. The token never appears in output, `--debug` logs, reports or commit messages.
- **Repository content is untrusted:** workflows are parsed with PyYAML's safe loader. YAML whose aliases expand past 200,000 nodes is rejected, because a 600-byte file can otherwise expand to billions of nodes and hang the run. Nothing from a repository is executed.
- **Writes:** only to the tool's branch, never to the default branch, and only when every commit on that branch is the tool's (see branch rules).
- **Injected jobs:** the tool adds no triggers to the workflow. Every injected job has `permissions: contents: read`, skips pull requests from forks, and has no `${{ }}` expressions inside its `run:` scripts; secrets reach the actions through `with:`/`env:` only.
- **Actions:** pinned by tag by default. For a large rollout, `--pin-sha` pins them to commit SHAs, so a moved tag can't change what runs.
