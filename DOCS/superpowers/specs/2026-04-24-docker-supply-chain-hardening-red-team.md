# Red Team Review: Docker Supply-Chain Hardening

**Date:** 2026-04-24
**Spec reviewed:** `DOCS/superpowers/specs/2026-04-24-docker-supply-chain-hardening-design.md`
**Reviewer role:** Adversarial security / reliability

---

## Security

### S1. Guard author check is spoofable via committer/author mismatch on `workflow_run` (HIGH)

The guard at `rebuild-release-tags.yml` relies on
`github.event.workflow_run.head_commit.author.username == 'renovate[bot]'`.
The `author` on `head_commit` is the GIT author (text field in the commit
object), not the authenticated GitHub user. Anyone with push access — or
anyone whose PR got merged — can set the git author to
`renovate[bot] <29139614+renovate[bot]@users.noreply.github.com>` locally,
push, and the guard check will pass. The field comes from the commit object,
which is attacker-controlled content.

The GitHub-verified identity for `workflow_run` is
`github.event.workflow_run.triggering_actor.login` and
`github.event.workflow_run.actor.login`. The design's chosen field is the
one an attacker can forge.

Combined with the main-branch protection finding (S2), this is exploitable
end-to-end.

**Fix:** Replace the author check with

```yaml
if: >-
  github.event.workflow_run.conclusion == 'success' &&
  github.event.workflow_run.event == 'push' &&
  github.event.workflow_run.head_branch == 'main' &&
  github.event.workflow_run.triggering_actor.login == 'renovate[bot]' &&
  github.event.workflow_run.actor.login == 'renovate[bot]'
```

Validate `triggering_actor` AND `actor` (these are verified GitHub
identities, not git commit metadata). Additionally verify the commit is
signed by Renovate via `gh api repos/{owner}/{repo}/commits/{sha} --jq
'.commit.verification.verified'` and that the signer is the Renovate app —
Renovate signs commits with its GitHub App key, and that signature cannot be
forged without compromising the app.

---

### S2. `main` has no required status checks and allows force-pushes — the entire "auto-merge is safe" premise collapses (HIGH)

Verified against live repo via `gh api repos/billchurch/webssh2/branches/main/protection`:

- `required_status_checks.contexts: []` — no checks are required.
- `required_pull_request_reviews` is absent — no reviews required.
- `allow_force_pushes.enabled: true`.
- `allow_auto_merge: false` at the repository level.

Consequences:

1. Renovate "auto-merge" cannot be enabled because the repo-level setting is
   off. Renovate will fall back to creating the PR but cannot merge it.
   Setting `platformAutomerge: true` without the repo toggle is a silent
   no-op.
2. Even if auto-merge is enabled, with no required status checks the PR will
   merge the instant Renovate creates it, regardless of whether
   `docker-image-scan` ran or passed. `docker-image-scan` is advisory only
   unless required.
3. Force-push is allowed on `main`, which is a separate defect the spec does
   not address but makes every tag/digest guarantee in the spec moot.

**Fix:** Before PR 3 (Renovate) ships:

1. Enable `allow_auto_merge` at repo level (`gh api -X PATCH
   repos/billchurch/webssh2 -f allow_auto_merge=true`).
2. Add required status checks on `main`. At minimum require the
   `build-lint-test` job and the new `docker-image-scan` job (with the
   specific check names, verified by name). Note that conditional jobs
   (those with `if: github.event_name == 'pull_request'` or path-filter
   gated) report a special "skipped but required" status — GitHub will pass
   the required check as long as the run concluded, but the `if` gating of
   individual *steps* within a job will still let the job report success
   even when nothing ran. Solution: make the filter produce a dedicated
   `docker-image-scan-required` job that always runs and only conditionally
   does real work, so the required-check name is stable.
3. Disable `allow_force_pushes` on `main`.
4. Require signed commits on `main` (already enabled per the protection
   API). Keep it that way; Renovate supports commit signing.

Without these repo-level changes, the spec is unsafe to ship.

---

### S3. `workflow_run` re-checkout uses the default branch, bypassing the guard (HIGH)

`actions/checkout` inside a `workflow_run`-triggered workflow defaults to
checking out the default branch at the time the triggered workflow runs,
NOT the commit that triggered it. This is the single most common
`workflow_run` foot-gun. The guard reads the Dockerfile from `main` at
trigger time, but `rebuild-release-tags.yml` then does:

- Reads the new digest from `Dockerfile` on `main` (the spec says: "Extract
  the new base digest from the Dockerfile on `main`").

If someone pushes a new commit to `main` between the `docker-publish.yml`
completion and the `workflow_run` firing, the rebuild workflow will read a
Dockerfile that has MORE changes than the one the guard validated. The
guard and the extraction run against potentially different tree states.
Worse, the "diff is digest-only" check uses the SHA the guard inspected,
but the build step's `git checkout <release-tag>` + `--build-arg
BASE_IMAGE=<digest extracted from main>` could mix a new release commit's
source with a digest pulled from a later, unrelated commit.

**Fix:**

1. Pin all git reads and API calls to the exact commit SHA that triggered
   the workflow_run:
   `github.event.workflow_run.head_sha`. Use it everywhere:
   `gh api repos/.../commits/${HEAD_SHA}`,
   `actions/checkout@... with: ref: ${{ github.event.workflow_run.head_sha }}`.
2. Extract `BASE_IMAGE` from the Dockerfile at that exact SHA, not from
   HEAD of main.
3. If `head_sha` is not the current HEAD of main at execution time, warn
   and still proceed — the rebuild against a release-tag source tree is
   still valid; what matters is that guard + digest extraction + diff-check
   all reference the SAME commit.
4. Enforce with a hard check early in the guard job:
   `git rev-parse origin/main` equals `head_sha`, or abort.

---

### S4. `dorny/paths-filter` with `pull_request` on a compromised PR head can poison the filter (MEDIUM)

`dorny/paths-filter` compares the PR head against the base. On
`pull_request` events, the checkout uses `GITHUB_HEAD_REF` — the PR
branch. If a malicious PR modifies `.github/paths-filter.yml` or similar
in-tree config in the PR itself, the filter logic becomes
attacker-controlled. This is only consequential if the job later runs
privileged operations (secrets, writes). The spec uses `pull_request`
(not `pull_request_target`), so `GITHUB_TOKEN` has only the
default PR-side permissions (read) and `docker-image-scan` has
`security-events: write` but no Docker Hub/GHCR push. Risk: exhausts
`security-events` quota / pollutes Security tab with attacker-supplied
SARIF. Not catastrophic, but real.

Secondary concern: `dorny/paths-filter` is a new transitive dependency in
the supply chain. Pin to a full SHA (the spec says it will; verify during
PR review) AND subscribe to the repo's releases so compromises are caught.

**Fix:**

1. Keep the spec's `pull_request` trigger (not `pull_request_target`).
   Never switch to `pull_request_target` for this job — that would hand
   write permissions to the attacker-controlled PR branch.
2. Pin `dorny/paths-filter` to a commit SHA, not a tag. Add a comment with
   the verified tag name so SHA updates are auditable.
3. Define filters inline in the workflow (as the spec already does); never
   read filter YAML from the repo root, which would be PR-controlled.
4. Add a top-level workflow `permissions: {}` and grant only what each job
   needs (the spec does this for the job, but the workflow-level default
   should also be `read-all` or `{}`).

---

### S5. Digest guard regex is trivially bypassable (HIGH)

The spec's regex is:

```text
^ARG BASE_IMAGE=...@sha256:[0-9a-f]{64}$
```

Problems:

1. The regex anchors `^...$`, but the guard's stated logic is "the
   Dockerfile diff modifies only the BASE_IMAGE default value". If
   Renovate (or an attacker crafting a PR styled as Renovate) includes
   *additional* lines in the diff that also match
   `^ARG BASE_IMAGE=...@sha256:...$`, the regex is satisfied per-line. But
   a single extra modified line elsewhere in the file (e.g., a new `RUN`
   step, an injected `COPY`, an altered `USER`) is not detected by a regex
   that only inspects BASE_IMAGE lines. The guard must check the whole
   diff, not just the matching lines.
2. `{64}` allows any hex — including digests of maliciously-prepared
   images (typo-squatted `node:22-apline@sha256:...`). The regex doesn't
   check that the image reference is `node:22-alpine@...`. Renovate
   normally writes the full reference, but an attacker impersonating
   Renovate (see S1) could write `ARG
   BASE_IMAGE=evil.registry.example/node:22-alpine@sha256:<real digest of
   evil image>` and satisfy the regex.
3. The `^...$` anchoring assumes the Dockerfile has one BASE_IMAGE ARG;
   the spec's Dockerfile sketch has the ARG declared once at top but
   referenced via `${BASE_IMAGE}` in three `FROM` stages. Renovate's
   digest-pin update may edit ALL THREE `FROM` lines depending on how
   Renovate interprets ARG scoping. Plan for a multi-line diff that
   matches multiple positions.

**Fix:**

1. Do not rely on regex against the diff. Instead:
   - Use `git diff --name-only ${BASE_SHA} ${HEAD_SHA}` and require the
     output is exactly `Dockerfile\n` (no other files).
   - Use `git diff ${BASE_SHA} ${HEAD_SHA} -- Dockerfile` and parse with
     a structured check: verify the ONLY hunk's removed-line count equals
     added-line count AND every changed pair matches
     `^-ARG BASE_IMAGE=node:22-alpine@sha256:[0-9a-f]{64}$` →
     `^\+ARG BASE_IMAGE=node:22-alpine@sha256:[0-9a-f]{64}$`.
   - Pin the literal image string `node:22-alpine` in the check. Do not
     accept arbitrary registries.
2. Additionally verify the new digest resolves on Docker Hub to a manifest
   list whose config matches `node:22-alpine` metadata (optional; adds
   latency but closes the gap).
3. Reject the rebuild if `git diff --name-status` shows any rename, copy,
   or mode change on Dockerfile.

---

### S6. Trivy image scan in `ci.yml` uploads SARIF that can be forged by malicious PR authors to pollute Security tab (MEDIUM)

`security-events: write` is granted to `docker-image-scan`, triggered on
`pull_request`. A PR author can craft a Dockerfile that causes Trivy to
emit arbitrary SARIF content (filenames, rule IDs, descriptions), which is
then uploaded under `category: trivy-image`. Code scanning UI renders
these as findings. This is not exfiltration, but it:

- Dilutes real alert signal.
- Can be used to drop misleading "fixed"/"dismissed" noise against real
  rules.

**Fix:**

1. Drop `security-events: write` from the PR-triggered image-scan job.
   Leave SARIF upload for push / scheduled / workflow_dispatch runs only.
   On PR, Trivy's `exit-code: 1` already blocks the merge; SARIF upload is
   not required.
2. If the Security tab signal is desired for PR work, run it in a
   separate workflow triggered by `pull_request_target` with tightly
   scoped checkout (no attacker code), or post results as a PR comment.

---

### S7. Renovate's commit identity is a GitHub App key — scope of blast radius if compromised (MEDIUM)

Auto-merge of Renovate commits to `main` is equivalent to granting
Renovate write access to production image tags. If Renovate's GitHub App
is compromised (upstream incident, installation token leak, malicious
Renovate contribution), an attacker with that key can:

- Open a Renovate-authored PR bumping the digest to a malicious image.
- Rely on auto-merge to land on `main`.
- Trigger `docker-publish.yml` and `rebuild-release-tags.yml`, poisoning
  `latest`, `main`, and every release tag series.

The image scan (Trivy) is a filter, not an oracle — a freshly-compromised
image with no known CVEs passes.

**Fix:**

1. Constrain Renovate's auto-merge to digest-only updates of a specific
   repository coordinate. Enforce in the workflow, not only in
   `renovate.json`:

   ```yaml
   - name: Verify base image is canonical
     run: |
       grep -E '^ARG BASE_IMAGE=node:22-alpine@sha256:[0-9a-f]{64}$' Dockerfile
   ```

   And add a lightweight "this digest is listed in the Docker Hub
   `node:22-alpine` tag manifest list" check, e.g. via
   `docker buildx imagetools inspect node:22-alpine --format '{{json .}}'`
   and comparing the digest.

2. Require Renovate's commit to be signed (verified) and the signer key to
   match the known Renovate GitHub App key fingerprint.
3. Keep a manual kill-switch: a repo variable like
   `ALLOW_RENOVATE_AUTOMERGE=true` that the workflow reads and refuses to
   run the rebuild job if false.

---

### S8. GHA buildx cache can carry layers from a previous unsafe build (MEDIUM)

`docker-publish.yml` sets `cache-from: type=gha, cache-to: type=gha,
mode=max`. The spec's split `build → scan → push` flow uses this cache
across the first (scannable) build and the second (pushed) build. But the
GHA cache is shared across branches and PRs by default scope. An attacker
who can land even one cache-tainted build (say, via a feature branch)
could push layers that are then pulled into the scanned build. Trivy
scans the final image, so layer-level tampering that doesn't surface as a
CVE (e.g., injected binary, modified entrypoint script) would not be
caught.

Additionally, build-args cache scoping interacts with the digest pin: if
`BASE_IMAGE` is part of the effective cache key, cache hits are safe; if
not, a previous build's layers for a DIFFERENT base digest could be
reused. BuildKit keys layers on `ARG` values that participate in `FROM`,
so this is usually safe — but worth enforcing.

**Fix:**

1. Narrow GHA cache scope to push events on `main` and the release flow.
   Do NOT use `cache-to: type=gha` on PR-triggered builds. Set
   `cache-from: type=gha` (read-only) on PR builds so PRs benefit without
   being able to poison.
2. Use `cache-to: type=gha,mode=max,scope=publish-${{ github.ref }}` and
   `cache-from: type=gha,scope=publish-refs/heads/main` to prevent feature
   branches from writing into the publish cache.
3. Explicitly include `BASE_IMAGE` in `build-args` on every build so the
   digest is part of the cache key.

---

### S9. `workflow_run` on `docker-publish.yml` fires on ALL completions, including failures and non-main branches (MEDIUM)

The spec says "Trigger: `workflow_run` completion of `docker-publish.yml`
on `main`." `workflow_run` fires on ANY completion (success, failure,
cancelled) of the upstream workflow, on any branch where that workflow
ran, unless explicitly filtered. `docker-publish.yml` runs on
`workflow_dispatch` (any branch), `release`, and `push` to `main`. The
rebuild workflow could fire on:

- A failed `docker-publish.yml` run (no image was pushed; rebuilding
  release tags against a phantom digest).
- A `workflow_dispatch` run for a feature branch.
- A `release`-triggered run (not a Renovate merge).

**Fix:**

At the top of `rebuild-release-tags.yml`:

```yaml
on:
  workflow_run:
    workflows: ['docker-publish']
    types: [completed]
    branches: [main]

jobs:
  guard:
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'push' &&
      github.event.workflow_run.head_branch == 'main'
```

Explicitly check `conclusion == 'success'`, `event == 'push'`, and
`head_branch == 'main'`. Note: `branches:` filter on `workflow_run` is
recently supported — verify documentation vs implementation and duplicate
the check in `if:` as belt-and-suspenders.

---

### S10. Release-tag rebuild has no concurrency control — races can publish mismatched manifests (MEDIUM)

`docker-publish.yml` has a `concurrency` group; the new
`rebuild-release-tags.yml` does not per spec. If two Renovate digest PRs
merge in quick succession (unlikely but possible if Renovate retries or
the dashboard is mass-merged), two rebuild workflows race. They read the
same `latest release tag` but may pull different `BASE_IMAGE` values
depending on `main` HEAD at checkout time. The last writer wins for each
individual manifest tag, but `X`, `X.Y`, `X.Y.Z` may end up pointing to
DIFFERENT underlying image digests (one from digest A, one from digest
B).

**Fix:**

```yaml
concurrency:
  group: rebuild-release-tags
  cancel-in-progress: false
```

Do NOT use `cancel-in-progress: true` — that would leave a half-pushed
set of tags. Queue instead. Combine with an idempotency check: before
pushing, resolve the latest release tag AGAIN and verify it matches what
the workflow started with.

---

### S11. `update release notes` step in `docker-publish.yml` uses unescaped semver interpolation into a shell heredoc (LOW)

Not introduced by the new spec, but activated by it. The current step
builds `DOCKER_SECTION` via shell interpolation of
`${{ steps.release_meta.outputs.semver_minor }}` into a multi-line string
that is passed to `gh release edit --notes`. The `release_meta` values
are derived from the release tag name by regex and therefore safe today.
BUT the new rebuild workflow will ALSO want to append to release notes
(per the spec: "post a comment to the GitHub release"). If that comment
generation uses similar interpolation patterns, verify no user-influenced
strings (e.g., Renovate PR URL, which is
`github.event.workflow_run.pull_requests[0].html_url` or similar) pass
through shell interpolation unsanitized. Script injection via PR titles
is a known GitHub Actions CVE class.

**Fix:**

1. In the rebuild workflow's "post comment" step, never pass user-
   controlled strings as `${{ }}` directly into shell. Assign to
   environment variables first, then reference as `"$VAR"` inside the
   script block. Example:

   ```yaml
   env:
     PR_URL: ${{ github.event.workflow_run.pull_requests[0].html_url }}
   run: |
     body=$(printf '%s\n' "Triggered by $PR_URL")
     gh release comment "$RELEASE_TAG" --body "$body"
   ```

2. Audit the existing `docker-publish.yml` release-notes step for the
   same pattern and retrofit defensively.

---

### S12. `rebuild-release-tags.yml` publishes release-tag images with `sha-<release-commit>` semantics still in place, risking sha-tag contract break (MEDIUM)

The spec says: "Do not republish `sha-<release-commit>` (it already
exists and must stay immutable on its original digest)." The
`docker/metadata-action` config in the current
`docker-publish.yml` includes `type=sha` unconditionally, which emits
`sha-<7char>` for every build.

If the rebuild workflow reuses the current `docker-publish.yml` metadata
config verbatim, the metadata action WILL generate a `sha-<commit>` tag
based on `GITHUB_SHA` at the time of the rebuild run. `GITHUB_SHA` on
`workflow_run` points to the head of the default branch in the rebuild
workflow's own context, but when `actions/checkout` checks out the
release tag, `GITHUB_SHA` in the env is NOT updated; it still points to
the triggering commit. The metadata action uses the ref/sha from
`github.ref` and `github.sha` of the workflow's own context. Result: the
rebuild could push `sha-<mainhead-sha>` pointing to the release-tag
source tree + new base digest — a tag that has never existed before for
that commit, and a misleading one (the SHA is not the source SHA).

Worse, if someone dispatches the rebuild workflow after a long delay,
`github.sha` could collide with a DIFFERENT existing `sha-<...>` tag,
clobbering an immutable tag.

**Fix:**

1. In the rebuild workflow's metadata step, explicitly DISABLE
   `type=sha`. Only emit the semver tags:

   ```yaml
   tags: |
     type=raw,value=${{ steps.release_meta.outputs.semver_full }}
     type=raw,value=${{ steps.release_meta.outputs.semver_minor }}
     type=raw,value=${{ steps.release_meta.outputs.semver_major }}
   ```

2. Add a post-push assertion: query the registry for `sha-<release
   commit>` and verify its digest is UNCHANGED from before the rebuild.
   Fail the workflow if it changed (shouldn't happen, but catches config
   drift).

---

### S13. `gh release list --limit 50` picks "latest release" by creation order, not semver — pre-releases and drafts can poison the selection (MEDIUM)

The guard resolves the latest release via:

```bash
gh release list --limit 50 --json tagName \
  --jq '[.[] | select(.tagName | startswith("webssh2-server-v"))][0].tagName'
```

`gh release list` orders by creation time. Results:

- A draft or pre-release created after the latest stable (e.g.,
  `webssh2-server-v5.0.0-beta.1`) would be picked first, and its source
  tree rebuilt with a new base digest, pushing `5`, `5.0`, `5.0.0-beta.1`
  tags.
- `startswith("webssh2-server-v")` matches `v4.2.1` AND `v5.0.0-rc.1` AND
  any future variant.
- If someone creates a release with a patched historic tag (e.g., for
  backport), the rebuild picks it up.

**Fix:**

1. Use `gh release view --json tagName,isLatest,isDraft,isPrerelease`
   and filter `isLatest == true`. GitHub tracks the `latest` flag
   explicitly; use that source of truth.

   ```bash
   latest_tag=$(gh release list --limit 50 --json tagName,isLatest \
     --jq '.[] | select(.isLatest == true) | .tagName')
   ```

2. Additionally validate the tag matches the strict regex
   `^webssh2-server-v[0-9]+\.[0-9]+\.[0-9]+$` — reject pre-releases,
   drafts, and anything with suffix.
3. If no matching release is found, exit 0 with a log message (the spec
   already specifies this behavior for "pre-first-release").

---

## Denial-of-Wallet (DoW)

### DoW1. Unbounded Renovate-PR-storm multiplies Trivy downloads, buildx runs, and GHA minutes (MEDIUM)

A malicious open-source contributor (or a Renovate config bug) could
trigger many PRs touching the path-filter matches (`Dockerfile`,
`package-lock.json`, `.github/workflows/ci.yml`). Each PR runs:

- 1 × amd64 buildx build (~2-3 min)
- 1 × Trivy DB download (~500MB amortized; Trivy aggressively caches but
  cold caches still download)
- 1 × SARIF upload

With GHA free-tier limits irrelevant for public repos (unlimited minutes),
the cost is on Docker Hub pulls (rate-limited) and Trivy's GHCR hosted DB
(also rate-limited for anonymous pulls). Docker Hub's anonymous pull
limit is 100 pulls / 6 hours / IP. Every `build-push-action` on a PR
pulls `node:22-alpine`. A PR spam of 10+ simultaneous PRs from different
forks can saturate the runner's Docker Hub budget and cause Trivy's
`FATAL: failed to download vuln list` errors across the org.

**Fix:**

1. Authenticate Docker Hub pulls on PR jobs using a read-only token.
   `docker/login-action` with a scoped PAT raises the limit to 200
   pulls / 6 hours for authenticated users.
2. Enable Trivy DB caching via `TRIVY_DB_REPOSITORY` pointed at a
   mirror, or use `cache: true` on `aquasecurity/trivy-action`.
3. Set `concurrency` on the image-scan job to cancel prior runs on the
   same PR:

   ```yaml
   concurrency:
     group: docker-image-scan-${{ github.event.pull_request.number }}
     cancel-in-progress: true
   ```

4. Skip image scan on PRs from forks (they cannot push anyway, and the
   scan is advisory). Add `if: github.event.pull_request.head.repo.full_name
   == github.repository`.

---

### DoW2. `workflow_run` fan-out chain can self-trigger if naming overlaps (LOW-MEDIUM)

If the new `rebuild-release-tags.yml` does its final push via
`docker/build-push-action`, and that push (somehow) ends up triggering
`docker-publish.yml` via a registry webhook or a `repository_dispatch`
event, the chain loops. The current `docker-publish.yml` triggers on
`workflow_dispatch`, `release`, `push`. None of those fire from a pushed
Docker image directly, so no direct loop — but: the rebuild workflow
calls `gh release edit` / `gh release comment` to post the new digest.
If the comment triggers any `release` sub-event, or if it's ever changed
to `gh release create`, the chain loops.

**Fix:**

1. Add a workflow-level guard that the rebuild workflow never runs the
   rebuild more than once per `head_sha`. Persist state via a GitHub
   release label or a PR comment:

   ```bash
   if gh release view "$LATEST" --json body | \
      jq -e --arg sha "$HEAD_SHA" '.body | contains("rebuild-sha: \($sha)")'; then
     echo "Already rebuilt for $HEAD_SHA, skipping"
     exit 0
   fi
   ```

2. Document that release body edits must not include strings that could
   pattern-match a loop detector.

---

### DoW3. Split amd64-build-then-multi-arch-build doubles cache egress under cache misses (LOW)

The spec's "build amd64 for scanning, then multi-arch build+push"
pattern is well-known. When the GHA cache misses (new base image, cache
eviction), the multi-arch push step rebuilds all layers on BOTH arches.
GHA cache egress is metered at ~5GB / repo / week free tier; a large
Node.js base image + dependencies + build layers can be 400-800MB per
arch. A few dozen Renovate PRs hitting cold caches per week can exceed
the free tier, at which point cache pulls fall back to uncached builds
(slower, higher runner-minute consumption).

**Fix:**

1. Use `cache-from: type=registry,ref=ghcr.io/billchurch/webssh2:buildcache`
   and `cache-to: type=registry,ref=...` to store build cache in the
   container registry. GHCR bandwidth is free for public repos and
   unbounded for private images.
2. Delete / TTL the buildcache tag weekly via a scheduled job to prevent
   indefinite growth.

---

### DoW4. Trivy's `exit-code: 1` + SARIF upload doubles runtime on every failed scan (LOW)

SARIF upload is `if: always()`. When Trivy fails (exit 1), SARIF still
uploads. This is correct for visibility, but during a CVE storm (e.g.,
multiple Renovate PRs all failing the gate for the same upstream CVE),
every PR runs the full Trivy scan to completion before uploading. Each
failure pays full scan + upload time.

**Fix:**

Accept as a reasonable trade-off. Alternative: short-circuit Trivy to
exit on first HIGH finding (`--exit-code 1` already does this); ensure
Trivy is configured with `exit-on-eol: true` and `severity:
CRITICAL,HIGH` to avoid scanning LOW/MEDIUM rules.

---

## Availability

### A1. `gh release list` with `isLatest` filter, combined with "wait for latest" semantics, causes in-flight release clobbering (HIGH)

Timeline:

1. Developer cuts release `webssh2-server-v4.3.0`. `release-please.yml`
   tags main, then dispatches `docker-publish.yml` for that tag.
2. Simultaneously, an unrelated Renovate digest PR merges. Its
   `docker-publish.yml` run starts.
3. `workflow_run` fires for the Renovate run. Rebuild workflow starts.
4. `gh release list` now resolves `v4.3.0` as latest (because it just
   got published).
5. Rebuild workflow checks out `v4.3.0`, builds with NEW digest, pushes
   `4.3.0`, `4.3`, `4`.
6. The original `docker-publish.yml` for `v4.3.0` (triggered by
   `release-please`) is STILL RUNNING, publishing `4.3.0` with the OLD
   digest. Last writer wins, but writers are interleaved.

End state: `4.3.0` tag points to an image built with a base digest
DIFFERENT from the one documented in the release notes. `sha-<release-
commit>` may or may not exist depending on which finished last.

**Fix:**

1. Guard: detect "release just happened" by comparing
   `workflow_run.created_at` against the latest release's `published_at`.
   If the release was published within the last 10 minutes, skip the
   rebuild and log "deferring to release flow".
2. Add a `concurrency` group shared between `docker-publish.yml` and
   `rebuild-release-tags.yml`:

   ```yaml
   concurrency:
     group: image-publish
     cancel-in-progress: false
   ```

   This forces them to queue rather than interleave.
3. After push, verify the release's `sha-<commit>` tag digest is
   unchanged. If it changed, fail loudly.

---

### A2. Upstream `node:22-alpine` manifest-list disappearance breaks every build until manually patched (HIGH)

By pinning `BASE_IMAGE` to a specific manifest-list digest, the repo
depends on that specific manifest being available. Docker Hub has
occasionally removed manifests (accidental delete, policy violation,
Docker Inc. incidents). When that digest disappears:

- All builds fail immediately with "manifest not found".
- Renovate will open a new PR with a new digest — good — but only on its
  schedule (Monday mornings per spec). The repo can be broken for up to a
  week if the failure is not noticed.
- Worse: if the `sha-<commit>` image pull fails in `docker-publish.yml`
  (it does `docker pull` after build), the workflow fails even though
  the multi-arch push succeeded. This is pre-existing but now amplified.

**Fix:**

1. Add a `renovate.json` schedule of "at least daily" for digest-only
   updates (not weekly):

   ```json
   {
     "description": "Check base image digest daily",
     "matchManagers": ["dockerfile"],
     "matchUpdateTypes": ["digest"],
     "schedule": ["* 0-6 * * *"]
   }
   ```

2. Cache a fallback base image in GHCR: weekly, pull
   `node:22-alpine@<current-pinned-digest>` and re-tag it to
   `ghcr.io/billchurch/webssh2-base:22-alpine`. Allow the Dockerfile to
   fall back to the mirror via a second ARG or a CI-supplied build-arg
   when Docker Hub is down.
3. Monitor build failures with a scheduled "smoke build" workflow
   (already in spec's non-goals; reconsider).

---

### A3. Renovate bot availability is a single point of failure for security patching (HIGH)

The entire flow depends on Renovate opening PRs. If Renovate is down,
paused, or misconfigured (schedule typo, matchManagers typo), base-image
CVEs do not get patched. The spec's non-goals explicitly exclude
"scheduled safety-net rebuilds". This is a deliberate choice, but the
red-team lens: CVE responsiveness depends on an external bot.

Specific Renovate failure modes observed historically:

- Renovate GitHub App being uninstalled by a co-maintainer.
- Renovate rate-limits on hosted `mend.io` backend.
- Renovate schedule mis-parsing ("before 6am on monday" — does this mean
  UTC? Local? The spec sets `timezone`, which should work, but timezone
  parsing bugs have appeared in Renovate before).
- Renovate's `dockerfile` manager not picking up ARG-based digest pins
  (it DOES support this, but `helpers:pinGitHubActionDigests` is a
  different manager — confirm the right one is active).

**Fix:**

1. Add a scheduled "safety net" workflow (reverse the spec's non-goal):
   weekly, trigger `docker-publish.yml` with `workflow_dispatch` on main
   and on the latest release tag. Even without a digest change, Trivy
   scans the latest pulled upstream layer (note: pinned digest means no
   drift — see 2 below).
2. Alternative: keep the pinned digest, but ALSO run a weekly cron that
   compares the pinned digest to the live `node:22-alpine` digest and
   opens an issue if they differ and no Renovate PR exists.
3. Monitor Renovate dashboard open-PR age. Alert if any PR sits > 3 days
   without merge.

---

### A4. `workflow_run` timing race: publish finishes AFTER rebuild starts (MEDIUM)

`workflow_run` fires when the upstream workflow *completes*. But the
upstream workflow's "complete" can be:

- All jobs succeeded
- Any job failed

If `docker-publish.yml`'s build succeeds but `Test docker image` fails
(the final step), the run is marked failed but the IMAGE IS ALREADY
PUSHED. The rebuild workflow correctly won't fire (guard on
`conclusion == 'success'`), but the release-tags are inconsistent with
`main`/`latest` — which were pushed.

Separately: there's a subtle race where the guard inspects the commit
that triggered publish, but `rebuild-release-tags.yml` then checks out
the latest release tag and rebuilds it. If a NEW release (v4.3.0) is
published between guard check and rebuild execution, the rebuild might
target a release that has its OWN `docker-publish.yml` still in progress
(see A1).

**Fix:**

1. Make `docker-publish.yml`'s `Test docker image` step non-failing
   (accept as advisory), OR short-circuit the push if the test fails.
   Currently it's neither: push happens first, test runs after, test
   failure doesn't roll back. Fix by wiring test BEFORE push (rework
   ordering).
2. Add the mutual concurrency group from A1.

---

### A5. Auto-merge leaves `main` in a state where CI is broken and no human notices (MEDIUM)

If Renovate auto-merges a PR where `docker-image-scan` is NOT a required
status check (see S2), and the post-merge `docker-publish.yml` fails
scan, `main` still has a merged Renovate commit pointing to a
vulnerable digest. The next release will pick up that digest. If release
cadence is weekly and CVEs are fixed faster than that cadence, the stale
`main` causes regressions in consumer Docker images.

**Fix:**

1. Make `docker-image-scan` a REQUIRED check on `main` (see S2).
2. Add a revert-on-failure automation: if the post-merge
   `docker-publish.yml` fails scan, auto-open a revert PR.
3. Require a human-review label for any digest update that skips auto-
   merge (e.g., if scan emits a MEDIUM finding that's below the HIGH
   threshold but still worth eyeballs).

---

### A6. `examples/Dockerfile` drift already exists and is not addressed (LOW)

Verified: `examples/Dockerfile` uses unpinned `FROM node:22-alpine`.
The spec explicitly makes this a non-goal, but:

- Consumers copy the example. Their builds silently inherit upstream
  drift.
- Issue #498 will reappear from copy-paste users.

**Fix:**

1. Either update `examples/Dockerfile` to include a commented reminder
   to pin by digest (a doc fix, not a code fix), OR explicitly note in
   the example's README that this is a template, not a production
   Dockerfile. A comment block:

   ```dockerfile
   # PRODUCTION USERS: pin this base image by digest.
   # The main Dockerfile at repo root uses:
   #   ARG BASE_IMAGE=node:22-alpine@sha256:...
   FROM node:22-alpine
   ```

2. Add a CI lint: grep `examples/Dockerfile` for unpinned `FROM` and
   emit a warning (not a failure) so drift is visible.

---

### A7. Renovate grouping: a digest bump grouped with a minor-version bump bypasses the guard (MEDIUM)

The spec's `packageRules` puts digest updates in auto-merge and
major/minor/patch under human review. But Renovate's default behavior can
GROUP updates — if a future minor `node` version is released
simultaneously with a digest update to an older version, the resulting
PR may contain both. The guard regex (S5) requires ONLY Dockerfile
changed and ONLY digest line changed; a grouped update writes a new tag
(`node:22-alpine` → `node:22.14-alpine@sha256:...`) which changes the
image coordinate AND the digest. The guard correctly REJECTS it (good).
But Renovate's `automerge: true` on the digest rule wins by first-match;
if the PR is classified as digest-update, it auto-merges despite
containing a version change.

**Fix:**

1. In `renovate.json`, add an explicit `groupName: null` and
   `separateMinorPatch: true` under the digest rule to forbid grouping
   with other updates. Use `matchDepNames: ['node']` to narrow further.
2. Add a second package rule that EXPLICITLY lists the allowed mutation
   (`matchCurrentValue: '22-alpine'`) so any tag change disqualifies
   auto-merge:

   ```json
   {
     "matchManagers": ["dockerfile"],
     "matchUpdateTypes": ["digest"],
     "matchDepNames": ["node"],
     "matchCurrentValue": "22-alpine",
     "automerge": true,
     "groupName": null
   }
   ```

3. The workflow-side guard (S5 fix) is the defense in depth. Both layers
   must hold.

---

### A8. `sha-<commit>` immutability contract can be silently violated by workflow-dispatch (LOW-MEDIUM)

The spec says `sha-<commit>` tags are immutable. But `docker-publish.yml`
can be triggered via `workflow_dispatch` with any ref, and the metadata
action emits `type=sha` every time. If someone dispatches against a
historic commit, the `sha-<commit>` tag gets re-pushed — possibly with a
different base image digest than the original push. The existing
workflow has no "refuse to push if sha tag exists" guard.

**Fix:**

1. Add a pre-push check:

   ```yaml
   - name: Verify sha tag immutability
     run: |
       existing=$(gh api "/v2/billchurch/webssh2/manifests/sha-${GITHUB_SHA::7}" \
         --jq '.config.digest' 2>/dev/null || echo "")
       if [ -n "$existing" ]; then
         echo "sha-${GITHUB_SHA::7} already exists (digest $existing). Refusing to overwrite."
         exit 1
       fi
   ```

   Adapt for Docker Hub API (the GH `gh api` command won't reach Docker
   Hub; use curl with auth).

2. Alternatively, make sha-tag push conditional:
   `type=sha,enable=${{ github.event_name == 'push' && github.ref ==
   'refs/heads/main' }}` so dispatched builds never re-push.

---

## Performance

### P1. Dual amd64 build (scan + push) is wasted work on 95% of PRs (LOW)

The split `build → scan → push` pattern does 2 amd64 builds on publish.
On cold cache, that's ~5 min extra. On warm cache, ~30-60s extra. For
99% of PR runs, the Dockerfile hasn't changed and the scan would pass
trivially.

**Fix:**

1. Do a single multi-arch `docker/build-push-action` with `push: false`
   and `outputs: type=docker,dest=/tmp/image.tar` to get a loadable
   artifact for amd64 PLUS cached manifests for arm64. Then `docker
   load` the amd64 tar for Trivy, then re-run `push: true` using the
   cache.
2. Alternative: use `docker buildx build --platform linux/amd64 --load`
   once, scan, then `docker buildx build --platform linux/amd64,
   linux/arm64 --push` with `cache-from=type=gha` so amd64 layers are
   reused from the first build.
3. Quantify before optimizing: a 1-2 min delta on monthly Renovate PRs
   is not a real performance problem. Low severity.

---

### P2. Path-filter misfire rate is high because `.github/workflows/ci.yml` is in the filter (LOW)

The spec includes `.github/workflows/ci.yml` in the
`docker-image-scan` path filter. Every unrelated CI workflow edit (new
step, updated action SHA) triggers a full image build+scan. In a repo
with ~5 workflow changes per month, that's 5 wasted image builds (~15
minutes each).

**Fix:**

Remove `.github/workflows/ci.yml` from the path filter. Include it only
if the ci workflow directly affects the image build (it doesn't; the
image is built in docker-publish.yml, which has its own scanning).
Narrow the filter to:

```yaml
image:
  - 'Dockerfile'
  - 'package-lock.json'
  - 'package.json'
  - '.github/workflows/docker-publish.yml'
  - '.github/workflows/ci.yml'  # ONLY if docker-image-scan job changes
```

Actually: the scan only runs if THIS job's definition changed, which is
circular. Better: include `.github/paths-filter.yml` if the filter
config is externalized, and exclude ci.yml from itself.

---

### P3. Renovate scheduler contention — "before 6am on monday" is when everyone schedules (LOW)

Mend.io's Renovate backend processes scheduled jobs in bursts. Scheduling
at common times (Monday morning, weekly) increases queue latency. No
functional impact, but if the team expects PRs "on Monday" and they
arrive Tuesday, debugging the delay is painful.

**Fix:**

1. Pick an off-peak schedule like `"before 4am on tuesday"` or
   `"every weekday"`.
2. Do not depend on exact timing; drive urgency via the scheduled mirror
   check (A2 fix) rather than Renovate timing.

---

### P4. Trivy DB download amplification across multiple jobs (LOW)

`docker-image-scan` (ci.yml) and the publish-time scan both download
Trivy's DB (~500MB cached). If scheduled safety-net scans are added (A3
fix), that's 3 downloads per run cycle. Each job in
`aquasecurity/trivy-action` re-downloads unless cache is wired.

**Fix:**

Enable `cache: true` on `aquasecurity/trivy-action` (default in
v0.35.0+). Verify the action version already does this, and confirm
`ORAS_CACHE` / `TRIVY_CACHE_DIR` paths are on the GHA `actions/cache`
key so cross-workflow sharing works.

---

## Summary

| ID | Category | Severity | Status |
| --- | --- | --- | --- |
| S1 | Security | HIGH | Open — replace `head_commit.author` with `triggering_actor.login` AND verify commit signature |
| S2 | Security | HIGH | Open — enable repo `allow_auto_merge`, add required status checks, disable force-push on main BEFORE PR 3 |
| S3 | Security | HIGH | Open — checkout `workflow_run.head_sha` everywhere; never read `main` HEAD in the rebuild workflow |
| S4 | Security | MEDIUM | Open — pin dorny/paths-filter to SHA, keep `pull_request` (not `_target`), set workflow-level `permissions: {}` |
| S5 | Security | HIGH | Open — replace regex with structured diff check (whole-file + single-line digest mutation + literal `node:22-alpine` coordinate) |
| S6 | Security | MEDIUM | Open — drop `security-events: write` from PR-triggered scan; upload SARIF only on push |
| S7 | Security | MEDIUM | Open — constrain Renovate auto-merge to known coordinate; require signed Renovate commits; add kill-switch env var |
| S8 | Security | MEDIUM | Open — scope GHA cache by ref; read-only cache on PRs; include `BASE_IMAGE` in `build-args` |
| S9 | Security | MEDIUM | Open — filter `workflow_run` on `conclusion`, `event`, `head_branch` explicitly |
| S10 | Security | MEDIUM | Open — add `concurrency: rebuild-release-tags` group (no cancel-in-progress) |
| S11 | Security | LOW | Open — audit rebuild workflow's comment generation for shell injection via `${{ }}` |
| S12 | Security | MEDIUM | Open — disable `type=sha` in rebuild metadata; assert sha-tag digest unchanged post-push |
| S13 | Security | MEDIUM | Open — use `isLatest == true` filter, reject pre-releases/drafts via strict regex |
| DoW1 | DoW | MEDIUM | Open — authenticate Docker Hub pulls; cancel-in-progress on PR-scan concurrency; skip forks |
| DoW2 | DoW | LOW-MEDIUM | Open — add per-`head_sha` idempotency guard to rebuild workflow |
| DoW3 | DoW | LOW | Open — switch buildx cache to registry cache on GHCR |
| DoW4 | DoW | LOW | Accept as trade-off; verify Trivy severity filters |
| A1 | Availability | HIGH | Open — shared `concurrency: image-publish` group; defer rebuild if release published in last 10 minutes |
| A2 | Availability | HIGH | Open — daily Renovate schedule; mirror base image in GHCR; add fallback ARG |
| A3 | Availability | HIGH | Open — reinstate scheduled safety-net workflow; monitor Renovate dashboard PR age |
| A4 | Availability | MEDIUM | Open — reorder `docker-publish.yml` test-before-push; apply A1 concurrency |
| A5 | Availability | MEDIUM | Open — make `docker-image-scan` required; auto-revert on post-merge failure |
| A6 | Availability | LOW | Open — add doc-level pin reminder to `examples/Dockerfile` |
| A7 | Availability | MEDIUM | Open — in `renovate.json`, forbid grouping for digest rule; narrow by `matchCurrentValue` |
| A8 | Availability | LOW-MEDIUM | Open — pre-push check that `sha-<commit>` tag does not already exist |
| P1 | Performance | LOW | Open — single-build-then-load pattern instead of double build |
| P2 | Performance | LOW | Open — narrow path filter; remove self-referential `ci.yml` path |
| P3 | Performance | LOW | Open — pick an off-peak Renovate schedule |
| P4 | Performance | LOW | Open — enable Trivy `cache: true` and share DB across jobs |

### Critical path before shipping

Must fix before PR 3 (Renovate enablement) or the flow is unsafe:

- **S2** (repo branch protection)
- **S1 + S3 + S5** (guard correctness)
- **A1** (concurrency against release flow)
- **A3** (Renovate availability fallback — at least the mirror check)

Must fix before PR 4 (rebuild workflow):

- **S9 + S10 + S12 + S13** (workflow_run filtering, concurrency, tag
  contract, release selection)
- **A4** (publish test-before-push)

Everything else can ship with mitigations documented.
