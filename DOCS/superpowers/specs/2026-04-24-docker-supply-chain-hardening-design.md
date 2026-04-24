# Docker Supply-Chain Hardening — Design

- Date: 2026-04-24
- Driving issue: [#498](https://github.com/billchurch/webssh2/issues/498)
- Status: Approved after red-team review (see
  `2026-04-24-docker-supply-chain-hardening-red-team.md`)

## Context

Published image `billchurch/webssh2:sha-159d154` was flagged by a consumer
scanner for CVEs in Alpine 3.23.3 packages (`openssl 3.5.5-r0`,
`musl 1.2.5-r21`). Upstream `node:22-alpine` now resolves to Alpine 3.23.4,
which patches those packages.

Root causes:

1. `Dockerfile` uses the mutable tag `node:22-alpine`. Builds are not
   reproducible and there is no auditable link between upstream base-image
   updates and repo commits.
2. No scheduled or event-driven rebuilds exist. Published tags go stale as
   Alpine ships security patches; nothing republishes `latest`/`main` or the
   most recent release tag series.
3. The Trivy step in `ci.yml` scans the source tree (`scan-type: 'fs'`), not
   the built container image. Base-image CVEs never surface in CI.
4. `docker-publish.yml` has no image-scan gate. A compromised or regressed
   upstream digest could be published without detection.
5. `main` branch protection has no required status checks, no required
   reviews, and allows force-pushes; repo-level `allow_auto_merge` is off.
   Any "auto-merge is safe" story has to start by fixing the repo posture.

## Goals

1. Close #498 with a patched, digest-pinned image the reporter can verify.
2. Auto-rebuild `latest`, `main`, and the most recent release tag series
   (`X.Y.Z`, `X.Y`, `X`) whenever upstream ships a base-image patch.
3. Gate every rebuild with image-level vulnerability scanning so regressions
   in upstream digests never reach consumers.
4. Preserve immutability of `sha-<commit>` tags.
5. Harden repo-level branch protection so the auto-merge pipeline has
   required, enforceable gates.

## Non-Goals

- Rebuilding release tag series older than the latest one.
- Migrating Docker Hub publishing to OIDC (tracked separately; Docker Hub
  OIDC support is still limited).
- Updating `examples/Dockerfile` beyond a documentation-level reminder to
  pin by digest (it is a sample, not a published image).
- Auto-reverting merged Renovate commits on post-merge scan failure (nice
  to have, but deferred).

## Accepted Risks

Documenting risks we are knowingly accepting, to make re-evaluation easy
when they materialize:

1. **Renovate as a single point of failure for CVE patching.** If the
   Renovate GitHub App is paused, uninstalled, rate-limited, or
   misconfigured, base-image CVEs do not land. We accept this rather than
   building a parallel scheduled rebuild, on the premise that: (a)
   Renovate outages are rare and publicly visible, (b) the repo's
   Dependency graph will continue to surface CVEs through GitHub's
   native advisories, (c) we can trigger a rebuild manually via
   `workflow_dispatch` on `docker-publish.yml` within minutes. If
   Renovate misses a CVE in practice, revisit A3 in the red-team
   review and add a scheduled drift-check workflow.
2. **Upstream `node:22-alpine` manifest disappearance** breaks builds
   until Renovate opens a new PR or a human overrides the digest. Same
   mitigation as above: manual dispatch is available.
3. **`docker-publish.yml` test-after-push ordering** (existing defect,
   A4 in the red-team review) is addressed as part of PR 2 since that PR
   already restructures the workflow. Not tracked as a separate risk.

## Notation

`<pinned-sha>` appearing in workflow snippets below is a placeholder. The
implementation plan resolves each one to a full 40-character commit SHA
for the named upstream action, per the project's supply-chain policy.

## Architecture

```text
Upstream node:22-alpine digest changes
            │
            ▼
    Renovate bot opens PR
  (digest-only; forbidden from grouping with version bumps;
   matchDepNames: ['node'], matchCurrentValue: '22-alpine')
            │
            ▼
   ci.yml docker-image-scan (dorny/paths-filter gated):
   - Skip fork PRs (no push secrets available anyway)
   - cancel-in-progress on same PR
   - Authenticate Docker Hub pull (raises anon rate-limit)
   - docker buildx build --load (amd64) with --build-arg BASE_IMAGE
   - Trivy image scan, exit-code: 1 on CRITICAL/HIGH fixable
   - NO security-events: write (scan is advisory via exit code only)
            │
   fail? ──► block merge (job is a REQUIRED status check on main)
            │
            ▼ (pass)
  Required-check passes → Renovate platformAutomerge completes
            │
            ▼
  docker-publish.yml (push trigger on main):
   1. Build amd64 --load (scannable)
   2. Trivy image scan (fail closed)
   3. Smoke-test amd64 image (moved before push)
   4. Multi-arch buildx build+push (reuses cache)
   Publishes: latest, main, sha-<commit>
   SARIF uploaded under trivy-image category
            │
            ▼
  rebuild-release-tags.yml (workflow_run on docker-publish.yml):
   on:
     workflow_run:
       workflows: ['docker-publish']
       types: [completed]
       branches: [main]
   Guard job (structured checks, attacker-resistant):
     a. workflow_run.conclusion == 'success'
     b. workflow_run.event == 'push'
     c. workflow_run.head_branch == 'main'
     d. workflow_run.triggering_actor.login == 'renovate[bot]'
     e. workflow_run.actor.login == 'renovate[bot]'
     f. Commit at head_sha has verified signature AND signer is Renovate
        GitHub App (via /commits/{sha} .commit.verification)
     g. Diff at head_sha touches exactly one file: Dockerfile
     h. Diff is a single-line replacement where old and new both match
        ^ARG BASE_IMAGE=node:22-alpine@sha256:[0-9a-f]{64}$
     i. No renames, mode changes, or other diff-status markers
     j. Less than 10 minutes since the latest GitHub release was
        published (defers to release flow if a release is mid-publish)
     k. Repo variable ALLOW_AUTO_REBUILD == 'true' (kill-switch)
   Rebuild job (only if guard passes):
     - actions/checkout with ref: workflow_run.head_sha
     - Extract new digest from Dockerfile at that exact SHA
     - actions/checkout latest release tag (isLatest==true, strict
       ^webssh2-server-v[0-9]+\.[0-9]+\.[0-9]+$ regex) into a worktree
     - docker buildx build --build-arg BASE_IMAGE=<new digest>
     - Trivy image scan (fail closed)
     - Publish X.Y.Z, X.Y, X ONLY (type=sha disabled in metadata-action)
     - Post-push assertion: registry digest of sha-<release-commit> is
       unchanged from pre-rebuild snapshot
     - Comment on the GitHub release with the new base + image digests
   concurrency:
     - Shared group 'image-publish' with docker-publish.yml (queue, don't cancel)
     - Per-head_sha idempotency check (skip if already rebuilt for this SHA)
```

## Components

### 0. Repository settings (PR 0, operator-run)

Before any workflow changes ship, apply repo-level hardening via
`gh api` (operator runs these; they are not workflow-editable):

```bash
# Enable auto-merge at repo level
gh api -X PATCH repos/billchurch/webssh2 -f allow_auto_merge=true

# Lock branch protection on main
gh api -X PUT repos/billchurch/webssh2/branches/main/protection \
  --input - <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "build-lint-test",
      "docker-image-scan"
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": null,
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_linear_history": false,
  "required_conversation_resolution": false,
  "lock_branch": false,
  "allow_fork_syncing": true,
  "required_signatures": true
}
JSON
```

Notes:

- `required_pull_request_reviews: null` preserves current "no review
  required" posture (Renovate auto-merge depends on this). If the
  operator later wants human review for non-Renovate PRs, add a CODEOWNERS
  rule and flip this back on — the auto-merge path still works when PR
  authors match an approved bot.
- `required_signatures: true` keeps the existing posture and is load-bearing
  for S1 in the red-team review: the rebuild workflow verifies that the
  Renovate commit is signed by Renovate's GitHub App key.
- `docker-image-scan` must be listed verbatim as it appears in the
  workflow. To handle path-filter skips without failing the required
  check, the job always runs a no-op "filter" step and reports success;
  the expensive build+scan steps are conditional on the filter output.
  Skipped jobs satisfy the required check as long as they complete.

### 1. `Dockerfile`

Pin `node:22-alpine` by manifest-list digest through a `BASE_IMAGE` build
arg so event-driven rebuilds can override without editing source:

```dockerfile
# syntax=docker/dockerfile:1.7

ARG BASE_IMAGE=node:22-alpine@sha256:cb15fca92530d7ac113467696cf1001208dac49c3c64355fd1348c11a88ddf8f

FROM ${BASE_IMAGE} AS deps
...

FROM ${BASE_IMAGE} AS builder
...

FROM ${BASE_IMAGE} AS runtime
...
```

Notes:

- The digest above is the currently-published `node:22-alpine` manifest-list
  digest (Alpine 3.23.4) at the time of writing; the hotfix PR (PR 1)
  uses this exact value.
- Manifest-list digest preserves multi-arch (`linux/amd64`, `linux/arm64`).
- `ARG` scoping: global `ARG BASE_IMAGE=` declared before the first
  `FROM`. Renovate's `dockerfile` manager rewrites the ARG default when
  the digest changes; no per-stage redeclaration is needed because each
  `FROM` references the global ARG directly.
- `examples/Dockerfile` gets a non-functional comment pointing readers
  to pin by digest (doc-only update; no behavior change).

### 2. `.github/renovate.json` (new)

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended", ":dependencyDashboard"],
  "schedule": ["* 0-6 * * *"],
  "timezone": "America/New_York",
  "dockerfile": { "enabled": true },
  "packageRules": [
    {
      "description": "Auto-merge digest-only base image updates for node:22-alpine",
      "matchManagers": ["dockerfile"],
      "matchUpdateTypes": ["digest"],
      "matchDepNames": ["node"],
      "matchCurrentValue": "22-alpine",
      "automerge": true,
      "automergeType": "pr",
      "platformAutomerge": true,
      "groupName": null,
      "separateMinorPatch": true
    },
    {
      "description": "Require human review for base image version bumps",
      "matchManagers": ["dockerfile"],
      "matchUpdateTypes": ["major", "minor", "patch"],
      "automerge": false
    }
  ]
}
```

Notes:

- Schedule runs daily during the 0-6 EST window, not weekly. A weekly
  schedule leaves a multi-day gap between upstream Alpine patch and PR
  open. Daily is low-cost for Renovate and lowers the attack window.
- `matchDepNames: ['node']` + `matchCurrentValue: '22-alpine'` narrows
  auto-merge to the one coordinate we actually trust. Any deviation (a
  typo-squat, a `node:22-apline`, or a different tag) falls through to
  the version-bump rule and requires review.
- `groupName: null` + `separateMinorPatch: true` prevents Renovate from
  bundling a digest bump with a version change into one PR; the
  workflow-side guard (component 5) is defense in depth.
- Enabling the Renovate GitHub App against the repo is a one-time
  operator step, listed in the rollout plan.

### 3. `.github/workflows/ci.yml` (modify)

Add a `docker-image-scan` job. The job always runs (so it satisfies the
required status check) but only builds and scans when a relevant file
changed. Fork PRs are skipped entirely.

```yaml
docker-image-scan:
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'
  concurrency:
    group: docker-image-scan-${{ github.event.pull_request.number }}
    cancel-in-progress: true
  permissions:
    contents: read
  steps:
    - uses: actions/checkout@<pinned-sha>
    - id: filter
      uses: dorny/paths-filter@<pinned-sha>
      with:
        filters: |
          image:
            - 'Dockerfile'
            - 'package-lock.json'
            - 'package.json'
            - '.github/workflows/docker-publish.yml'
    - name: Skip when nothing image-relevant changed
      if: steps.filter.outputs.image != 'true'
      run: echo "No image-relevant changes; passing required check."
    - name: Skip fork PRs
      if: >-
        steps.filter.outputs.image == 'true' &&
        github.event.pull_request.head.repo.full_name != github.repository
      run: echo "Fork PR; image scan skipped (advisory; main-branch scan is the gate)."
    # Real work only runs for non-fork, image-relevant PRs
    - if: >-
        steps.filter.outputs.image == 'true' &&
        github.event.pull_request.head.repo.full_name == github.repository
      uses: docker/login-action@<pinned-sha>
      with:
        username: ${{ secrets.DOCKERHUB_USERNAME }}
        password: ${{ secrets.DOCKERHUB_TOKEN }}
    - if: >-
        steps.filter.outputs.image == 'true' &&
        github.event.pull_request.head.repo.full_name == github.repository
      uses: docker/setup-buildx-action@<pinned-sha>
    - if: >-
        steps.filter.outputs.image == 'true' &&
        github.event.pull_request.head.repo.full_name == github.repository
      name: Build amd64 image for scanning
      uses: docker/build-push-action@<pinned-sha>
      with:
        context: .
        load: true
        tags: webssh2:pr-${{ github.event.pull_request.number }}
        platforms: linux/amd64
        cache-from: type=gha,scope=publish-refs/heads/main
    - if: >-
        steps.filter.outputs.image == 'true' &&
        github.event.pull_request.head.repo.full_name == github.repository
      name: Trivy image scan
      uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0
      with:
        image-ref: webssh2:pr-${{ github.event.pull_request.number }}
        format: table
        severity: CRITICAL,HIGH
        ignore-unfixed: true
        exit-code: 1
        cache: true
```

Design choices and red-team mitigations:

- No `security-events: write` on this job (S6). PR scan is advisory via
  `exit-code: 1`; SARIF upload happens only on push, from
  `docker-publish.yml`. Prevents attacker-supplied SARIF pollution.
- Job always completes with success when nothing image-relevant changed,
  so it satisfies the required status check. Expensive steps are
  conditional on `filter.outputs.image == 'true'`.
- `cache-from: type=gha,scope=publish-refs/heads/main` (read-only; no
  `cache-to`) so PRs benefit from the main-line cache without being able
  to poison it (S8).
- Docker Hub authenticated pull (DoW1) raises the anon rate-limit from
  100 to 200 pulls / 6 hours, which matters during PR storms.
- Fork PRs skip the build step because they cannot access
  `DOCKERHUB_TOKEN`. The trade-off (fork contributors don't get local
  scan feedback) is acceptable; the post-merge `docker-publish.yml` scan
  is the enforcement point.

### 4. `.github/workflows/docker-publish.yml` (modify)

Restructure to a four-phase flow: build amd64 → scan → smoke-test → push
multi-arch. This addresses:

- Image-scan gate (primary design requirement).
- A4 in the red-team review (pre-existing defect: test-after-push).

```yaml
concurrency:
  group: image-publish                 # shared with rebuild-release-tags.yml (A1)
  cancel-in-progress: false

jobs:
  build-and-push:
    steps:
      # ... existing checkout, qemu, buildx, login steps ...

      - name: Build amd64 image (load, for scan + smoke)
        uses: docker/build-push-action@<pinned-sha>
        with:
          context: .
          load: true
          platforms: linux/amd64
          tags: local/webssh2:scan
          build-args: |
            BASE_IMAGE=<read from Dockerfile ARG default>
          cache-from: type=gha
          cache-to: type=gha,mode=max,scope=publish-${{ github.ref }}

      - name: Trivy image scan (fail closed)
        uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0
        with:
          image-ref: local/webssh2:scan
          format: sarif
          output: trivy-image.sarif
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: 1
          cache: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@<pinned-sha>
        with:
          sarif_file: trivy-image.sarif
          category: trivy-image

      - name: Smoke-test amd64 image
        run: |
          CONTAINER_ID=$(docker run -d --rm \
            -e DEBUG=webssh2:* local/webssh2:scan)
          for i in {1..30}; do
            if docker logs "$CONTAINER_ID" 2>&1 | grep -q "server started successfully"; then
              docker stop "$CONTAINER_ID"; exit 0
            fi
            sleep 1
          done
          docker logs "$CONTAINER_ID" && docker stop "$CONTAINER_ID" && exit 1

      - name: Multi-arch build and push
        id: build
        uses: docker/build-push-action@<pinned-sha>
        with:
          context: .
          push: true
          platforms: linux/amd64,linux/arm64
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}
          cache-from: type=gha,scope=publish-${{ github.ref }}
          cache-to: type=gha,mode=max,scope=publish-${{ github.ref }}
```

Design choices:

- `concurrency.group: image-publish` is shared with the new rebuild
  workflow so the two cannot interleave pushes during a release (A1).
  `cancel-in-progress: false` queues rather than aborts.
- Cache scope keyed to `github.ref` (S8) so feature branches can never
  write into the main publish cache.
- Smoke test runs BEFORE the multi-arch push (A4). The existing
  "Test docker image" step that ran post-push is removed.
- `type=sha` in metadata-action already produces `sha-<commit>`. That's
  fine here — this workflow is the original source of truth for that
  tag. S12's mitigation is confined to the rebuild workflow.

### 5. `.github/workflows/rebuild-release-tags.yml` (new)

```yaml
name: rebuild-release-tags

on:
  workflow_run:
    workflows: ['docker-publish']
    types: [completed]
    branches: [main]

concurrency:
  group: image-publish                 # shared with docker-publish.yml (A1)
  cancel-in-progress: false

permissions:
  contents: read
  packages: write

jobs:
  guard:
    runs-on: ubuntu-latest
    outputs:
      proceed: ${{ steps.decide.outputs.proceed }}
      head_sha: ${{ github.event.workflow_run.head_sha }}
      new_digest: ${{ steps.extract.outputs.new_digest }}
      release_tag: ${{ steps.release.outputs.tag }}
    if: >-
      github.event.workflow_run.conclusion == 'success' &&
      github.event.workflow_run.event == 'push' &&
      github.event.workflow_run.head_branch == 'main' &&
      github.event.workflow_run.triggering_actor.login == 'renovate[bot]' &&
      github.event.workflow_run.actor.login == 'renovate[bot]' &&
      vars.ALLOW_AUTO_REBUILD == 'true'
    steps:
      - name: Checkout at head_sha (not main HEAD)
        uses: actions/checkout@<pinned-sha>
        with:
          ref: ${{ github.event.workflow_run.head_sha }}
          fetch-depth: 0
      - name: Verify commit is signed by Renovate GitHub App
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
        run: |
          verification=$(gh api repos/${{ github.repository }}/commits/${HEAD_SHA} \
            --jq '.commit.verification')
          verified=$(echo "$verification" | jq -r '.verified')
          reason=$(echo "$verification"  | jq -r '.reason')
          if [ "$verified" != "true" ] || [ "$reason" != "valid" ]; then
            echo "::error::Commit ${HEAD_SHA} is not signed-and-verified"
            exit 1
          fi
      - name: Verify diff is digest-only on Dockerfile
        env:
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
        run: |
          parent=$(git rev-parse ${HEAD_SHA}^)
          files=$(git diff --name-status "${parent}" "${HEAD_SHA}")
          [ "$files" = $'M\tDockerfile' ] || { echo "::error::Unexpected diff: $files"; exit 1; }
          hunks=$(git diff "${parent}" "${HEAD_SHA}" -- Dockerfile | \
                  grep -E '^[+-]ARG BASE_IMAGE=' || true)
          removed=$(echo "$hunks" | grep -c '^-ARG BASE_IMAGE=' || true)
          added=$(echo   "$hunks" | grep -c '^+ARG BASE_IMAGE=' || true)
          if [ "$removed" != "1" ] || [ "$added" != "1" ]; then
            echo "::error::Expected exactly one BASE_IMAGE line change; got -$removed +$added"
            exit 1
          fi
          pattern='^[+-]ARG BASE_IMAGE=node:22-alpine@sha256:[0-9a-f]{64}$'
          echo "$hunks" | grep -Eq "$pattern" || { echo "::error::Diff lines do not match strict pattern"; exit 1; }
      - name: Defer if release was published in last 10 minutes
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          published=$(gh release list --limit 1 --json publishedAt --jq '.[0].publishedAt')
          if [ -n "$published" ] && [ $(( $(date +%s) - $(date -d "$published" +%s) )) -lt 600 ]; then
            echo "::error::Release published within 10 minutes; deferring to release flow"
            exit 1
          fi
      - id: extract
        name: Extract new BASE_IMAGE digest from Dockerfile at head_sha
        run: |
          digest=$(grep -E '^ARG BASE_IMAGE=' Dockerfile | head -1 | sed 's/^ARG BASE_IMAGE=//')
          echo "new_digest=$digest" >> "$GITHUB_OUTPUT"
      - id: release
        name: Resolve latest release tag via isLatest
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          tag=$(gh release list --limit 50 --json tagName,isLatest,isDraft,isPrerelease \
                --jq '.[] | select(.isLatest==true and .isDraft==false and .isPrerelease==false) | .tagName')
          if ! [[ "$tag" =~ ^webssh2-server-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "::notice::No qualifying release tag; skipping"
            echo "tag=" >> "$GITHUB_OUTPUT"
          else
            echo "tag=$tag" >> "$GITHUB_OUTPUT"
          fi
      - id: decide
        name: Per-head_sha idempotency check
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          HEAD_SHA: ${{ github.event.workflow_run.head_sha }}
          RELEASE_TAG: ${{ steps.release.outputs.tag }}
        run: |
          if [ -z "$RELEASE_TAG" ]; then echo "proceed=false" >> "$GITHUB_OUTPUT"; exit 0; fi
          body=$(gh release view "$RELEASE_TAG" --json body --jq '.body')
          if echo "$body" | grep -q "rebuild-sha: ${HEAD_SHA}"; then
            echo "::notice::Already rebuilt for ${HEAD_SHA}"
            echo "proceed=false" >> "$GITHUB_OUTPUT"
          else
            echo "proceed=true" >> "$GITHUB_OUTPUT"
          fi

  rebuild:
    runs-on: ubuntu-latest
    needs: guard
    if: needs.guard.outputs.proceed == 'true'
    permissions:
      contents: write       # to post release comment
      packages: write
    env:
      HEAD_SHA: ${{ needs.guard.outputs.head_sha }}
      NEW_DIGEST: ${{ needs.guard.outputs.new_digest }}
      RELEASE_TAG: ${{ needs.guard.outputs.release_tag }}
    steps:
      - name: Snapshot existing sha-tag digest (for post-push assertion)
        env:
          RELEASE_TAG: ${{ env.RELEASE_TAG }}
        run: |
          # release commit SHA from tag
          release_sha=$(gh api repos/${{ github.repository }}/git/ref/tags/${RELEASE_TAG} \
            --jq '.object.sha')
          echo "RELEASE_SHA=${release_sha}" >> "$GITHUB_ENV"
          # query Docker Hub for current sha-<short> digest
          short=${release_sha:0:7}
          before=$(curl -fsSL "https://hub.docker.com/v2/repositories/billchurch/webssh2/tags/sha-${short}" \
            | jq -r '.digest' 2>/dev/null || echo "")
          echo "SHA_TAG_DIGEST_BEFORE=${before}" >> "$GITHUB_ENV"

      - name: Checkout release tag source into worktree
        uses: actions/checkout@<pinned-sha>
        with:
          ref: ${{ env.RELEASE_SHA }}
          path: release-src
          fetch-depth: 0

      - name: Overlay new BASE_IMAGE digest onto release-src Dockerfile
        working-directory: release-src
        run: |
          sed -i "s|^ARG BASE_IMAGE=.*|ARG BASE_IMAGE=${NEW_DIGEST}|" Dockerfile
          grep -E '^ARG BASE_IMAGE=' Dockerfile   # sanity check

      - uses: docker/setup-qemu-action@<pinned-sha>
      - uses: docker/setup-buildx-action@<pinned-sha>
      - uses: docker/login-action@<pinned-sha>
        with:
          registry: docker.io
          username: ${{ secrets.DOCKERHUB_USERNAME }}
          password: ${{ secrets.DOCKERHUB_TOKEN }}
      - uses: docker/login-action@<pinned-sha>
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build amd64 for scan
        uses: docker/build-push-action@<pinned-sha>
        with:
          context: release-src
          load: true
          platforms: linux/amd64
          tags: local/webssh2-rebuild:scan

      - name: Trivy image scan (fail closed)
        uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0
        with:
          image-ref: local/webssh2-rebuild:scan
          format: sarif
          output: trivy-rebuild.sarif
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: 1
          cache: true

      - name: Derive semver tags
        id: semver
        run: |
          tag="${RELEASE_TAG#webssh2-server-v}"
          major="${tag%%.*}"
          minor="${tag%.*}"
          echo "full=$tag"     >> "$GITHUB_OUTPUT"
          echo "minor=$minor"  >> "$GITHUB_OUTPUT"
          echo "major=$major"  >> "$GITHUB_OUTPUT"

      - name: Multi-arch build and push (semver tags ONLY; no sha-tag)
        uses: docker/build-push-action@<pinned-sha>
        id: push
        with:
          context: release-src
          push: true
          platforms: linux/amd64,linux/arm64
          tags: |
            docker.io/billchurch/webssh2:${{ steps.semver.outputs.full }}
            docker.io/billchurch/webssh2:${{ steps.semver.outputs.minor }}
            docker.io/billchurch/webssh2:${{ steps.semver.outputs.major }}
            ghcr.io/billchurch/webssh2:${{ steps.semver.outputs.full }}
            ghcr.io/billchurch/webssh2:${{ steps.semver.outputs.minor }}
            ghcr.io/billchurch/webssh2:${{ steps.semver.outputs.major }}

      - name: Assert sha-tag digest unchanged
        run: |
          short=${RELEASE_SHA:0:7}
          after=$(curl -fsSL "https://hub.docker.com/v2/repositories/billchurch/webssh2/tags/sha-${short}" \
            | jq -r '.digest')
          if [ "$after" != "${SHA_TAG_DIGEST_BEFORE}" ]; then
            echo "::error::sha-${short} digest changed from ${SHA_TAG_DIGEST_BEFORE} to ${after}"
            exit 1
          fi

      - name: Comment on release with new image digest
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_URL: ${{ github.event.workflow_run.pull_requests[0].html_url }}
          IMAGE_DIGEST: ${{ steps.push.outputs.digest }}
        run: |
          body=$(printf '%s\n' \
            "🔁 Base image refreshed (no source changes)" \
            "- Base image: ${NEW_DIGEST}" \
            "- Refreshed tags: ${RELEASE_TAG#webssh2-server-v}, ${{ steps.semver.outputs.minor }}, ${{ steps.semver.outputs.major }}" \
            "- New image digest: ${IMAGE_DIGEST}" \
            "- Triggered by: ${PR_URL}" \
            "" \
            "rebuild-sha: ${HEAD_SHA}")
          current=$(gh release view "$RELEASE_TAG" --json body --jq '.body')
          gh release edit "$RELEASE_TAG" --notes "${current}

${body}"
```

Design choices and red-team mitigations (paren refs):

- Guard `if:` uses `triggering_actor.login` + `actor.login` (both GH-
  verified) and verifies commit signature (S1, S7).
- All git/API reads are keyed to `workflow_run.head_sha`, never `main`
  HEAD (S3).
- Structured diff check: `git diff --name-status` requires exactly
  `M<tab>Dockerfile`, then a strict regex requires exactly one removed
  and one added `ARG BASE_IMAGE=node:22-alpine@sha256:<64 hex>` line
  (S5).
- `workflow_run` is filtered on `conclusion`, `event`, and
  `head_branch` explicitly (S9).
- `concurrency.group: image-publish` is shared with `docker-publish.yml`
  (S10, A1). A 10-minute defer check guards against the release-flow
  race explicitly (A1).
- Release tag resolved via `isLatest==true` + strict regex excluding
  drafts and pre-releases (S13).
- `type=sha` is omitted entirely from the tag list; only semver tags
  are pushed. Post-push assertion reads Docker Hub and fails if the
  release-commit `sha-<short>` tag digest changed (S12).
- Per-`head_sha` idempotency via marker string in release body (DoW2).
- `ALLOW_AUTO_REBUILD` repo variable acts as a manual kill-switch (S7).

### 6. `examples/Dockerfile`

Comment-only update:

```dockerfile
# NOTE: This is a documentation sample, not the production Dockerfile.
# For production, pin the base image by manifest digest — see the
# repo-root Dockerfile:
#   ARG BASE_IMAGE=node:22-alpine@sha256:...
FROM node:22-alpine
```

No build behavior changes; Renovate does not auto-manage this file.

## Data Flow / Tag Strategy

| Event                                  | Tags published                           | Image digest |
| -------------------------------------- | ---------------------------------------- | ------------ |
| Code change merged to `main`           | `latest`, `main`, `sha-<commit>`         | New          |
| Release tag cut                        | `X.Y.Z`, `X.Y`, `X`, `sha-<release-commit>`, optionally `latest` | New          |
| Renovate digest bump merged to `main`  | `latest`, `main`, `sha-<renovate-commit>` **and** `X.Y.Z`, `X.Y`, `X` (no sha-tag) | New for each path |

`sha-<commit>` tags are never moved after their original publish. The
rebuild workflow explicitly does not push a sha-tag; it asserts the
release-commit sha-tag digest is unchanged as a safety check.

## Error Handling

| Failure mode                                     | Behavior                                    |
| ------------------------------------------------ | ------------------------------------------- |
| Renovate PR fails image scan                     | Required check fails; PR blocked; auto-merge does not fire |
| Renovate PR author impersonation                 | Signature verification fails at guard step g; rebuild job does not run |
| Grouped version+digest PR reaches main           | Structured diff check fails; rebuild skipped |
| `docker-publish.yml` scan fails                  | Publish aborts; existing `latest`/`main` tags unchanged |
| Rebuild workflow race with release flow          | Shared `image-publish` concurrency queues them; 10-minute defer adds belt-and-suspenders |
| Rebuild workflow scan fails                      | Release tags unchanged; workflow shows failed status |
| Release tag deleted or missing `isLatest`        | Guard exits with `proceed=false`; no-op |
| `ALLOW_AUTO_REBUILD` set to false (kill-switch)  | Guard job's `if:` fails; rebuild does not run |
| Upstream `node:22-alpine` digest disappears      | Builds fail; Renovate opens a new PR (daily schedule); manual dispatch available as fallback |
| Trivy DB download failure                        | Action retries; repeated failure fails closed |
| Post-push sha-tag digest changed                 | Workflow fails loudly; tags are already pushed so manual remediation needed (should be unreachable) |

## Testing Strategy

1. **Repo-level protection (PR 0):** After applying, open a throwaway PR
   from a branch that has no `docker-image-scan` change; verify the
   required check passes as a "skipped but successful" job.
2. **Image scan (PR 2):** Draft PR pinning `BASE_IMAGE` to a historic
   digest with known HIGH CVEs; confirm `docker-image-scan` fails and
   blocks merge. Close draft.
3. **Publish-time scan (PR 2):** Dispatch `docker-publish.yml` via
   `workflow_dispatch` on a branch with the same bad digest; confirm the
   multi-arch push is aborted.
4. **Smoke-test ordering (PR 2):** On a branch with a broken entrypoint,
   confirm the workflow fails before push and the `latest` tag is
   unchanged.
5. **Renovate wiring (PR 3):** After enabling the app, observe the
   onboarding PR; verify `renovate.json` takes effect on the first
   real digest PR.
6. **Rebuild guard — happy path (PR 4):** Manual dispatch with
   `simulate=true` input (added to workflow for testing only) against
   the latest Renovate merge; inspect each guard step's output.
7. **Rebuild guard — negative cases:** Dispatch with contrived
   `workflow_run` contexts missing each guard criterion; confirm the
   job's `if:` evaluates to false.
8. **End-to-end:** Wait for the first real Renovate digest PR after all
   PRs land. Observe: CI scan passes → auto-merge → `docker-publish.yml`
   fires → `rebuild-release-tags.yml` guard passes → release tags
   republished. Document observed digests in a closing comment on #498.

## Rollout Plan

Five PRs (PR 0 is operator-run, not code), each individually shippable.

### PR 0 — Repo settings (operator runs gh api commands)

- Apply `allow_auto_merge=true`.
- Lock `main` branch protection: required status checks = `[build-lint-test,
  docker-image-scan]`, no force-pushes, signed commits required.
- Verify via `gh api repos/billchurch/webssh2/branches/main/protection`.
- Create repo variable `ALLOW_AUTO_REBUILD=true`.

### PR 1 — Hotfix (closes #498)

- Modify `Dockerfile`: add global `ARG BASE_IMAGE=node:22-alpine@sha256:<3.23.4 digest>`.
  Update each `FROM` to `FROM ${BASE_IMAGE}`.
- Verify locally: `docker build -t test . && docker inspect test --format '{{.Image}}'`.
- Merge. Manually dispatch `docker-publish.yml` with `publish_latest=true`.
- Comment on #498 with new image digest + base-image digest; close.

### PR 2 — Image scanning + publish restructure

- Add `docker-image-scan` job to `ci.yml` (always runs, conditionally does work).
- Restructure `docker-publish.yml` to four-phase: build amd64 → scan →
  smoke-test → multi-arch push.
- Add shared `concurrency.group: image-publish`.
- Scope GHA cache by ref.
- Verify via deliberately bad digest in a draft PR; confirm both gates
  block. Revert bad digest; merge.

### PR 3 — Renovate configuration + examples/Dockerfile comment

- Add `.github/renovate.json` with the rules in component 2.
- Add pinning reminder comment to `examples/Dockerfile`.
- Operator enables Renovate GitHub App against the repo.
- Wait for Renovate's onboarding PR; review and merge.
- Do NOT merge any real digest PR from Renovate until PR 4 ships — until
  then, `rebuild-release-tags.yml` does not exist and only `latest`/`main`
  will refresh.

### PR 4 — Event-driven release-tag rebuild

- Add `.github/workflows/rebuild-release-tags.yml` per component 5.
- Include `simulate` input on `workflow_dispatch` for dry-run testing
  (short-circuits the actual `docker push`).
- Run simulated dispatches against all guard criteria (positive and
  negative cases).
- Arm in production. Document observed digests in a closing comment on
  #498 after first real fire.

## Follow-Ups (Deferred)

Tracked as future issues, not blocking the rollout:

- **GHCR registry cache** instead of GHA cache (DoW3).
- **Auto-revert on post-merge scan failure** (A5 extension).
- **Pre-push sha-tag immutability check** in `docker-publish.yml` for
  `workflow_dispatch` against historic commits (A8).
- **Docker Hub credential scope audit** — verify `DOCKERHUB_TOKEN`
  scope is "write only to `billchurch/webssh2`"; narrow if broader.
- **Image attestations** (`docker build --attest=type=provenance`) for
  verifiable build provenance.

## References

- Global supply-chain policy: `~/.claude/rules/supply-chain-security.md`
- Project instructions: `CLAUDE.md`
- Red-team review:
  `DOCS/superpowers/specs/2026-04-24-docker-supply-chain-hardening-red-team.md`
- Current Dockerfile: `Dockerfile`
- Current workflows: `.github/workflows/ci.yml`,
  `.github/workflows/docker-publish.yml`
- Issue: [#498](https://github.com/billchurch/webssh2/issues/498)
