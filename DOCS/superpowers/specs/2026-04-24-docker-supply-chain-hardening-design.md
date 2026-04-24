# Docker Supply-Chain Hardening — Design

- Date: 2026-04-24
- Driving issue: [#498](https://github.com/billchurch/webssh2/issues/498)
- Status: Approved; implementation plan to follow

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

## Goals

1. Close #498 with a patched, digest-pinned image the reporter can verify.
2. Auto-rebuild `latest`, `main`, and the most recent release tag series
   (`X.Y.Z`, `X.Y`, `X`) whenever upstream ships a base-image patch.
3. Gate every rebuild with image-level vulnerability scanning so regressions
   in upstream digests never reach consumers.
4. Preserve immutability of `sha-<commit>` tags.

## Non-Goals

- Rebuilding release tag series older than the latest one.
- Scheduled "safety-net" rebuilds on top of the event-driven flow.
- Migrating Docker Hub publishing to OIDC (tracked separately; Docker Hub
  OIDC support is still limited).
- Updating `examples/Dockerfile` — it is a documentation sample, not
  published.

## Architecture

```text
Upstream node:22-alpine digest changes
            │
            ▼
    Renovate bot opens PR
  (digest-only update, grouped separately from version bumps)
            │
            ▼
   ci.yml path-filtered Dockerfile job:
   docker buildx build --load (amd64) → Trivy image scan
            │
   fail? ──► block auto-merge; Renovate dependency dashboard surfaces
            │
            ▼ (pass)
  Renovate auto-merges PR (digest-only, renovate[bot] commits only)
            │
            ▼
  docker-publish.yml (push trigger on main):
   build → Trivy image scan (final audit) → multi-arch push
   publishes: latest, main, sha-<commit>
            │
            ▼
  rebuild-release-tags.yml (workflow_run on docker-publish.yml):
   Guard: triggering commit authored by renovate[bot]
          AND diff touches only Dockerfile
          AND the change is digest-only on BASE_IMAGE
   Fan-out:
     - Resolve latest release tag via `gh release list`
     - Checkout that tag into an ephemeral worktree
     - Build with --build-arg BASE_IMAGE=<new digest>
     - Trivy image scan (fail closed)
     - Multi-arch push: X.Y.Z, X.Y, X (image digest is new;
       sha-<commit> tag on the release commit stays immutable)
     - On success, comment on the GitHub release with the new image
       digest and base-image digest
```

## Components

### 1. `Dockerfile`

Pin `node:22-alpine` by digest through a `BASE_IMAGE` build arg so
event-driven rebuilds can override the digest without editing source:

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
  digest (Alpine 3.23.4) at the time of writing. The hotfix PR (PR 1) pins
  this exact value.
- Using the manifest-list digest preserves multi-arch support
  (`linux/amd64`, `linux/arm64`).
- The `ARG` must be redeclared before each `FROM` stage that references it
  (Docker scoping rule). Declaring it once at the top then referencing via
  `${BASE_IMAGE}` in `FROM` lines only works if the `ARG` is declared in
  each stage before use, or declared as a global `ARG` before the first
  `FROM`. The implementation plan specifies the exact placement.

### 2. `.github/renovate.json` (new)

```json
{
  "$schema": "https://docs.renovatebot.com/renovate-schema.json",
  "extends": ["config:recommended", ":dependencyDashboard"],
  "schedule": ["before 6am on monday"],
  "timezone": "America/New_York",
  "dockerfile": { "enabled": true },
  "packageRules": [
    {
      "description": "Auto-merge digest-only base image updates",
      "matchManagers": ["dockerfile"],
      "matchUpdateTypes": ["digest"],
      "automerge": true,
      "automergeType": "pr",
      "platformAutomerge": true
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

The user is expected to enable the Renovate GitHub App against the
repository as a one-time setup step outside this design.

### 3. `.github/workflows/ci.yml` (modify)

Add a new job `docker-image-scan`, gated by a path filter so it only runs
when relevant files change. Use `dorny/paths-filter` on `pull_request` to
produce an `images` output that gates the subsequent build+scan steps:

```yaml
docker-image-scan:
  runs-on: ubuntu-latest
  if: github.event_name == 'pull_request'
  permissions:
    contents: read
    security-events: write
  steps:
    - uses: actions/checkout@<pinned-sha>  # pinned per supply-chain policy
    - id: filter
      uses: dorny/paths-filter@<pinned-sha>
      with:
        filters: |
          image:
            - 'Dockerfile'
            - 'package-lock.json'
            - '.github/workflows/ci.yml'
    - if: steps.filter.outputs.image == 'true'
      uses: docker/setup-buildx-action@<pinned-sha>
    - if: steps.filter.outputs.image == 'true'
      name: Build image (amd64, load for scanning)
      uses: docker/build-push-action@<pinned-sha>
      with:
        context: .
        load: true
        tags: webssh2:pr-${{ github.event.pull_request.number }}
        platforms: linux/amd64
    - if: steps.filter.outputs.image == 'true'
      name: Trivy image scan
      uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0
      with:
        image-ref: webssh2:pr-${{ github.event.pull_request.number }}
        format: sarif
        output: trivy-image.sarif
        severity: CRITICAL,HIGH
        ignore-unfixed: true
        exit-code: 1
    - if: always() && steps.filter.outputs.image == 'true'
      name: Upload SARIF
      uses: github/codeql-action/upload-sarif@<pinned-sha>
      with:
        sarif_file: trivy-image.sarif
        category: trivy-image
```

`<pinned-sha>` is notation; the implementation plan will resolve each
placeholder to the current upstream release SHA, following the global
supply-chain policy of pinning GitHub Actions by full commit SHA.

The existing filesystem Trivy scan stays; the new job adds image-level
coverage. SARIF category is distinct so both scans surface independently in
the Security tab.

### 4. `.github/workflows/docker-publish.yml` (modify)

Insert an image-scan gate between build and push. Because the current
workflow does a single multi-arch `buildx` push in one step, the
implementation splits that into:

1. Build `linux/amd64` locally with `--load` (scannable).
2. Trivy image scan; fail closed on HIGH/CRITICAL fixable findings.
3. On pass, run the full multi-arch `buildx` build+push. The amd64 layer is
   cached from step 1 via `cache-from: type=gha`.

Trade-off: step 1 duplicates the amd64 build. The GHA cache reuse makes
the push step pull layers from cache instead of rebuilding, so the net
overhead is one extra scan + cache read (~1-2 min).

### 5. `.github/workflows/rebuild-release-tags.yml` (new)

Trigger: `workflow_run` completion of `docker-publish.yml` on `main`.

First job `guard`:

- Exits with success (no-op) unless all of the following hold:
  - `github.event.workflow_run.head_commit.author.username == 'renovate[bot]'`
  - The commit diff touches only `Dockerfile` (verified via `gh api` on
    the commit).
  - The Dockerfile diff modifies only the `BASE_IMAGE` default value
    (regex on `^ARG BASE_IMAGE=...@sha256:[0-9a-f]{64}$`), not any other
    line.

Second job `rebuild` (needs: guard, only runs when guard says "proceed"):

- `gh release list --limit 50 --json tagName --jq '[.[] | select(.tagName | startswith("webssh2-server-v"))][0].tagName'`
  to resolve the latest release tag.
- `gh release download` is not needed; checkout the tag via
  `actions/checkout` with `ref: <tag>`.
- Extract the new base digest from the Dockerfile on `main`:
  `grep -E '^ARG BASE_IMAGE=' Dockerfile`.
- Run the same build → scan → multi-arch push steps as
  `docker-publish.yml`, but with `--build-arg BASE_IMAGE=<new digest>` so
  the release-tag source tree is rebuilt against the fresh base.
- Compute tags using the same semver-derivation logic already present in
  `docker-publish.yml` (extract from release tag name). Publish to
  `X.Y.Z`, `X.Y`, `X`.
- Do **not** republish `sha-<release-commit>` (it already exists and must
  stay immutable on its original digest). The new image digest is tracked
  via the `X.Y.Z` tag's manifest digest and surfaced in the release
  comment.

On success, post a comment to the GitHub release:

```text
🔁 Base image refreshed (no source changes)
- Base image: node:22-alpine@sha256:<new digest>
- Refreshed tags: X.Y.Z, X.Y, X
- New image digest: sha256:<digest>
- Triggered by: <renovate PR link>
```

On scan failure, fail the workflow and let the existing GitHub Actions
notification surface the error. No issue auto-filing in this iteration; if
failures prove frequent, add in a follow-up.

## Data Flow / Tag Strategy

| Event                                  | Tags published                           | Image digest |
| -------------------------------------- | ---------------------------------------- | ------------ |
| Code change merged to `main`           | `latest`, `main`, `sha-<commit>`         | New          |
| Release tag cut                        | `X.Y.Z`, `X.Y`, `X`, optionally `latest` | New          |
| Renovate digest bump merged to `main`  | `latest`, `main`, `sha-<commit>` **and** `X.Y.Z`, `X.Y`, `X` | New for each path |

`sha-<commit>` tags are never moved. Each represents the exact image built
from that commit with whatever base digest was in effect at that time.

## Error Handling

| Failure mode                                | Behavior                                    |
| ------------------------------------------- | ------------------------------------------- |
| Renovate PR fails image scan                | Auto-merge blocked; Renovate dashboard issue surfaces the failure |
| `docker-publish.yml` scan fails             | Publish aborts; `main` and `latest` keep their previous digests |
| `rebuild-release-tags.yml` scan fails       | Release tags keep their previous digests; workflow shows failed status |
| Guard logic misfires (false positive)       | Release tags get rebuilt against same source — idempotent, no harm |
| Guard logic misfires (false negative)       | Release tags stay stale until next Renovate PR or manual dispatch |
| Release tag not found (e.g., pre-first-release) | Workflow exits 0 with a log message     |
| Trivy DB download failure                   | Retry once; on second failure, fail closed  |
| Registry push failure                       | Standard `docker/build-push-action` retries; manual rerun otherwise |

## Testing Strategy

1. **Image scan (PR gate)**: Open a draft PR that pins `BASE_IMAGE` to a
   known-vulnerable historic digest (e.g., an older Alpine with published
   HIGH CVEs). Confirm the `docker-image-scan` job fails and blocks
   merge. Close the draft without merging.
2. **Publish-time scan**: Same technique against a branch that can trigger
   `docker-publish.yml` via `workflow_dispatch`. Confirm publish is
   aborted on scan failure.
3. **Release-tag rebuild guard**: Dispatch `rebuild-release-tags.yml`
   manually with a synthetic `workflow_run` context that does not meet
   the guard criteria (e.g., non-`renovate[bot]` author). Confirm guard
   job exits with "skip" status.
4. **Release-tag rebuild happy path**: After PR 4 merges, simulate via
   manual dispatch with a `simulate=true` input that runs all steps
   except the final `docker push`. Inspect the Trivy report and the tags
   that *would* have been pushed.
5. **End-to-end**: After all PRs are live, wait for the first
   Renovate-generated digest PR. Observe: CI scan runs, auto-merge,
   `docker-publish.yml` fires, `rebuild-release-tags.yml` fans out,
   release-tag image digest changes. Document observed digests in a
   closing comment on #498.

## Rollout Plan

Four PRs, merged in order. Each is individually shippable; no feature
flags needed.

### PR 1 — Hotfix (closes #498)

- Modify `Dockerfile`: add `ARG BASE_IMAGE=node:22-alpine@sha256:<3.23.4 digest>`
  and update each `FROM` line to reference `${BASE_IMAGE}`.
- Verify locally: `docker build . && docker inspect ... | grep Image`.
- Merge, then manually trigger `docker-publish.yml` via `workflow_dispatch`
  with `publish_latest=true`.
- Comment on #498 with the new image digest and base-image digest; close.

### PR 2 — Image scanning

- Add `docker-image-scan` job to `ci.yml` (path-filtered).
- Modify `docker-publish.yml` to split build + scan + push.
- Test via a draft PR with a deliberately bad digest; confirm both gates
  block publication.
- Revert the bad digest; merge the workflow changes.

### PR 3 — Renovate configuration

- Add `.github/renovate.json`.
- User enables Renovate GitHub App against repo.
- Wait for Renovate's onboarding PR; review and merge.
- First real Renovate digest PR validates end-to-end flow.

### PR 4 — Event-driven release-tag rebuild

- Add `.github/workflows/rebuild-release-tags.yml`.
- Include a `simulate` input flag for dry-run testing.
- Run simulated dispatches before the next Renovate digest PR lands.
- After first real fire, document observed behavior in a follow-up issue
  if any adjustments are needed.

## Open Questions (to resolve during planning)

- Renovate timezone choice: design assumes `America/New_York`; confirm
  during planning if different preference.
- Whether to also publish image attestations (`docker build --attest`)
  alongside scans. Valuable for provenance but adds complexity — deferred
  unless user wants it folded in.

## References

- Global policy: `~/.claude/rules/supply-chain-security.md`
- Project CLAUDE.md: `/Users/bill/Documents/GitHub/webssh/webssh2/CLAUDE.md`
- Current Dockerfile: `Dockerfile`
- Current workflows: `.github/workflows/ci.yml`, `.github/workflows/docker-publish.yml`
- Issue: [#498](https://github.com/billchurch/webssh2/issues/498)
