# Docker Supply-Chain Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close issue #498 and eliminate the class of bug it represents by digest-pinning the base image, gating every publish with a Trivy image scan, auto-merging Renovate digest bumps, and fanning out rebuilds to the most recent release tag series.

**Architecture:** Five PRs landed in order. PR 0 hardens repo-level branch protection so auto-merge is enforceable. PR 1 ships the Dockerfile digest pin as a hotfix that closes the user-visible issue. PR 2 adds image-level Trivy scanning to both PR CI and the publish workflow, and restructures the publish workflow so the smoke test runs before the push. PR 3 wires Renovate with tightly-scoped auto-merge rules. PR 4 adds the `workflow_run`-triggered release-tag rebuild, with an attacker-resistant guard (triggering-actor check, signed-commit verification, structured diff check, `isLatest` release selection, sha-tag immutability assertion).

**Tech Stack:** Docker + BuildKit, GitHub Actions, `dorny/paths-filter`, `aquasecurity/trivy-action` v0.35.0, `docker/build-push-action` v6.18.0, Renovate (Mend.io-hosted GitHub App), `gh` CLI.

---

## Reference Spec

`DOCS/superpowers/specs/2026-04-24-docker-supply-chain-hardening-design.md`

## Reference Red-Team Review

`DOCS/superpowers/specs/2026-04-24-docker-supply-chain-hardening-red-team.md`

## Pinned Action SHAs (use these verbatim in every workflow file)

| Action | SHA + version |
| --- | --- |
| `actions/checkout` | `11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2` |
| `actions/setup-node` | `49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0` |
| `aquasecurity/trivy-action` | `57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0` |
| `docker/build-push-action` | `263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0` |
| `docker/login-action` | `5e57cd118135c172c3672efd75eb46360885c0ef # v3.6.0` |
| `docker/metadata-action` | `c299e40c65443455700f0fdfc63efafe5b349051 # v5.10.0` |
| `docker/setup-buildx-action` | `e468171a9de216ec08956ac3ada2f0791b6bd435 # v3.11.1` |
| `docker/setup-qemu-action` | `c7c53464625b32c7a7e944ae62b3e17d2b600130 # v3.7.0` |
| `github/codeql-action/upload-sarif` | `ff0a06e83cb2de871e5a09832bc6a81e7276941f # v3.28.18` |
| `dorny/paths-filter` | `de90cc6fb38fc0963ad72b210f1f284cd68cea36 # v3.0.2` |

If any of these SHAs need to be refreshed at implementation time, look up the action's latest release on GitHub and record the new SHA alongside the version number.

## File Structure

| File | Responsibility | Touched in |
| --- | --- | --- |
| `Dockerfile` | Production multi-stage build; global `ARG BASE_IMAGE=<pinned digest>` | PR 1 |
| `examples/Dockerfile` | Documentation sample; pinning reminder comment only | PR 3 |
| `.github/workflows/ci.yml` | Adds `docker-image-scan` job (always-run, conditional work) | PR 2 |
| `.github/workflows/docker-publish.yml` | Restructure to build → scan → smoke → push; shared concurrency; ref-scoped cache | PR 2 |
| `.github/workflows/rebuild-release-tags.yml` | NEW: workflow_run-triggered release-tag rebuild with guard + rebuild jobs | PR 4 |
| `.github/renovate.json` | NEW: digest-only auto-merge rules for `node:22-alpine` | PR 3 |

No source code files change. This is entirely a build/CI/ops plan.

---

## PR 0 — Repository Settings (Operator-Run)

This PR has no code. It consists of `gh api` calls the operator runs locally. The calls need admin permission on the repo.

### Task 0.1: Snapshot current branch protection

**Files:** none

- [ ] **Step 1: Capture current protection**

Run:

```bash
gh api repos/billchurch/webssh2/branches/main/protection > /tmp/protection.before.json
```

Expected: writes a JSON file. If the command fails with 404, `main` has no protection rule; record that fact explicitly in `/tmp/protection.before.json` with `{"_note":"no protection rule at time of snapshot"}`.

- [ ] **Step 2: Confirm baseline**

Run:

```bash
jq '{
  contexts: .required_status_checks.contexts,
  reviews: .required_pull_request_reviews,
  force_pushes: .allow_force_pushes.enabled,
  signatures: .required_signatures.enabled
}' /tmp/protection.before.json
```

Expected output matches the red-team review findings: empty `contexts`, `reviews` is null or missing, `force_pushes` is true.

### Task 0.2: Enable `allow_auto_merge` at repo level

**Files:** none

- [ ] **Step 1: Apply the setting**

Run:

```bash
gh api -X PATCH repos/billchurch/webssh2 -f allow_auto_merge=true
```

Expected: returns JSON for the repo with `"allow_auto_merge": true`.

- [ ] **Step 2: Verify**

Run:

```bash
gh api repos/billchurch/webssh2 --jq '.allow_auto_merge'
```

Expected output: `true`

### Task 0.3: Lock `main` branch protection

**Files:** none

- [ ] **Step 1: Apply the new protection rule**

Run:

```bash
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

Expected: returns JSON matching the applied rule; exit 0.

- [ ] **Step 2: Verify**

Run:

```bash
gh api repos/billchurch/webssh2/branches/main/protection --jq '{
  contexts: .required_status_checks.contexts,
  force_pushes: .allow_force_pushes.enabled,
  signatures: .required_signatures.enabled
}'
```

Expected:

```json
{
  "contexts": ["build-lint-test", "docker-image-scan"],
  "force_pushes": false,
  "signatures": true
}
```

Note: `docker-image-scan` is listed as a required check BEFORE the job exists in ci.yml. That is intentional: until PR 2 lands, PRs will be blocked from merging to main because the required check will never report. Mitigation: PR 2 must be the very next PR to land, and PR 2's own PR merge will need temporary removal of `docker-image-scan` from `contexts` or admin override. **Proceed with the simpler flow:** merge PR 2 via admin override once (`gh api -X PUT .../required_status_checks -f contexts='["build-lint-test"]'`, merge, then re-add `docker-image-scan`). See Task 2.x rollout step.

### Task 0.4: Create the `ALLOW_AUTO_REBUILD` repo variable

**Files:** none

- [ ] **Step 1: Create the variable**

Run:

```bash
gh variable set ALLOW_AUTO_REBUILD --body 'true' --repo billchurch/webssh2
```

Expected: `✓ Set variable ALLOW_AUTO_REBUILD for billchurch/webssh2`.

- [ ] **Step 2: Verify**

Run:

```bash
gh variable list --repo billchurch/webssh2 | grep ALLOW_AUTO_REBUILD
```

Expected: output shows `ALLOW_AUTO_REBUILD   true   <timestamp>`.

### Task 0.5: Document the change

**Files:**
- Modify: commit message of PR 0 (or an issue comment) with the before/after JSON.

- [ ] **Step 1: Post the snapshots**

Paste the output of `jq` from Task 0.1 Step 2 and the verification JSON from Task 0.3 Step 2 into a new GitHub issue titled "PR 0: repo settings applied for #498 (traceability)" and close it. This gives an auditable trail without touching code.

---

## PR 1 — Dockerfile Digest Pin Hotfix (Closes #498)

### Task 1.1: Resolve the current `node:22-alpine` manifest-list digest

**Files:** none

- [ ] **Step 1: Pull and read**

Run:

```bash
docker pull node:22-alpine
docker buildx imagetools inspect node:22-alpine --format '{{json .Manifest}}' \
  | jq -r '.digest'
```

Expected: a string of the form `sha256:<64 hex characters>`. Record this digest; call it `$BASE_DIGEST` for the remainder of PR 1.

- [ ] **Step 2: Sanity-check against the issue report**

The issue cites `sha256:cb15fca92530d7ac113467696cf1001208dac49c3c64355fd1348c11a88ddf8f` as the Alpine 3.23.4 digest. If `$BASE_DIGEST` matches, use it. If the registry has since advanced (a newer patch), use the fresh digest and note the change in the PR description.

### Task 1.2: Modify `Dockerfile` to pin the base image

**Files:**
- Modify: `Dockerfile`

- [ ] **Step 1: Add the global ARG and update each FROM**

Edit `Dockerfile`. After the `# syntax=docker/dockerfile:1.7` line and before the first `FROM`, add:

```dockerfile
ARG BASE_IMAGE=node:22-alpine@sha256:cb15fca92530d7ac113467696cf1001208dac49c3c64355fd1348c11a88ddf8f
```

Substitute the actual digest from Task 1.1 Step 1.

Replace each of the three `FROM node:22-alpine AS <stage>` lines with:

```dockerfile
FROM ${BASE_IMAGE} AS deps
```

(And equivalently for `builder` and `runtime` stages.)

- [ ] **Step 2: Verify the diff is exactly what we expect**

Run:

```bash
git diff Dockerfile
```

Expected: one `+ARG BASE_IMAGE=node:22-alpine@sha256:<64hex>` line added, and three `FROM node:22-alpine AS <stage>` lines replaced with `FROM ${BASE_IMAGE} AS <stage>`. Nothing else.

### Task 1.3: Verify the image builds

**Files:** none

- [ ] **Step 1: Build amd64**

Run:

```bash
docker buildx build --platform linux/amd64 --load -t webssh2:pr1-verify .
```

Expected: build completes with exit 0.

- [ ] **Step 2: Verify the resolved base image**

Run:

```bash
docker image inspect webssh2:pr1-verify \
  --format '{{range .RootFS.Layers}}{{.}}
{{end}}' \
  | head -3
```

Expected: non-empty layer list, confirming the image has real content.

Run:

```bash
docker history webssh2:pr1-verify --no-trunc | grep -i alpine || true
```

(Informational only; Alpine layer provenance is visible in history but not strictly verifiable from here.)

### Task 1.4: Run the app smoke test

**Files:** none

- [ ] **Step 1: Run the container**

Run:

```bash
CID=$(docker run -d --rm -e DEBUG=webssh2:* webssh2:pr1-verify)
for i in {1..30}; do
  if docker logs "$CID" 2>&1 | grep -q "server started successfully"; then
    echo "OK"; docker stop "$CID"; break
  fi
  sleep 1
done
```

Expected: prints `OK` within 30 seconds. If the loop exits without printing `OK`, investigate:

```bash
docker logs "$CID"
```

Then stop the container and fix before continuing.

### Task 1.5: Commit

**Files:** none

- [ ] **Step 1: Stage and commit**

Run:

```bash
git add Dockerfile
git commit -m "$(cat <<'EOF'
fix: pin node:22-alpine base image by digest

Closes #498.

Adds an ARG BASE_IMAGE defaulting to the current node:22-alpine
manifest-list digest (Alpine 3.23.4). Each FROM stage now references
${BASE_IMAGE}, which lets Renovate (arriving in a later PR) update the
pin via a one-line diff while preserving multi-arch support.

Consumers of billchurch/webssh2:latest scanning the old sha-159d154
image for CVEs in openssl 3.5.5-r0 / musl 1.2.5-r21 will see those
findings go away once the manual publish dispatched after this merge
pushes a fresh latest/main.
EOF
)"
```

Expected: commit created; `git log -1 --stat` shows the Dockerfile change.

### Task 1.6: Push and publish

**Files:** none

- [ ] **Step 1: Push and open PR**

Run:

```bash
git push -u origin HEAD:fix/pin-base-image-498
gh pr create --title "fix: pin node:22-alpine base image by digest (#498)" \
  --body "$(cat <<'EOF'
## Summary
- Pins node:22-alpine to the current manifest-list digest via ARG BASE_IMAGE
- Switches each FROM to reference ${BASE_IMAGE}

Closes #498.

## Test plan
- [x] docker buildx build --platform linux/amd64 --load succeeds
- [x] Container smoke test logs "server started successfully" within 30s
- [ ] After merge, dispatch docker-publish.yml to republish latest/main
- [ ] Comment on #498 with new image digest + base image digest; close
EOF
)"
```

Expected: PR URL printed.

- [ ] **Step 2: Merge the PR**

Once CI passes and reviews (if any) are in, merge via `gh pr merge --squash --delete-branch`.

- [ ] **Step 3: Dispatch a rebuild**

Run:

```bash
gh workflow run docker-publish.yml \
  --repo billchurch/webssh2 \
  --ref main \
  -f publish_latest=true
```

Expected: `✓ Created workflow_dispatch event for docker-publish.yml at main`.

Wait for the workflow to finish successfully.

- [ ] **Step 4: Close #498 with the new digest**

Run:

```bash
NEW_TAG=$(gh api repos/billchurch/webssh2/packages/container/webssh2/versions --limit 5 \
  --jq '.[0].name' 2>/dev/null || echo "")
gh issue comment 498 --body "Resolved in $(git rev-parse --short HEAD). The Dockerfile now pins node:22-alpine by manifest-list digest (Alpine 3.23.4). The main/latest tags have been republished; new image digest available via \`docker pull billchurch/webssh2:latest && docker inspect billchurch/webssh2:latest --format '{{index .RepoDigests 0}}'\`."
gh issue close 498
```

---

## PR 2 — Image Scanning + Publish Restructure

### Task 2.1: Add `docker-image-scan` job to `ci.yml`

**Files:**
- Modify: `.github/workflows/ci.yml` (add new job at end)

- [ ] **Step 1: Open a branch**

Run:

```bash
git checkout -b feat/image-scan-pipeline main
```

- [ ] **Step 2: Append the new job**

Open `.github/workflows/ci.yml`. After the existing `dependency-review` job, append:

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
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2

      - id: filter
        uses: dorny/paths-filter@de90cc6fb38fc0963ad72b210f1f284cd68cea36 # v3.0.2
        with:
          filters: |
            image:
              - 'Dockerfile'
              - 'package-lock.json'
              - 'package.json'
              - '.github/workflows/docker-publish.yml'

      - name: Note when nothing image-relevant changed
        if: steps.filter.outputs.image != 'true'
        run: echo "No image-relevant changes; passing required check as a no-op."

      - name: Note fork PR skip
        if: >-
          steps.filter.outputs.image == 'true' &&
          github.event.pull_request.head.repo.full_name != github.repository
        run: echo "Fork PR; image scan skipped (advisory; main-branch scan is the gate)."

      - name: Login to Docker Hub (raise anon rate-limit)
        if: >-
          steps.filter.outputs.image == 'true' &&
          github.event.pull_request.head.repo.full_name == github.repository
        uses: docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef # v3.6.0
        with:
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_TOKEN }}

      - name: Set up buildx
        if: >-
          steps.filter.outputs.image == 'true' &&
          github.event.pull_request.head.repo.full_name == github.repository
        uses: docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435 # v3.11.1

      - name: Build amd64 image for scanning
        if: >-
          steps.filter.outputs.image == 'true' &&
          github.event.pull_request.head.repo.full_name == github.repository
        uses: docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0
        with:
          context: .
          load: true
          tags: webssh2:pr-${{ github.event.pull_request.number }}
          platforms: linux/amd64
          cache-from: type=gha,scope=publish-refs/heads/main

      - name: Trivy image scan
        if: >-
          steps.filter.outputs.image == 'true' &&
          github.event.pull_request.head.repo.full_name == github.repository
        uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0
        with:
          image-ref: webssh2:pr-${{ github.event.pull_request.number }}
          format: table
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: '1'
          cache: true
```

- [ ] **Step 3: Verify the YAML parses**

Run:

```bash
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/ci.yml"))' && echo OK
```

Expected: `OK`.

- [ ] **Step 4: Commit**

Run:

```bash
git add .github/workflows/ci.yml
git commit -m "ci: add docker-image-scan job gated by paths filter

Always-run job (required status check) that only does real work when
Dockerfile / package-lock.json / package.json / docker-publish.yml
change on a non-fork PR. Fails closed on CRITICAL/HIGH fixable findings
in the built image."
```

### Task 2.2: Restructure `docker-publish.yml` to build → scan → smoke → push

**Files:**
- Modify: `.github/workflows/docker-publish.yml`

- [ ] **Step 1: Add the shared concurrency group**

Open `.github/workflows/docker-publish.yml`. Replace the existing `concurrency:` block (near the top) with:

```yaml
concurrency:
  group: image-publish
  cancel-in-progress: false
```

The old group `docker-publish-${{ github.event_name }}-${{ github.ref }}` is discarded in favor of the shared group that `rebuild-release-tags.yml` will also use.

- [ ] **Step 2: Add an amd64 build-load step before the current multi-arch push**

Find the "Build and push docker image" step (around line 147 in the current file). INSERT the following four steps BEFORE it:

```yaml
      - name: Build amd64 image (load, for scan + smoke)
        uses: docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0
        with:
          context: .
          file: ./Dockerfile
          load: true
          platforms: linux/amd64
          tags: local/webssh2:scan
          cache-from: type=gha,scope=publish-${{ github.ref }}
          cache-to: type=gha,mode=max,scope=publish-${{ github.ref }}

      - name: Trivy image scan (fail closed)
        uses: aquasecurity/trivy-action@57a97c7e7821a5776cebc9bb87c984fa69cba8f1 # v0.35.0
        with:
          image-ref: local/webssh2:scan
          format: sarif
          output: trivy-image.sarif
          severity: CRITICAL,HIGH
          ignore-unfixed: true
          exit-code: '1'
          cache: true

      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@ff0a06e83cb2de871e5a09832bc6a81e7276941f # v3.28.18
        with:
          sarif_file: trivy-image.sarif
          category: trivy-image

      - name: Smoke-test amd64 image
        run: |
          CID=$(docker run -d --rm \
            -e DEBUG=webssh2:* local/webssh2:scan)
          for i in {1..30}; do
            if docker logs "$CID" 2>&1 | grep -q "server started successfully"; then
              docker stop "$CID"
              exit 0
            fi
            sleep 1
          done
          docker logs "$CID"
          docker stop "$CID" || true
          exit 1
```

- [ ] **Step 3: Update the existing multi-arch push step to use the scoped cache**

In the existing "Build and push docker image" step, replace the `cache-from` and `cache-to` lines with:

```yaml
          cache-from: type=gha,scope=publish-${{ github.ref }}
          cache-to: type=gha,mode=max,scope=publish-${{ github.ref }}
```

- [ ] **Step 4: Remove the post-push `Test docker image` step**

The existing step named `Test docker image` (roughly lines 167-190) pulls the pushed image and tests it. With the smoke test now running pre-push, delete the entire step. The release-notes step (`Update release notes with Docker images`) should continue to depend on `steps.build.outputs.digest`, which remains available from the unchanged multi-arch step.

- [ ] **Step 5: Verify the YAML parses**

Run:

```bash
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/docker-publish.yml"))' && echo OK
```

Expected: `OK`.

- [ ] **Step 6: Commit**

Run:

```bash
git add .github/workflows/docker-publish.yml
git commit -m "ci: restructure docker-publish to build -> scan -> smoke -> push

- Shared 'image-publish' concurrency group with the upcoming
  rebuild-release-tags workflow (prevents interleaving during releases)
- amd64 build loaded locally for Trivy image scan; fails closed on
  CRITICAL/HIGH fixable findings
- Smoke test moved BEFORE the multi-arch push so a broken image no
  longer gets tagged latest before the test catches it
- GHA cache scoped to \${{ github.ref }} so feature branches cannot
  poison the publish cache
- Existing multi-arch push step reuses the scanned layer via cache"
```

### Task 2.3: Push and open PR 2

**Files:** none

- [ ] **Step 1: Push**

Run:

```bash
git push -u origin feat/image-scan-pipeline
```

- [ ] **Step 2: Open PR with the required-check workaround documented**

Run:

```bash
gh pr create --title "ci: add image scanning gate to PR and publish flows" \
  --body "$(cat <<'EOF'
## Summary
- New docker-image-scan job in ci.yml (always runs, conditional on Dockerfile/deps changes)
- docker-publish.yml restructured: build amd64 -> scan -> smoke-test -> multi-arch push
- Shared 'image-publish' concurrency group so the upcoming release-tag rebuild workflow cannot interleave with release publishes

## Required-check bootstrap note
PR 0 registered docker-image-scan as a required status check on main BEFORE this PR introduces the job. This PR will fail its own merge unless the check registers first. Temporary workaround for the merge only:
  gh api -X PATCH repos/billchurch/webssh2/branches/main/protection/required_status_checks -f 'contexts[]=build-lint-test'
Then merge, then restore the required check:
  gh api -X PATCH repos/billchurch/webssh2/branches/main/protection/required_status_checks -f 'contexts[]=build-lint-test' -f 'contexts[]=docker-image-scan'

## Test plan
- [ ] Open a draft PR with a deliberately vulnerable base digest and confirm docker-image-scan fails it
- [ ] After merge, dispatch docker-publish.yml on main and confirm build -> scan -> smoke -> push all run in order
- [ ] Confirm SARIF trivy-image category shows up in Security tab
EOF
)"
```

- [ ] **Step 3: Execute the bootstrap workaround when the PR is green**

Run (as repo admin):

```bash
gh api -X PATCH repos/billchurch/webssh2/branches/main/protection/required_status_checks \
  -f 'contexts[]=build-lint-test'
gh pr merge <PR#> --squash --delete-branch
gh api -X PATCH repos/billchurch/webssh2/branches/main/protection/required_status_checks \
  -f 'contexts[]=build-lint-test' -f 'contexts[]=docker-image-scan'
```

Verify the final `contexts` match Task 0.3 Step 2 expected output.

### Task 2.4: Post-merge verification

**Files:** none

- [ ] **Step 1: Confirm the image-scan job reported on main**

Run:

```bash
gh run list --workflow=ci.yml --branch=main --limit=3
```

Expected: latest run shows `docker-image-scan` completed.

- [ ] **Step 2: Dispatch a manual publish and verify the new ordering**

Run:

```bash
gh workflow run docker-publish.yml --ref main -f publish_latest=false
gh run watch   # or: gh run list --workflow=docker-publish.yml --limit=1
```

Expected: step order in the log is: build amd64 → Trivy image scan → Upload SARIF → Smoke-test → Multi-arch build+push.

- [ ] **Step 3: Confirm SARIF shows up**

In the GitHub UI, open Security → Code scanning. Confirm a `trivy-image` category result is present for the latest main run.

### Task 2.5: Negative-test the scan gate

**Files:** none

- [ ] **Step 1: Create a throwaway branch with a bad digest**

Pick a historic `node:22-alpine` manifest digest known to contain HIGH CVEs (e.g., an Alpine 3.20 digest). You can find one at <https://hub.docker.com/layers/library/node/22-alpine/images/>. Call it `$BAD_DIGEST`.

Run:

```bash
git checkout -b test/negative-scan main
sed -i "s|^ARG BASE_IMAGE=.*|ARG BASE_IMAGE=node:22-alpine@${BAD_DIGEST}|" Dockerfile
git add Dockerfile
git commit -m "test: intentionally bad base digest to verify scan gate"
git push -u origin test/negative-scan
gh pr create --draft --title "test: negative scan" --body "DO NOT MERGE"
```

- [ ] **Step 2: Confirm the scan fails**

Wait for CI. Expected: `docker-image-scan` job reports ❌ with HIGH/CRITICAL findings in the log.

- [ ] **Step 3: Close the test PR and delete the branch**

Run:

```bash
gh pr close --comment "scan-gate verified; closing" <PR#>
git push origin --delete test/negative-scan
```

---

## PR 3 — Renovate Configuration + Examples Comment

### Task 3.1: Enable the Renovate GitHub App (operator)

**Files:** none

- [ ] **Step 1: Install the app**

In the GitHub UI at <https://github.com/apps/renovate>, install against `billchurch/webssh2`. Scope: single repo.

- [ ] **Step 2: Verify**

Within a few minutes, Renovate will open an onboarding PR titled "Configure Renovate" against `main`. Confirm it exists:

```bash
gh pr list --author app/renovate
```

Do NOT merge the onboarding PR yet — the next tasks land a curated config that supersedes it.

### Task 3.2: Add `.github/renovate.json`

**Files:**
- Create: `.github/renovate.json`

- [ ] **Step 1: Open a branch**

Run:

```bash
git checkout -b feat/renovate-config main
```

- [ ] **Step 2: Write the config**

Create `.github/renovate.json`:

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

- [ ] **Step 3: Verify JSON parses**

Run:

```bash
python3 -c 'import json,sys; json.load(open(".github/renovate.json"))' && echo OK
```

Expected: `OK`.

### Task 3.3: Add the pinning reminder to `examples/Dockerfile`

**Files:**
- Modify: `examples/Dockerfile`

- [ ] **Step 1: Replace the top comment block**

Open `examples/Dockerfile`. Replace the first two lines:

```dockerfile
# Use node:22-alpine as a parent image for smallest size and best security
FROM node:22-alpine
```

with:

```dockerfile
# NOTE: This is a documentation sample, not the production Dockerfile.
# For production, pin the base image by manifest digest. The repo-root
# Dockerfile uses:
#   ARG BASE_IMAGE=node:22-alpine@sha256:...
FROM node:22-alpine
```

- [ ] **Step 2: Verify the file still builds conceptually**

Run:

```bash
grep -E '^(FROM|WORKDIR|COPY|RUN|EXPOSE|CMD|ENTRYPOINT)' examples/Dockerfile
```

Expected: output is unchanged from before the edit (the comment addition does not affect any directive line).

### Task 3.4: Commit and open PR 3

**Files:** none

- [ ] **Step 1: Commit**

Run:

```bash
git add .github/renovate.json examples/Dockerfile
git commit -m "ci: add Renovate config scoped to node:22-alpine digest updates

- Daily schedule (0-6 EST window) for faster CVE response
- Auto-merge restricted to matchDepNames=['node'] +
  matchCurrentValue='22-alpine' + matchUpdateTypes=['digest']
- Grouping forbidden on digest rule; version bumps go to human review
- examples/Dockerfile gains a doc-level reminder to pin in production"
```

- [ ] **Step 2: Push and open PR**

Run:

```bash
git push -u origin feat/renovate-config
gh pr create --title "ci: add Renovate config for node:22-alpine digest auto-merge" \
  --body "$(cat <<'EOF'
## Summary
- Narrow Renovate auto-merge to digest-only updates of node:22-alpine
- Daily schedule so CVE patch PRs open within hours, not weeks
- Examples Dockerfile gains a pinning reminder comment

## Test plan
- [ ] After merge, confirm Renovate's first real digest PR runs docker-image-scan
- [ ] Confirm platformAutomerge lands the PR automatically on green
- [ ] Confirm docker-publish.yml runs on the merge and publishes fresh latest/main
EOF
)"
```

- [ ] **Step 3: Close the onboarding PR**

After PR 3 merges, close Renovate's original onboarding PR with a comment pointing at the committed config:

```bash
gh pr close <onboarding-PR#> --comment "Superseded by .github/renovate.json in #<PR3>."
```

### Task 3.5: Post-merge verification

**Files:** none

- [ ] **Step 1: Wait for a real digest PR**

Within 24 hours, a Renovate digest PR may open if upstream Alpine advances. If not, test by asking Renovate to re-run via the dependency dashboard (click "Check now").

- [ ] **Step 2: Observe auto-merge**

When the first digest PR opens:

1. `docker-image-scan` runs and passes.
2. `build-lint-test` runs and passes.
3. Renovate merges via `platformAutomerge`.
4. `docker-publish.yml` runs on main and publishes a fresh `latest`/`main`.

Record the PR URL, pre-merge and post-merge image digests in an issue for traceability.

---

## PR 4 — Event-Driven Release-Tag Rebuild

### Task 4.1: Scaffold `rebuild-release-tags.yml`

**Files:**
- Create: `.github/workflows/rebuild-release-tags.yml`

- [ ] **Step 1: Open a branch**

Run:

```bash
git checkout -b feat/rebuild-release-tags main
```

- [ ] **Step 2: Write the workflow skeleton**

Create `.github/workflows/rebuild-release-tags.yml`:

```yaml
name: rebuild-release-tags

on:
  workflow_run:
    workflows: ['docker-publish']
    types: [completed]
    branches: [main]
  workflow_dispatch:
    inputs:
      simulate:
        description: 'Run all steps except the final docker push'
        default: 'false'
        required: true
        type: choice
        options: ['true', 'false']

concurrency:
  group: image-publish
  cancel-in-progress: false

permissions:
  contents: read
  packages: write

jobs:
  guard:
    runs-on: ubuntu-latest
    outputs:
      proceed: ${{ steps.decide.outputs.proceed }}
      head_sha: ${{ steps.ctx.outputs.head_sha }}
      new_digest: ${{ steps.extract.outputs.new_digest }}
      release_tag: ${{ steps.release.outputs.tag }}
      release_sha: ${{ steps.release.outputs.sha }}
    if: >-
      (
        github.event_name == 'workflow_run' &&
        github.event.workflow_run.conclusion == 'success' &&
        github.event.workflow_run.event == 'push' &&
        github.event.workflow_run.head_branch == 'main' &&
        github.event.workflow_run.triggering_actor.login == 'renovate[bot]' &&
        github.event.workflow_run.actor.login == 'renovate[bot]' &&
        vars.ALLOW_AUTO_REBUILD == 'true'
      ) ||
      github.event_name == 'workflow_dispatch'
    steps:
      - id: ctx
        name: Resolve triggering commit SHA
        run: |
          if [ "${{ github.event_name }}" = "workflow_run" ]; then
            echo "head_sha=${{ github.event.workflow_run.head_sha }}" >> "$GITHUB_OUTPUT"
          else
            echo "head_sha=${GITHUB_SHA}" >> "$GITHUB_OUTPUT"
          fi

      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ steps.ctx.outputs.head_sha }}
          fetch-depth: 0

      - name: Verify commit is signed and verified (workflow_run only)
        if: github.event_name == 'workflow_run'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          HEAD_SHA: ${{ steps.ctx.outputs.head_sha }}
        run: |
          verification=$(gh api repos/${{ github.repository }}/commits/${HEAD_SHA} \
            --jq '.commit.verification')
          verified=$(echo "$verification" | jq -r '.verified')
          reason=$(echo  "$verification" | jq -r '.reason')
          if [ "$verified" != "true" ] || [ "$reason" != "valid" ]; then
            echo "::error::Commit ${HEAD_SHA} verification=${verified} reason=${reason}"
            exit 1
          fi

      - name: Verify diff is digest-only on Dockerfile (workflow_run only)
        if: github.event_name == 'workflow_run'
        env:
          HEAD_SHA: ${{ steps.ctx.outputs.head_sha }}
        run: |
          parent=$(git rev-parse ${HEAD_SHA}^)

          # 1. Exactly one file must have changed, and it must be Dockerfile.
          files=$(git diff --name-status "${parent}" "${HEAD_SHA}")
          if [ "$files" != $'M\tDockerfile' ]; then
            echo "::error::Unexpected diff: $files"; exit 1
          fi

          # 2. Every +/- line in the Dockerfile diff must be an ARG BASE_IMAGE= line.
          #    (Reject changes to any OTHER Dockerfile line, even comments / whitespace.)
          changed=$(git diff "${parent}" "${HEAD_SHA}" -- Dockerfile | grep -E '^[+-]' | grep -Ev '^[+-]{3} ')
          non_arg=$(echo "$changed" | grep -Ev '^[+-]ARG BASE_IMAGE=' || true)
          if [ -n "$non_arg" ]; then
            echo "::error::Dockerfile has non-BASE_IMAGE changes:"; echo "$non_arg"; exit 1
          fi

          # 3. Exactly one removed and one added BASE_IMAGE line.
          removed_line=$(echo "$changed" | grep '^-ARG BASE_IMAGE=' || true)
          added_line=$(echo   "$changed" | grep '^+ARG BASE_IMAGE=' || true)
          if [ "$(echo "$removed_line" | grep -c .)" != "1" ] || \
             [ "$(echo "$added_line"   | grep -c .)" != "1" ]; then
            echo "::error::Expected exactly one BASE_IMAGE line change"
            echo "Removed: $removed_line"
            echo "Added:   $added_line"
            exit 1
          fi

          # 4. BOTH the removed and added lines must independently match the strict pattern.
          pattern='^[+-]ARG BASE_IMAGE=node:22-alpine@sha256:[0-9a-f]{64}$'
          if ! echo "$removed_line" | grep -Eq "$pattern"; then
            echo "::error::Removed line does not match strict pattern: $removed_line"; exit 1
          fi
          if ! echo "$added_line" | grep -Eq "$pattern"; then
            echo "::error::Added line does not match strict pattern: $added_line"; exit 1
          fi

      - name: Defer if a release was published in the last 10 minutes
        if: github.event_name == 'workflow_run'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          published=$(gh release list --limit 1 --json publishedAt --jq '.[0].publishedAt')
          if [ -n "$published" ]; then
            delta=$(( $(date +%s) - $(date -d "$published" +%s) ))
            if [ "$delta" -lt 600 ]; then
              echo "::error::Release published ${delta}s ago; deferring to release flow"
              exit 1
            fi
          fi

      - id: extract
        name: Extract new BASE_IMAGE digest from Dockerfile at head_sha
        run: |
          digest=$(grep -E '^ARG BASE_IMAGE=' Dockerfile | head -1 | sed 's/^ARG BASE_IMAGE=//')
          if [ -z "$digest" ]; then echo "::error::Could not read BASE_IMAGE"; exit 1; fi
          echo "new_digest=$digest" >> "$GITHUB_OUTPUT"

      - id: release
        name: Resolve latest release tag via isLatest
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          tag=$(gh release list --limit 50 --json tagName,isLatest,isDraft,isPrerelease \
                --jq '.[] | select(.isLatest==true and .isDraft==false and .isPrerelease==false) | .tagName')
          if [[ ! "$tag" =~ ^webssh2-server-v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            echo "::notice::No qualifying release tag; skipping"
            echo "tag=" >> "$GITHUB_OUTPUT"
            echo "sha=" >> "$GITHUB_OUTPUT"
            exit 0
          fi
          sha=$(gh api repos/${{ github.repository }}/git/ref/tags/${tag} \
                --jq '.object.sha')
          echo "tag=$tag" >> "$GITHUB_OUTPUT"
          echo "sha=$sha" >> "$GITHUB_OUTPUT"

      - id: decide
        name: Per-head_sha idempotency check
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          HEAD_SHA: ${{ steps.ctx.outputs.head_sha }}
          RELEASE_TAG: ${{ steps.release.outputs.tag }}
        run: |
          if [ -z "$RELEASE_TAG" ]; then
            echo "proceed=false" >> "$GITHUB_OUTPUT"; exit 0
          fi
          body=$(gh release view "$RELEASE_TAG" --json body --jq '.body')
          if echo "$body" | grep -q "rebuild-sha: ${HEAD_SHA}"; then
            echo "::notice::Already rebuilt for ${HEAD_SHA}"
            echo "proceed=false" >> "$GITHUB_OUTPUT"
          else
            echo "proceed=true" >> "$GITHUB_OUTPUT"
          fi
```

- [ ] **Step 3: Verify YAML parses**

Run:

```bash
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/rebuild-release-tags.yml"))' && echo OK
```

Expected: `OK`.

- [ ] **Step 4: Commit the guard-only skeleton**

Run:

```bash
git add .github/workflows/rebuild-release-tags.yml
git commit -m "ci: scaffold rebuild-release-tags guard job

Workflow_run-triggered; shared 'image-publish' concurrency group with
docker-publish.yml. Guard job verifies: workflow_run context matches
Renovate merge on main, commit is signed, diff is exactly one-line
digest change in Dockerfile, no release published within 10 minutes,
and produces the latest release tag via isLatest filter plus
per-head_sha idempotency. Rebuild job arrives in the next commit."
```

### Task 4.2: Add the `rebuild` job

**Files:**
- Modify: `.github/workflows/rebuild-release-tags.yml`

- [ ] **Step 1: Append the rebuild job**

At the end of `.github/workflows/rebuild-release-tags.yml`, after the `guard:` job, add:

```yaml
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
      RELEASE_SHA: ${{ needs.guard.outputs.release_sha }}
      SIMULATE: ${{ github.event.inputs.simulate || 'false' }}
    steps:
      - name: Snapshot existing sha-tag digest (for post-push assertion)
        run: |
          short="${RELEASE_SHA:0:7}"
          before=$(curl -fsSL "https://hub.docker.com/v2/repositories/billchurch/webssh2/tags/sha-${short}" \
            | jq -r '.digest' 2>/dev/null || echo "")
          echo "SHA_TAG_SHORT=${short}"          >> "$GITHUB_ENV"
          echo "SHA_TAG_DIGEST_BEFORE=${before}" >> "$GITHUB_ENV"

      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          ref: ${{ env.RELEASE_SHA }}
          path: release-src
          fetch-depth: 0

      - name: Overlay new BASE_IMAGE digest onto release-src Dockerfile
        working-directory: release-src
        run: |
          sed -i "s|^ARG BASE_IMAGE=.*|ARG BASE_IMAGE=${NEW_DIGEST}|" Dockerfile
          grep -E '^ARG BASE_IMAGE=' Dockerfile

      - uses: docker/setup-qemu-action@c7c53464625b32c7a7e944ae62b3e17d2b600130 # v3.7.0
      - uses: docker/setup-buildx-action@e468171a9de216ec08956ac3ada2f0791b6bd435 # v3.11.1

      - uses: docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef # v3.6.0
        with:
          registry: docker.io
          username: ${{ secrets.DOCKER_USERNAME }}
          password: ${{ secrets.DOCKER_TOKEN }}
      - uses: docker/login-action@5e57cd118135c172c3672efd75eb46360885c0ef # v3.6.0
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Build amd64 for scan
        uses: docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0
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
          exit-code: '1'
          cache: true

      - id: semver
        name: Derive semver tags from RELEASE_TAG
        run: |
          tag="${RELEASE_TAG#webssh2-server-v}"
          major="${tag%%.*}"
          minor="${tag%.*}"
          echo "full=$tag"    >> "$GITHUB_OUTPUT"
          echo "minor=$minor" >> "$GITHUB_OUTPUT"
          echo "major=$major" >> "$GITHUB_OUTPUT"

      - name: Multi-arch build and push (semver tags only; no sha-tag)
        id: push
        if: env.SIMULATE != 'true'
        uses: docker/build-push-action@263435318d21b8e681c14492fe198d362a7d2c83 # v6.18.0
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

      - name: Simulate push (dry-run)
        if: env.SIMULATE == 'true'
        run: |
          echo "SIMULATE=true; would have pushed:"
          echo "  docker.io/billchurch/webssh2:${{ steps.semver.outputs.full }}"
          echo "  docker.io/billchurch/webssh2:${{ steps.semver.outputs.minor }}"
          echo "  docker.io/billchurch/webssh2:${{ steps.semver.outputs.major }}"
          echo "  (ghcr counterparts)"

      - name: Assert sha-tag digest unchanged
        if: env.SIMULATE != 'true'
        run: |
          after=$(curl -fsSL "https://hub.docker.com/v2/repositories/billchurch/webssh2/tags/sha-${SHA_TAG_SHORT}" \
            | jq -r '.digest')
          if [ "$after" != "${SHA_TAG_DIGEST_BEFORE}" ]; then
            echo "::error::sha-${SHA_TAG_SHORT} digest changed from ${SHA_TAG_DIGEST_BEFORE} to ${after}"
            exit 1
          fi

      - name: Comment on release with new image digest
        if: env.SIMULATE != 'true'
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          PR_URL: ${{ github.event.workflow_run.pull_requests[0].html_url }}
          IMAGE_DIGEST: ${{ steps.push.outputs.digest }}
          SEMVER_FULL: ${{ steps.semver.outputs.full }}
          SEMVER_MINOR: ${{ steps.semver.outputs.minor }}
          SEMVER_MAJOR: ${{ steps.semver.outputs.major }}
        run: |
          body=$(printf '%s\n' \
            "[base-refresh] Base image refreshed (no source changes)" \
            "- Base image: ${NEW_DIGEST}" \
            "- Refreshed tags: ${SEMVER_FULL}, ${SEMVER_MINOR}, ${SEMVER_MAJOR}" \
            "- New image digest: ${IMAGE_DIGEST}" \
            "- Triggered by: ${PR_URL}" \
            "" \
            "rebuild-sha: ${HEAD_SHA}")
          current=$(gh release view "$RELEASE_TAG" --json body --jq '.body')
          gh release edit "$RELEASE_TAG" --notes "${current}

${body}"
```

- [ ] **Step 2: Verify YAML parses**

Run:

```bash
python3 -c 'import yaml,sys; yaml.safe_load(open(".github/workflows/rebuild-release-tags.yml"))' && echo OK
```

Expected: `OK`.

- [ ] **Step 3: Commit**

Run:

```bash
git add .github/workflows/rebuild-release-tags.yml
git commit -m "ci: implement rebuild-release-tags rebuild job

Checks out release-tag source into release-src/, overlays new
BASE_IMAGE digest, builds + Trivy-scans amd64, then does multi-arch
build+push of X.Y.Z, X.Y, X (no sha-tag emission). Asserts the
release-commit sha-<short> tag digest in Docker Hub is unchanged
post-push. Posts a base-image-refresh comment on the GitHub release
carrying a 'rebuild-sha: <sha>' idempotency marker.

Supports workflow_dispatch with simulate=true for dry-run testing."
```

### Task 4.3: Dry-run via workflow_dispatch simulate

**Files:** none

- [ ] **Step 1: Push the branch and open PR**

Run:

```bash
git push -u origin feat/rebuild-release-tags
gh pr create --title "ci: add event-driven rebuild-release-tags workflow" \
  --body "$(cat <<'EOF'
## Summary
- New .github/workflows/rebuild-release-tags.yml
- Triggered by workflow_run on docker-publish completion (main branch, Renovate commits only)
- Guards: triggering_actor/actor=renovate[bot], signed commit verification, structured diff check (exactly one digest-only line in Dockerfile), isLatest release filter, 10-minute release defer, per-head_sha idempotency, ALLOW_AUTO_REBUILD variable kill-switch
- Rebuild: overlays new digest onto release-tag source, multi-arch build+scan+push of semver tags (X.Y.Z, X.Y, X), asserts sha-tag digest unchanged, posts release comment

## Test plan
- [ ] Merge and dispatch with simulate=true; inspect guard + rebuild step outputs
- [ ] Dispatch with simulate=false against current state after a real Renovate merge; confirm release tags refresh and sha-tag digest assertion passes
EOF
)"
```

- [ ] **Step 2: Merge when CI is green**

Once `docker-image-scan` and `build-lint-test` pass, merge:

```bash
gh pr merge <PR#> --squash --delete-branch
```

- [ ] **Step 3: Dispatch simulate=true and capture the run ID**

Run:

```bash
gh workflow run rebuild-release-tags.yml --ref main -f simulate=true
sleep 5
RID=$(gh run list --workflow=rebuild-release-tags.yml --limit=1 --json databaseId --jq '.[0].databaseId')
gh run watch "$RID"
```

Expected: workflow completes. Under `workflow_dispatch`, the guard job skips the signature / diff / defer checks but exercises the release resolution, digest extraction, and idempotency logic. The rebuild job runs through build + scan but not push (simulate=true).

- [ ] **Step 4: Inspect the run log**

Run:

```bash
gh run view "$RID" --log | grep -E '(BASE_IMAGE|release tag|Would have pushed|SIMULATE)'
```

Expected: shows the resolved release tag, the extracted `NEW_DIGEST`, and the simulated push list.

### Task 4.4: Negative-test the guards

**Files:** none

- [ ] **Step 1: Flip the kill-switch**

Run:

```bash
gh variable set ALLOW_AUTO_REBUILD --body 'false' --repo billchurch/webssh2
```

- [ ] **Step 2: Trigger a workflow_run scenario**

Push a no-op change to main via a non-Renovate commit to force `docker-publish.yml` to run, then verify `rebuild-release-tags.yml` does NOT start (the top-level `if:` should evaluate false).

Run:

```bash
gh run list --workflow=rebuild-release-tags.yml --limit=5
```

Expected: no new run corresponding to the just-completed `docker-publish.yml` run.

- [ ] **Step 3: Restore the kill-switch**

Run:

```bash
gh variable set ALLOW_AUTO_REBUILD --body 'true' --repo billchurch/webssh2
```

- [ ] **Step 4: Document the behavior in the PR's post-merge comment**

Comment on the merged PR 4 with a summary: "Dispatch simulate=true verified; kill-switch verified; awaiting first real Renovate digest PR for end-to-end validation."

### Task 4.5: End-to-end validation after first real Renovate digest PR

**Files:** none

- [ ] **Step 1: Wait for a real Renovate digest PR to land on main**

This may take days; the Renovate schedule is daily and Alpine publishes patches irregularly.

- [ ] **Step 2: Observe the chain**

When the digest PR merges:

1. `docker-publish.yml` fires on push to main; publishes `latest`, `main`, `sha-<renovate-sha>`.
2. `rebuild-release-tags.yml` fires on `workflow_run` completion.
3. Guard passes; rebuild job runs; release tags (`X.Y.Z`, `X.Y`, `X`) get new image digests.
4. Release body gets the "Base image refreshed" comment with a `rebuild-sha:` marker.

Verify via:

```bash
gh run list --workflow=rebuild-release-tags.yml --limit=3
gh release view $(gh release list --limit 1 --json tagName --jq '.[0].tagName') --json body --jq '.body' | tail -20
```

- [ ] **Step 3: Close out #498 with the observed digests**

Comment on #498 with: the original sha-159d154 base digest, the new `latest` image digest, and the new release-tag image digest. This is the final audit trail that the pipeline works end to end.

---

## Post-Rollout

- [ ] **Verify the critical-check coverage matches PR 0**

Run:

```bash
gh api repos/billchurch/webssh2/branches/main/protection --jq '.required_status_checks.contexts'
```

Expected: `["build-lint-test", "docker-image-scan"]`.

- [ ] **Follow-up tracking**

Open GitHub issues (or add to an existing backlog) for each item in the spec's "Follow-Ups (Deferred)" section. Link each issue back to the red-team review file and this plan.
