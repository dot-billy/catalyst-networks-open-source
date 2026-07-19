# OSS Release Procedure

The OSS repository has its own public history. Never merge or push the shared
`customer_app` repository history, branches, tags, worktrees, environment files,
or deployment artifacts into this repository. Port reusable changes as reviewed
patches on an OSS branch and merge them through a dedicated pull request.

## Before opening the release pull request

1. Fetch the public remote and rebase the release branch onto `origin/main`.
2. Confirm `git status --short` is empty except for the intended release work.
3. Review `git diff --stat origin/main...HEAD` and `git diff --check`.
4. Run the OSS guard, unit tests, Django checks, focused suites, fresh-database
   migration smoke, Docker Compose health/bootstrap smoke, and the full-history
   secret scan listed in the release goal.
5. In a fresh full-depth clone, run:

   ```bash
   git fetch --force --tags origin '+refs/heads/*:refs/remotes/origin/*'
   gitleaks git --redact --verbose --log-opts="--all" .
   git ls-tree -r --name-only origin/main | grep -E '(^|/)(\.env($|\.)|.*\.(key|pem)$|cookies?\.txt$|.*\.log$)' && exit 1 || true
   ```

   Investigate every finding. Never suppress a real credential; remove it from
   the branch, rotate it, and purge it from reachable history before publishing.
   Fingerprint ignores require a documented false-positive review in the PR.
   The two committed `.gitleaksignore` entries are historical documentation-only
   JWT placeholders: one API-reference response example and the matching schema
   response example. Their current-tree values have been replaced with explicit
   `<access-token>` placeholders. Do not add broad rule or path exclusions for
   committed release content.
6. Push only the dedicated OSS branch and merge it with the repository's normal
   squash policy after all required checks pass.

## Tag and GitHub Release

1. Fetch `origin/main` after merge and verify the merge commit is the exact
   commit validated by the final CI run.
2. Check out that commit in a clean worktree and repeat `git diff --check`, the
   OSS guard, and the full-history Gitleaks scan.
3. Confirm `pyproject.toml` and the API schema expose the intended version.
4. Create an annotated tag, push that tag only, and verify its peeled commit:

   ```bash
   tested_commit=<tested-commit-sha>
   git tag -a vX.Y.Z "$tested_commit" -m 'Catalyst Networks OSS vX.Y.Z'
   git push origin vX.Y.Z
   test "$(git rev-parse vX.Y.Z^{})" = "$tested_commit"
   ```

5. Publish a GitHub Release from the tag. Include migration requirements,
   security behavior, and interface-name compatibility notes.
6. Verify the public release tag and GitHub Release both point at the tested
   commit. Do not rebuild or move the tag after publication.
