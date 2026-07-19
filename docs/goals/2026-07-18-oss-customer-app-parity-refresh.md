# Goal: Refresh OSS Parity and Prepare the Next Release

**Created:** 2026-07-18
**Repository:** `dot-billy/catalyst-networks-open-source`
**Source of shared behavior:** `dot-billy/customer_app`
**Status:** Ready for execution

## Goal

Bring the open-source Catalyst Networks product up to date with the remaining reusable fixes from `customer_app`, finish or preserve outstanding OSS-only work, strengthen release safety, and publish a coherent release after validation.

## Current Baseline

- The latest shared customer changes are already present on OSS `origin/main`:
  - Security Groups and Assign Nodes improvements: OSS PR #11.
  - SAML behind TLS proxy fix: OSS PR #12.
  - `punchy.respond` configuration: OSS PR #13.
  - Organization and node `config_overrides`, including the node PATCH fix: OSS PR #14.
- There are currently no open OSS pull requests.
- The latest OSS `main` guard workflow passed.
- The local OSS checkout is three commits behind `origin/main` and contains uncommitted work that must be preserved before updating:
  - Collision-safe certificate filenames.
  - A missing node-delete confirmation template and test.
- The local uncommitted work passes `git diff --check`, Python compilation, the OSS guard, and the guard/intake unit tests. Focused Django tests have not yet been run against a live test stack.
- The public `v1.0.0` tag is 35 commits behind OSS `origin/main`, and the repository has no newer GitHub Release.

## Required Work

### 1. Preserve and Reconcile Existing OSS Work

- Create a dedicated branch or clean worktree without discarding the current uncommitted changes.
- Preserve the certificate filename and node-delete confirmation work exactly as user-owned changes.
- Update the implementation base to current OSS `origin/main`.
- Resolve overlaps in:
  - `nodes/api_registration.py`
  - `nodes/serializers.py`
  - `nodes/tests.py`
- Run focused node certificate, deletion, registration, and config-generation tests.

### 2. Port the Customer CA Redirect Fix

OSS still redirects to `certificates_org:detail` without the required organization slug after creating a certificate authority.

- Change the org-scoped CA-create redirect to pass both `slug` and `pk`.
- Port or adapt the customer regression test using temporary certificate storage and a mocked `nebula-cert` invocation.
- Verify that successful CA creation redirects to the organization-scoped detail page without `NoReverseMatch`.

Customer source: `customer_app` commit `5c0f591` / PR #63.

### 3. Complete Node Authentication Logging Hardening

OSS already removed raw request-header logging, so the critical authorization-token leak is not present. It still logs more identity and request detail than the hardened customer implementation.

- Replace verbose INFO-level permission logging with redacted DEBUG-level decision logging.
- Do not log authorization headers, API tokens, user emails, raw metadata, or full tracebacks.
- Harden authentication exception logging so exception strings cannot disclose token material.
- Preserve current organization scoping and node object-permission behavior.
- Add regression coverage for both `checkin` and `download_config` node-token traffic.

Customer source: `customer_app` commit `d28358b` / PR #76.

### 4. Decide and Implement Nebula Interface Naming

Customer App derives Linux/Windows Nebula interface names from the organization slug; OSS still emits `tun.dev: nebula1`.

Decision required before implementation:

- Adopt the customer behavior directly, or
- Introduce it behind an explicit compatibility setting for existing self-hosted installations.

If adopted:

- Port the deterministic, Linux-safe interface-name helper.
- Keep names at 15 bytes or fewer and limited to `[a-z0-9-]`.
- Preserve the `nebula1` fallback for empty or invalid slugs.
- Add collision, truncation, and config-generation tests.
- Document that existing Linux/Windows nodes change interface name after their next configuration sync; macOS continues to auto-assign `utunN`.

Customer source: `customer_app` commit `efde6d5` / PR #60.

### 5. Make an Explicit Admin 2FA Decision

Customer App includes TOTP protection and an optional IP allowlist for Django admin; OSS does not.

- Decide whether this belongs in the default OSS product, as an opt-in self-hosting feature, or remains hosted-only.
- If accepted, port it with disabled-by-default settings, setup documentation, recovery guidance, and tests.
- Record the decision in `docs/PORT_LEDGER.md` even if rejected.

Customer source: `customer_app` commit `8b86d19` / PR #56.

### 6. Strengthen OSS Publish Safety

Plane issue `42a43e9c-bfce-40e3-be45-820ee39f3cf3` remains a high-priority Todo for a clean-history publish process and CI secret-scan gate.

- Add a recognized secret scanner such as gitleaks or trufflehog to pull-request and main-branch CI.
- Scan relevant Git history, not only the current working tree.
- Keep the existing OSS commercial-boundary and changed-file guard tests.
- Document the clean-tree and clean-history release procedure.
- Pin or update GitHub Actions to maintained Node 24-compatible releases.

The current origin-ref filename audit did not find `.env`, certificate-key, cookie, or build-log paths reachable from public OSS refs. This is not a substitute for the required content-aware historical scan.

### 7. Refresh Public Documentation and Port Tracking

- Replace the README clone placeholder with the real public repository URL.
- Update the feature list and architecture table for Google Workspace and generic OIDC support.
- Document the current Security Groups features, configuration overrides, and relevant node configuration behavior.
- Update the stale `porting` statuses in `docs/PORT_LEDGER.md` where work has already merged.
- Add ledger rows for:
  - CA redirect fix.
  - Logging hardening.
  - Nebula interface naming decision.
  - Admin 2FA decision.
  - Secret-scan/release-safety work.

### 8. Validate and Publish the Next OSS Release

Required validation:

- `python3 tools/oss_guard_scan.py`
- `python3 -m unittest tests.test_oss_guard_scan tests.test_port_diff_intake`
- `python manage.py check`
- `python manage.py makemigrations --check --dry-run`
- Focused Django tests for certificates, nodes, authentication/permissions, SSO, organizations, and Security Groups.
- Fresh-database migration smoke.
- Docker Compose health and login/bootstrap smoke.
- Secret scan across the release tree and relevant history.
- `git diff --check`.

After validation:

- Merge through a dedicated OSS pull request.
- Update the project version according to the chosen release level.
- Create a new signed or annotated tag after `v1.0.0`.
- Publish a GitHub Release with migration and interface-name compatibility notes.
- Confirm the release tag points to the tested commit.

## Acceptance Criteria

- OSS CA creation no longer fails on the post-create redirect.
- Node-token authentication and permission logs contain no secrets, raw headers, email addresses, or full tracebacks.
- The Nebula interface-name behavior has an explicit, documented product decision and complete tests.
- The existing local certificate/delete work is either merged with tests or preserved on a clearly named branch with a documented disposition.
- A content-aware historical secret scan is enforced in CI.
- README and port ledger accurately describe the shipped OSS product.
- All required checks pass on the final pull request.
- A post-`v1.0.0` OSS release is published from the validated commit.

## Recommended Execution Order

1. Preserve the dirty local OSS work and create a clean implementation base from `origin/main`.
2. Port the CA redirect and complete logging hardening.
3. Reconcile and test the existing certificate/delete work.
4. Make the interface-name and admin-2FA product decisions.
5. Implement accepted decisions and update the port ledger.
6. Add historical secret scanning and update CI actions.
7. Refresh public documentation.
8. Run the full validation matrix and publish the next OSS release.

## Reference Links

- OSS repository: https://github.com/dot-billy/catalyst-networks-open-source
- Customer App repository: https://github.com/dot-billy/customer_app
- OSS parity PR #11: https://github.com/dot-billy/catalyst-networks-open-source/pull/11
- OSS SAML fix PR #12: https://github.com/dot-billy/catalyst-networks-open-source/pull/12
- OSS `punchy.respond` PR #13: https://github.com/dot-billy/catalyst-networks-open-source/pull/13
- OSS `config_overrides` PR #14: https://github.com/dot-billy/catalyst-networks-open-source/pull/14
