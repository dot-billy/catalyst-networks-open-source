# Security Groups And Assign Nodes OSS Sync Design

Date: 2026-06-28
Status: approved for design, pending implementation plan
Source repo: `/home/uwadmin/Development/catalyst-networks-mono-repo/customer_app`
Target repo: `/home/uwadmin/Development/catalyst-networks-open-source`
Approved approach: direct cherry-pick with OSS guardrails

## Goal

Sync the current commercial security-groups and Assign Nodes work into the open-source Catalyst repository quickly by cherry-picking the commercial commits, while preserving OSS-only behavior and blocking commercial-only code, docs, secrets, deployment state, and hosted product copy.

## Current State

The OSS repository already includes the previous customer parity baseline and allauth-backed OIDC SSO. It also has an OSS Assign Nodes picker commit on the current branch plus local uncommitted edits in:

- `security_groups/tests.py`
- `static/css/design-system.css`
- `templates/security_groups/org_assign_nodes.html`

Those local edits are considered existing work and must be preserved or consciously reconciled during implementation. The commercial source contains the newer security-groups product area work: Tags, directional Rules, target groups, the Node x Tag matrix, the direction-first rule editor, effective rules, recipe presets, the target-group display fix, and the dense Assign Nodes picker.

## Source Commits

Cherry-pick these commercial commits in order:

| Order | Commit | Purpose |
| --- | --- | --- |
| 1 | `e220956` | Phase 4 foundation: UI renames, route scaffolding, NoReverseMatch fix, dead-code cleanup |
| 2 | `90b5ede` | Tag list/detail and plain-English summaries |
| 3 | `0fee70c` | Node x Tag matrix and batched membership changes |
| 4 | `64dee9d` | Direction-first rule editor and live rule preview |
| 5 | `5bf9fc4` | Per-node Effective Rules |
| 6 | `6a5426d` | Recipe wizard and idempotent preset rules |
| 7 | `722719c` | Surface target-group firewall rules in detail/list views |
| 8 | `9b6a2a2` | Dense searchable Assign Nodes picker |

If a cherry-pick applies documentation under `.superpowers` or commercial planning files, drop those files from the OSS commit unless they are rewritten as OSS-facing documentation under `docs/` and pass the product-boundary review.

## Included Scope

- Security-group model evolution into the shared Tag/Rule behavior needed by the UI, including migrations and compatibility aliases where the commercial implementation requires them.
- Directional firewall rules with `direction`, `match_type`, `target_groups`, typed sources, and CIDR/any support.
- Node certificate/config behavior needed for tag membership and effective rule display.
- Node x Tag matrix, tag summaries, direction-first rule editor, live preview partials, per-node Effective Rules page, and recipe wizard.
- Target-group display fix from commercial `origin/main`.
- Dense Assign Nodes picker behavior and page-scoped CSS, preserving OSS wording.
- Focused tests for migrations, rule resolution, matrix apply behavior, rule editor validation, recipes, effective rules, and Assign Nodes render/post behavior.

## Excluded Scope

- Commercial-only modules and paths: `licensing/`, `plans/`, `support/`, `analytics/`, `saas_entitlements/`, billing, hosted support, demo-mode flows, plan limits, upgrade banners, and customer entitlement behavior.
- Private deployment and release material: Docker registry publishing, GitOps overlays, backoffice records, production domains, internal cluster names, build logs, `.env` files, cert/key stores, and runtime state.
- Secret values or secret-like examples beyond safe sample values already allowed by OSS guard policy.
- Commercial docs or notes that mention hosted operations unless rewritten as generic OSS documentation.
- Unrelated commercial changes from admin hardening, dependency bumps, SSO, email, support, licensing, or hosted SaaS features.

## Cherry-Pick Strategy

Use direct cherry-picks rather than hand-porting. Each commit should be applied with conflicts resolved in favor of the OSS repository's public product shape:

1. Start from a dedicated OSS branch based on current `origin/main` or the existing Assign Nodes OSS branch if that branch remains the intended target.
2. Snapshot the current OSS working tree before implementation so the existing Assign Nodes edits can be recovered if conflict resolution becomes messy.
3. Cherry-pick the commits in the listed order, resolving conflicts as they appear.
4. For each conflict, keep shared model, view, template, CSS, and test behavior; drop commercial-only code, docs, paths, and copy.
5. After each logical chunk, run focused tests or at least Django import checks before moving to the next commit.
6. Commit resolved cherry-picks as separate commits when practical so regressions can be traced back to one source slice.

This approach accepts more conflict resolution work in exchange for speed and history traceability.

## Conflict Resolution Rules

- Preserve OSS-only docs, bootstrap registration, QR/mobile node flows, bulk node operations, and public docs routes unless a commercial change is clearly compatible and tested.
- Preserve OSS naming where the commercial Assign Nodes page uses commercial-specific wording. The target page should continue to read as an open-source admin workflow.
- Keep OSS guard tooling intact: `tools/oss_guard_scan.py`, `tools/port_diff_intake.py`, and their tests must remain green.
- Do not copy the commercial `.github/workflows/docker-build.yml` or other production release automation into OSS as part of this sync.
- Do not copy `.superpowers/`, `.claude/`, `.codex/`, `.agents/`, local notes, venv files, caches, media, staticfiles, or generated artifacts.
- If a commercial test depends on a commercial-only app, rewrite the assertion around the generic OSS behavior or drop that test from the sync.
- If migrations conflict, prefer the migration path that is safe for a fresh OSS install and for an existing OSS database at the current `origin/main` schema.

## Data Flow And Behavior

Tag membership remains the source for Nebula certificate groups. Matrix and Assign Nodes changes update node-tag membership and must trigger the same certificate regeneration behavior already expected by the source implementation. Rule edits are config changes and should affect generated firewall config without re-signing certificates unless membership changes.

Effective Rules views must use the same resolver used by config generation so the UI and generated Nebula config cannot drift. Recipe presets generate ordinary rules with a marker that allows idempotent re-apply without deleting hand-authored rules.

## Verification

Implementation is not complete until these checks pass or the exact blocker is documented:

- `python3 tools/oss_guard_scan.py` from the OSS repo after conflict resolution.
- `python3 -m unittest tests.test_oss_guard_scan tests.test_port_diff_intake`.
- Focused Django tests covering `security_groups` and node effective/config behavior.
- Migration check on a clean database through Docker Compose.
- Smoke check for health, login redirect, organization security-groups pages, Tag detail, matrix, rule editor preview, recipes, effective rules, and Assign Nodes save behavior.

Use Docker Compose commands from the OSS repo unless a narrower local Python command is known to be valid for a pure unit test.

## Risks

- Direct cherry-pick can bring commercial-only files into the index during conflict resolution. The guard scanner and path review are mandatory before any implementation commit is considered ready.
- The OSS branch already has Assign Nodes work, so `9b6a2a2` may duplicate or conflict with existing picker changes. Resolve toward one polished OSS version rather than stacking two picker implementations.
- Model and migration changes are the highest-risk part because OSS has public install paths. Verify both fresh migrations and upgrade from current OSS schema.
- Commercial docs and tests may reference private product assumptions. Treat every copied doc and test as suspect until it is reviewed against the OSS boundary.

## Done Criteria

The sync is done when OSS contains the current security-groups and Assign Nodes behavior from the listed commercial commits, excludes commercial-only material, passes the guard and focused tests, and has a clean implementation history that makes the cherry-picked slices reviewable.
