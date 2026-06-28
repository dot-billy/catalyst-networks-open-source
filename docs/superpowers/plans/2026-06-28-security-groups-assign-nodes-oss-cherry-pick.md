# Security Groups Assign Nodes OSS Cherry-Pick Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Direct-cherry-pick the current commercial security-groups and Assign Nodes work into `catalyst-networks-open-source` while preserving OSS-only behavior and blocking commercial-only material.

**Architecture:** Continue from the OSS feature branch, fetch commercial commit objects from the local `customer_app` checkout, protect the current dirty Assign Nodes edits in a stash, then apply commercial commits with `git cherry-pick --no-commit` one slice at a time. Each slice removes commercial planning/runtime files before commit, keeps OSS public docs/bootstrap/mobile-node behavior, and runs focused checks before the next slice.

**Tech Stack:** Django 5.2, PostgreSQL, Redis, Celery, Django templates, HTMX, Alpine.js, Docker Compose, Git cherry-pick, OSS guard scanner.

---

## File Structure

- `docs/superpowers/specs/2026-06-28-security-groups-assign-nodes-oss-sync-design.md`: approved design and source commit sequence.
- `docs/PORT_LEDGER.md`: product-boundary ledger updated at the end with this sync decision.
- `security_groups/models.py`: `Tag` model shape, `SecurityGroup` compatibility alias, directional `FirewallRule`, `target_groups`, `managed_by_recipe`, and through-table compatibility.
- `security_groups/migrations/0007_rename_securitygroup_to_tag.py`, `0008_add_direction_matchtype_targetgroups_color.py`, `0009_backfill_rule_targets_and_match_type.py`, `0010_firewallrule_managed_by_recipe_and_more.py`, `_backfill_helpers.py`: schema and data migration path from current OSS security groups to tags/rules.
- `security_groups/summaries.py`, `security_groups/recipes.py`: plain-English tag summaries and recipe preset registry.
- `security_groups/views.py`, `security_groups/urls_org.py`, `security_groups/tests.py`: org-scoped Tags, Rules, Matrix, Recipes, Assign Nodes, and regression coverage.
- `nodes/models.py`, `nodes/api_registration.py`, `nodes/tasks.py`, `nodes/web_views.py`, `nodes/views.py`, `nodes/urls_org.py`, `nodes/effective_rules.py`, `nodes/tests.py`: tag-aware config rendering, cert group claims, effective rule display, and node route wiring.
- `templates/security_groups/*.html`: tag detail/list, matrix, rule preview/form, recipes, Assign Nodes table UI.
- `templates/nodes/effective_rules.html`, `templates/nodes/org_detail.html`, `templates/nodes/org_security_groups.html`: node-side entry points and effective rule display.
- `templates/base/base.html`, `templates/components/mobile_nav.html`, `static/css/design-system.css`: navigation wording and Assign Nodes picker styling.
- `tools/oss_guard_scan.py`, `tests/test_oss_guard_scan.py`, `tests/test_port_diff_intake.py`: guardrails that must stay intact and passing.

## Source Commits

Use these full commercial SHAs:

```text
cacea6b9943b9fd34d78776d458cf0977eee7da5  Security groups: Tags + directional Rules + CIDR-source firewall fix
e2209561e97f20847e10b53a92cac91a46c56871  Phase 4 slice 1/6: Foundation
90b5ede33dfe50661c74345ad0554dc57cafca4a  Phase 4 slice 2/6: Tag list/detail + summary
0fee70cf933a9ad8e2ef9d7791e75602a4cc042c  Phase 4 slice 3/6: Node x Tag matrix
64dee9db89bce273d8b896f9af68b49c55650df4  Phase 4 slice 4/6: direction-first rule editor
5bf9fc4564e111d7aa2f0691c299801ace10e7a8  Phase 4 slice 5/6: per-node Effective Rules
6a5426d305a729b7819b510eed9992cd1fc579e6  Phase 4 slice 6/6: Recipes
722719c9eda27be5809132e49fc6ef0c553abaa3  fix: surface target-group firewall rules
9b6a2a28ff25ed87bab6c2de0f382930426dffef  feat: dense searchable node picker
```

## Conflict Policy

Use this decision table for every conflicted path:

| Path pattern | Decision |
| --- | --- |
| `.superpowers/**`, `.claude/**`, `.codex/**`, `.agents/**` | Remove from the index and working tree. |
| `docs/superpowers/plans/2026-06-21-phase4-*.md` | Remove from the index and working tree; this OSS plan supersedes those commercial plans. |
| `docs/superpowers/specs/2026-06-21-phase4-security-groups-ui-design.md` | Remove from the index and working tree; the approved OSS spec supersedes it. |
| `.github/workflows/docker-build.yml`, deployment, registry, GitOps, runtime files | Keep the OSS version or remove the incoming file. |
| `templates/base/base.html`, `templates/components/mobile_nav.html` | Keep OSS docs/bootstrap links and add only Tags/Rules navigation wording needed by this feature. |
| `nodes/views.py`, `nodes/urls_org.py`, `nodes/web_views.py` | Keep OSS bulk export/import/delete/renew, mobile-node creation/signing, and registration-token routes while adding effective-rules wiring. |
| `templates/nodes/org_detail.html`, `templates/nodes/org_security_groups.html` | Keep OSS mobile/bulk node affordances and add tag/effective-rules entry points. |
| `security_groups/**`, `templates/security_groups/**` | Prefer incoming commercial feature behavior, then replace commercial wording with OSS wording where visible to users. |
| `static/css/design-system.css`, `templates/security_groups/org_assign_nodes.html`, `security_groups/tests.py` | Reconcile commercial picker with the existing OSS local table-style picker edits; final page must contain the table markers already asserted by the dirty OSS tests. |

## Task 1: Prepare Branch, Stash Local Picker Edits, And Fetch Commercial Commits

**Files:**
- Modify: none
- Test: Git status and commit-object availability

- [ ] **Step 1: Confirm the OSS branch and dirty files**

Run:

```bash
git status --short --branch
```

Expected: branch `CNCUST-b534e87a/streamline-assign-nodes-picker`; tracked modifications only in `security_groups/tests.py`, `static/css/design-system.css`, and `templates/security_groups/org_assign_nodes.html`; untracked `.claude/` may be present.

- [ ] **Step 2: Stash only the existing tracked Assign Nodes edits**

Run:

```bash
git stash push -m "pre-security-groups-oss-sync-local-picker-edits" -- \
  security_groups/tests.py \
  static/css/design-system.css \
  templates/security_groups/org_assign_nodes.html
```

Expected: `Saved working directory and index state` appears.

- [ ] **Step 3: Confirm the tracked worktree is clean**

Run:

```bash
git status --short --branch
```

Expected: no tracked `M` lines. The untracked `.claude/` directory may still appear and must remain uncommitted.

- [ ] **Step 4: Add or refresh the local commercial remote**

Run:

```bash
if git remote get-url customer-app-local >/dev/null 2>&1; then
  git remote set-url customer-app-local /home/uwadmin/Development/catalyst-networks-mono-repo/customer_app
else
  git remote add customer-app-local /home/uwadmin/Development/catalyst-networks-mono-repo/customer_app
fi
git fetch customer-app-local
```

Expected: fetch completes and creates or updates `customer-app-local/main` and `customer-app-local/CNCUST-b534e87a/streamline-assign-nodes-picker`.

- [ ] **Step 5: Verify every source commit object exists in the OSS repo**

Run:

```bash
for c in \
  cacea6b9943b9fd34d78776d458cf0977eee7da5 \
  e2209561e97f20847e10b53a92cac91a46c56871 \
  90b5ede33dfe50661c74345ad0554dc57cafca4a \
  0fee70cf933a9ad8e2ef9d7791e75602a4cc042c \
  64dee9db89bce273d8b896f9af68b49c55650df4 \
  5bf9fc4564e111d7aa2f0691c299801ace10e7a8 \
  6a5426d305a729b7819b510eed9992cd1fc579e6 \
  722719c9eda27be5809132e49fc6ef0c553abaa3 \
  9b6a2a28ff25ed87bab6c2de0f382930426dffef
do
  git cat-file -e "$c^{commit}" && echo "$c present"
done
```

Expected: nine `present` lines.

- [ ] **Step 6: Run guard baseline**

Run:

```bash
python3 -m unittest tests.test_oss_guard_scan tests.test_port_diff_intake
```

Expected: `OK`.

## Task 2: Cherry-Pick Backend Tag/Rule Prerequisite

**Files:**
- Modify: `nodes/api_registration.py`
- Modify: `nodes/models.py`
- Modify: `nodes/serializers.py`
- Modify: `nodes/tasks.py`
- Modify: `nodes/tests.py`
- Modify: `nodes/web_views.py`
- Modify: `notifications/signals.py`
- Modify: `security_groups/admin.py`
- Create: `security_groups/management/__init__.py`
- Create: `security_groups/management/commands/__init__.py`
- Create: `security_groups/management/commands/dump_node_configs.py`
- Create: `security_groups/migrations/0007_rename_securitygroup_to_tag.py`
- Create: `security_groups/migrations/0008_add_direction_matchtype_targetgroups_color.py`
- Create: `security_groups/migrations/0009_backfill_rule_targets_and_match_type.py`
- Create: `security_groups/migrations/_backfill_helpers.py`
- Modify: `security_groups/models.py`
- Modify: `security_groups/tests.py`
- Modify: `security_groups/views.py`
- Test: `security_groups.tests`, node config/certificate tests

- [ ] **Step 1: Apply the commercial backend prerequisite without committing**

Run:

```bash
git cherry-pick -x --no-commit cacea6b9943b9fd34d78776d458cf0977eee7da5
```

Expected: either a clean staged patch or conflict markers to resolve in the listed files.

- [ ] **Step 2: Resolve conflicts using the shared-backend decision**

Run:

```bash
git diff --name-only --diff-filter=U
```

For each unmerged file, keep the incoming commercial Tag/Rule backend behavior and preserve OSS-only node flows. The final code must satisfy these exact interface names:

```python
from security_groups.models import FirewallRule, Tag
SecurityGroup = Tag
Node.tags
Node.security_groups
Node.get_all_applicable_firewall_rules()
FirewallRule.direction
FirewallRule.match_type
FirewallRule.target_groups
FirewallRule.source_groups
FirewallRule.source_nodes
FirewallRuleSourceGroup
```

After editing the conflicted files, run:

```bash
for f in $(git diff --name-only --diff-filter=U); do
  git add "$f"
done
```

Expected: `git diff --name-only --diff-filter=U` returns no paths.

- [ ] **Step 3: Confirm no blocked files entered the index**

Run:

```bash
git status --short
python3 tools/oss_guard_scan.py
```

Expected: no `.superpowers/`, `.claude/`, `.codex/`, `.agents/`, `licensing/`, `plans/`, `support/`, `analytics/`, or `saas_entitlements/` paths in status; guard scan prints `OSS guard scan passed.`

- [ ] **Step 4: Run focused backend tests**

Run:

```bash
docker compose run --rm -T web python manage.py test \
  security_groups.tests \
  nodes.tests.NodeAPIMasterTokenRegressionTests \
  nodes.tests.NodeCertificateReliabilityTests \
  -v 2
```

Expected: tests pass with `OK`.

- [ ] **Step 5: Commit backend prerequisite**

Run:

```bash
git add \
  nodes/api_registration.py nodes/models.py nodes/serializers.py nodes/tasks.py nodes/tests.py nodes/web_views.py \
  notifications/signals.py \
  security_groups/admin.py security_groups/management security_groups/migrations security_groups/models.py security_groups/tests.py security_groups/views.py
git commit -m "feat: port tag-based security group backend" \
  -m "(cherry picked from commit cacea6b9943b9fd34d78776d458cf0977eee7da5)"
```

Expected: one commit containing only shared backend files.

## Task 3: Cherry-Pick Phase 4 Foundation

**Files:**
- Modify: `nodes/tests.py`
- Modify: `security_groups/tests.py`
- Modify: `security_groups/views.py`
- Modify: `templates/base/base.html`
- Modify: `templates/components/mobile_nav.html`
- Modify: `templates/nodes/org_security_groups.html`
- Remove after cherry-pick: `docs/superpowers/plans/2026-06-21-phase4-foundation.md`
- Remove after cherry-pick: `docs/superpowers/specs/2026-06-21-phase4-security-groups-ui-design.md`
- Test: security group routing/navigation tests

- [ ] **Step 1: Apply the commercial foundation slice without committing**

Run:

```bash
git cherry-pick -x --no-commit e2209561e97f20847e10b53a92cac91a46c56871
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Remove commercial planning docs from this slice**

Run:

```bash
git rm -f --ignore-unmatch \
  docs/superpowers/plans/2026-06-21-phase4-foundation.md \
  docs/superpowers/specs/2026-06-21-phase4-security-groups-ui-design.md
```

Expected: those paths are absent from `git status --short`.

- [ ] **Step 3: Resolve navigation conflicts**

Run:

```bash
git diff --name-only --diff-filter=U
```

For `templates/base/base.html` and `templates/components/mobile_nav.html`, keep OSS docs links and bootstrap registration behavior, and apply only the visible `Groups` to `Tags` and `Policies` to `Rules` navigation changes. After editing:

```bash
git add templates/base/base.html templates/components/mobile_nav.html templates/nodes/org_security_groups.html security_groups/views.py security_groups/tests.py nodes/tests.py
```

Expected: no unmerged paths remain.

- [ ] **Step 4: Run foundation tests**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests nodes.tests.NodeOrgUrlExportTests -v 2
python3 tools/oss_guard_scan.py
```

Expected: Django tests pass with `OK`; guard scan passes.

- [ ] **Step 5: Commit foundation slice**

Run:

```bash
git commit -m "feat: port security groups navigation foundation" \
  -m "(cherry picked from commit e2209561e97f20847e10b53a92cac91a46c56871)"
```

Expected: one commit with no commercial planning docs.

## Task 4: Cherry-Pick Tag List, Detail, And Summaries

**Files:**
- Create: `security_groups/summaries.py`
- Modify: `security_groups/tests.py`
- Modify: `security_groups/views.py`
- Modify: `templates/security_groups/detail.html`
- Modify: `templates/security_groups/org_list.html`
- Remove after cherry-pick: `docs/superpowers/plans/2026-06-21-phase4-slice2-tags.md`
- Test: tag summary/list/detail tests

- [ ] **Step 1: Apply the commercial tag summary slice without committing**

Run:

```bash
git cherry-pick -x --no-commit 90b5ede33dfe50661c74345ad0554dc57cafca4a
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Remove commercial planning doc**

Run:

```bash
git rm -f --ignore-unmatch docs/superpowers/plans/2026-06-21-phase4-slice2-tags.md
```

Expected: the commercial plan file is absent from status.

- [ ] **Step 3: Resolve and stage tag files**

Run:

```bash
git diff --name-only --diff-filter=U
git add security_groups/summaries.py security_groups/tests.py security_groups/views.py templates/security_groups/detail.html templates/security_groups/org_list.html
```

Expected: no unmerged paths remain.

- [ ] **Step 4: Run tag tests and guard scan**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests -v 2
python3 tools/oss_guard_scan.py
```

Expected: tests pass with `OK`; guard scan passes.

- [ ] **Step 5: Commit tag summary slice**

Run:

```bash
git commit -m "feat: port tag summaries and detail views" \
  -m "(cherry picked from commit 90b5ede33dfe50661c74345ad0554dc57cafca4a)"
```

Expected: one commit.

## Task 5: Cherry-Pick Node x Tag Matrix

**Files:**
- Modify: `security_groups/tests.py`
- Modify: `security_groups/urls_org.py`
- Modify: `security_groups/views.py`
- Create: `templates/security_groups/_matrix_apply_result.html`
- Create: `templates/security_groups/matrix.html`
- Modify: `templates/security_groups/org_list.html`
- Remove after cherry-pick: `.superpowers/slice3-fixes.md`
- Remove after cherry-pick: `docs/superpowers/plans/2026-06-21-phase4-slice3-matrix.md`
- Test: matrix view/apply tests

- [ ] **Step 1: Apply the commercial matrix slice without committing**

Run:

```bash
git cherry-pick -x --no-commit 0fee70cf933a9ad8e2ef9d7791e75602a4cc042c
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Remove commercial-only files**

Run:

```bash
git rm -f --ignore-unmatch \
  .superpowers/slice3-fixes.md \
  docs/superpowers/plans/2026-06-21-phase4-slice3-matrix.md
```

Expected: neither path appears in status.

- [ ] **Step 3: Resolve and stage matrix files**

Run:

```bash
git diff --name-only --diff-filter=U
git add \
  security_groups/tests.py security_groups/urls_org.py security_groups/views.py \
  templates/security_groups/_matrix_apply_result.html templates/security_groups/matrix.html templates/security_groups/org_list.html
```

Expected: no unmerged paths remain.

- [ ] **Step 4: Run matrix tests and guard scan**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests -v 2
python3 tools/oss_guard_scan.py
```

Expected: tests pass with `OK`; guard scan passes.

- [ ] **Step 5: Commit matrix slice**

Run:

```bash
git commit -m "feat: port node tag matrix" \
  -m "(cherry picked from commit 0fee70cf933a9ad8e2ef9d7791e75602a4cc042c)"
```

Expected: one commit.

## Task 6: Cherry-Pick Direction-First Rule Editor

**Files:**
- Modify: `nodes/api_registration.py`
- Modify: `nodes/tests.py`
- Modify: `security_groups/tests.py`
- Modify: `security_groups/urls_org.py`
- Modify: `security_groups/views.py`
- Create: `templates/security_groups/_rule_preview.html`
- Modify: `templates/security_groups/org_policy_list.html`
- Create: `templates/security_groups/rule_form.html`
- Remove after cherry-pick: `docs/superpowers/plans/2026-06-21-phase4-slice4b-rule-editor.md`
- Test: rule editor and config rendering tests

- [ ] **Step 1: Apply the commercial rule-editor slice without committing**

Run:

```bash
git cherry-pick -x --no-commit 64dee9db89bce273d8b896f9af68b49c55650df4
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Remove commercial planning doc**

Run:

```bash
git rm -f --ignore-unmatch docs/superpowers/plans/2026-06-21-phase4-slice4b-rule-editor.md
```

Expected: the commercial plan file is absent from status.

- [ ] **Step 3: Resolve and stage rule-editor files**

Run:

```bash
git diff --name-only --diff-filter=U
git add \
  nodes/api_registration.py nodes/tests.py \
  security_groups/tests.py security_groups/urls_org.py security_groups/views.py \
  templates/security_groups/_rule_preview.html templates/security_groups/org_policy_list.html templates/security_groups/rule_form.html
```

Expected: no unmerged paths remain.

- [ ] **Step 4: Run rule-editor and node config tests**

Run:

```bash
docker compose run --rm -T web python manage.py test \
  security_groups.tests \
  nodes.tests.NodeCertificateReliabilityTests \
  -v 2
python3 tools/oss_guard_scan.py
```

Expected: tests pass with `OK`; guard scan passes.

- [ ] **Step 5: Commit rule-editor slice**

Run:

```bash
git commit -m "feat: port direction-first rule editor" \
  -m "(cherry picked from commit 64dee9db89bce273d8b896f9af68b49c55650df4)"
```

Expected: one commit.

## Task 7: Cherry-Pick Per-Node Effective Rules

**Files:**
- Create: `nodes/effective_rules.py`
- Modify: `nodes/tests.py`
- Modify: `nodes/urls_org.py`
- Modify: `nodes/views.py`
- Modify: `nodes/web_views.py`
- Create: `templates/nodes/effective_rules.html`
- Modify: `templates/nodes/org_detail.html`
- Remove after cherry-pick: `docs/superpowers/plans/2026-06-21-phase4-slice5-effective-rules.md`
- Test: effective rules tests

- [ ] **Step 1: Apply the commercial effective-rules slice without committing**

Run:

```bash
git cherry-pick -x --no-commit 5bf9fc4564e111d7aa2f0691c299801ace10e7a8
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Remove commercial planning doc**

Run:

```bash
git rm -f --ignore-unmatch docs/superpowers/plans/2026-06-21-phase4-slice5-effective-rules.md
```

Expected: the commercial plan file is absent from status.

- [ ] **Step 3: Preserve OSS node routes while adding effective rules**

Run:

```bash
git diff --name-only --diff-filter=U
```

In `nodes/urls_org.py`, final routes must include all existing OSS routes plus:

```python
path('<int:pk>/effective-rules/', views.org_node_effective_rules, name='effective_rules')
```

In `nodes/views.py`, final exports must keep OSS bulk/mobile views callable and expose `org_node_effective_rules`. Stage files:

```bash
git add \
  nodes/effective_rules.py nodes/tests.py nodes/urls_org.py nodes/views.py nodes/web_views.py \
  templates/nodes/effective_rules.html templates/nodes/org_detail.html
```

Expected: no unmerged paths remain.

- [ ] **Step 4: Run effective-rules tests and guard scan**

Run:

```bash
docker compose run --rm -T web python manage.py test nodes.tests.NodeCertificateReliabilityTests nodes.tests.NodeOrgUrlExportTests -v 2
python3 tools/oss_guard_scan.py
```

Expected: tests pass with `OK`; guard scan passes.

- [ ] **Step 5: Commit effective-rules slice**

Run:

```bash
git commit -m "feat: port per-node effective rules" \
  -m "(cherry picked from commit 5bf9fc4564e111d7aa2f0691c299801ace10e7a8)"
```

Expected: one commit.

## Task 8: Cherry-Pick Recipes

**Files:**
- Create: `security_groups/migrations/0010_firewallrule_managed_by_recipe_and_more.py`
- Modify: `security_groups/models.py`
- Create: `security_groups/recipes.py`
- Modify: `security_groups/tests.py`
- Modify: `security_groups/urls_org.py`
- Modify: `security_groups/views.py`
- Modify: `templates/security_groups/org_list.html`
- Create: `templates/security_groups/recipes.html`
- Remove after cherry-pick: `docs/superpowers/plans/2026-06-21-phase4-slice6-recipes.md`
- Test: recipe tests and migrations

- [ ] **Step 1: Apply the commercial recipes slice without committing**

Run:

```bash
git cherry-pick -x --no-commit 6a5426d305a729b7819b510eed9992cd1fc579e6
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Remove commercial planning doc**

Run:

```bash
git rm -f --ignore-unmatch docs/superpowers/plans/2026-06-21-phase4-slice6-recipes.md
```

Expected: the commercial plan file is absent from status.

- [ ] **Step 3: Resolve and stage recipe files**

Run:

```bash
git diff --name-only --diff-filter=U
git add \
  security_groups/migrations/0010_firewallrule_managed_by_recipe_and_more.py \
  security_groups/models.py security_groups/recipes.py security_groups/tests.py security_groups/urls_org.py security_groups/views.py \
  templates/security_groups/org_list.html templates/security_groups/recipes.html
```

Expected: no unmerged paths remain.

- [ ] **Step 4: Run recipe and migration checks**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests -v 2
docker compose run --rm -T web python manage.py makemigrations --check --dry-run
python3 tools/oss_guard_scan.py
```

Expected: tests pass with `OK`; `makemigrations` reports no model changes; guard scan passes.

- [ ] **Step 5: Commit recipes slice**

Run:

```bash
git commit -m "feat: port security group recipes" \
  -m "(cherry picked from commit 6a5426d305a729b7819b510eed9992cd1fc579e6)"
```

Expected: one commit.

## Task 9: Cherry-Pick Target-Group Display Fix

**Files:**
- Modify: `security_groups/tests.py`
- Modify: `security_groups/views.py`
- Modify: `templates/security_groups/detail.html`
- Modify: `templates/security_groups/org_policy_list.html`
- Test: target-group detail/list display tests

- [ ] **Step 1: Apply the target-group display fix without committing**

Run:

```bash
git cherry-pick -x --no-commit 722719c9eda27be5809132e49fc6ef0c553abaa3
```

Expected: staged changes or conflicts in the listed files.

- [ ] **Step 2: Resolve and stage display files**

Run:

```bash
git diff --name-only --diff-filter=U
git add security_groups/tests.py security_groups/views.py templates/security_groups/detail.html templates/security_groups/org_policy_list.html
```

Expected: no unmerged paths remain.

- [ ] **Step 3: Run display tests and guard scan**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests -v 2
python3 tools/oss_guard_scan.py
```

Expected: tests pass with `OK`; guard scan passes.

- [ ] **Step 4: Commit target-group display fix**

Run:

```bash
git commit -m "fix: show target-group firewall rules" \
  -m "(cherry picked from commit 722719c9eda27be5809132e49fc6ef0c553abaa3)"
```

Expected: one commit.

## Task 10: Reconcile Assign Nodes Picker Cherry-Pick And Existing OSS Picker Edits

**Files:**
- Modify: `security_groups/tests.py`
- Modify: `static/css/design-system.css`
- Modify: `templates/security_groups/org_assign_nodes.html`
- Test: Assign Nodes picker tests

- [ ] **Step 1: Apply the commercial Assign Nodes picker without committing**

Run:

```bash
git cherry-pick -x --no-commit 9b6a2a28ff25ed87bab6c2de0f382930426dffef
```

Expected: staged changes, conflicts, or an empty cherry-pick because OSS commit `2d1aa67` already ported the base picker.

- [ ] **Step 2: Handle an empty picker cherry-pick**

Run this check:

```bash
git status --short
```

If Git reports the cherry-pick is empty, run:

```bash
git cherry-pick --skip
```

Expected after skip: no active cherry-pick state.

- [ ] **Step 3: Reapply the pre-existing OSS table-style picker edits**

Run:

```bash
STASH_REF=$(git stash list --format='%gd %s' | awk '/pre-security-groups-oss-sync-local-picker-edits/{print $1; exit}')
test -n "$STASH_REF"
git stash apply "$STASH_REF"
```

Expected: either clean application or conflicts only in `security_groups/tests.py`, `static/css/design-system.css`, and `templates/security_groups/org_assign_nodes.html`.

- [ ] **Step 4: Resolve picker conflicts toward the OSS table UI**

Final `security_groups/tests.py` must include assertions for these markers:

```python
self.assertContains(resp, 'Search all columns')
self.assertContains(resp, 'ui-node-picker-table')
self.assertContains(resp, 'ui-node-picker-table-header')
self.assertContains(resp, 'aria-label="Sort by assignment"')
self.assertContains(resp, 'aria-label="Sort by name"')
self.assertContains(resp, 'aria-label="Sort by IP"')
self.assertContains(resp, 'aria-label="Sort by type"')
self.assertContains(resp, 'placeholder="Filter name"')
self.assertContains(resp, 'placeholder="Filter IP"')
self.assertContains(resp, 'x-model="typeFilter"')
self.assertContains(resp, 'x-model="assignedFilter"')
self.assertContains(resp, "sortBy('assigned')")
self.assertContains(resp, 'Select visible')
self.assertContains(resp, 'Clear visible')
```

Stage picker files:

```bash
git add security_groups/tests.py static/css/design-system.css templates/security_groups/org_assign_nodes.html
```

Expected: no unmerged paths remain.

- [ ] **Step 5: Run picker tests and guard scan**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests.AssignNodesPickerTests -v 2
python3 tools/oss_guard_scan.py
```

Expected: picker tests pass with `OK`; guard scan passes.

- [ ] **Step 6: Commit picker reconciliation**

Run:

```bash
git commit -m "feat: reconcile assign nodes table picker" \
  -m "(cherry picked from commit 9b6a2a28ff25ed87bab6c2de0f382930426dffef)"
```

Expected: one commit if files changed. If no files changed after the empty cherry-pick and stash apply, do not create a duplicate picker commit.

## Task 11: Update Port Ledger

**Files:**
- Modify: `docs/PORT_LEDGER.md`
- Test: OSS guard scan

- [ ] **Step 1: Add the security-groups sync ledger row**

Append this row to the ledger table in `docs/PORT_LEDGER.md`:

```markdown
| PORT-2026-06-28-001 | 2026-06-28 | `customer_app` commits `cacea6b`, `e220956`, `90b5ede`, `0fee70c`, `64dee9d`, `5bf9fc4`, `6a5426d`, `722719c`, `9b6a2a2` | Security Groups / Assign Nodes | `port:shared` | Direct cherry-pick current Tags, Rules, Matrix, Recipes, Effective Rules, target-group display, and Assign Nodes picker into OSS. | security_groups, nodes, templates/security_groups, templates/nodes, static/css | Same OSS paths | Preserve OSS docs/bootstrap/mobile/bulk-node behavior; remove commercial planning/runtime files. | `security_groups.tests`, `nodes.tests`, migration smoke | `tools/oss_guard_scan.py` | porting |
```

- [ ] **Step 2: Run guard scan**

Run:

```bash
python3 tools/oss_guard_scan.py docs/PORT_LEDGER.md
```

Expected: `OSS guard scan passed.`

- [ ] **Step 3: Commit ledger update**

Run:

```bash
git add docs/PORT_LEDGER.md
git commit -m "docs: record security groups OSS sync"
```

Expected: one docs commit.

## Task 12: Final Verification

**Files:**
- Test only

- [ ] **Step 1: Run guard unit tests**

Run:

```bash
python3 -m unittest tests.test_oss_guard_scan tests.test_port_diff_intake
```

Expected: `OK`.

- [ ] **Step 2: Run focused Django tests**

Run:

```bash
docker compose run --rm -T web python manage.py test security_groups.tests nodes.tests -v 2
```

Expected: tests pass with `OK`.

- [ ] **Step 3: Run migration consistency check**

Run:

```bash
docker compose run --rm -T web python manage.py makemigrations --check --dry-run
```

Expected: `No changes detected`.

- [ ] **Step 4: Run clean-database migration smoke in an isolated Compose project**

Run:

```bash
COMPOSE_PROJECT_NAME=oss_sg_sync_check docker compose down -v
COMPOSE_PROJECT_NAME=oss_sg_sync_check docker compose up -d db redis
COMPOSE_PROJECT_NAME=oss_sg_sync_check docker compose run --rm -T web python manage.py migrate --noinput
COMPOSE_PROJECT_NAME=oss_sg_sync_check docker compose run --rm -T web python manage.py check
COMPOSE_PROJECT_NAME=oss_sg_sync_check docker compose down -v
```

Expected: migrations apply successfully; `System check identified no issues`.

- [ ] **Step 5: Run final guard scan over changed files**

Run:

```bash
python3 tools/oss_guard_scan.py
```

Expected: `OSS guard scan passed.`

- [ ] **Step 6: Confirm no commercial-only files are tracked**

Run:

```bash
git ls-files | rg '(^|/)(\.superpowers|\.claude|\.codex|\.agents|licensing|plans|support|analytics|saas_entitlements|billing|certs_data|media|staticfiles)(/|$)' || true
```

Expected: no output except pre-existing OSS-allowed files already reviewed before this task. If output appears for newly introduced paths, remove those paths and rerun the guard scan.

- [ ] **Step 7: Confirm final status**

Run:

```bash
git status --short --branch
git log --oneline --decorate --max-count=12
```

Expected: branch is ahead of `origin/main`; only untracked `.claude/` may remain; recent commits show the spec, plan, and cherry-picked security-groups slices.

## Task 13: Final Review Notes

**Files:**
- Read: `git diff origin/main...HEAD --stat`
- Read: `git log --oneline origin/main..HEAD`

- [ ] **Step 1: Summarize implementation scope**

Run:

```bash
git diff origin/main...HEAD --stat
git log --oneline origin/main..HEAD
```

Expected: diff contains only OSS-safe security-groups, node effective/config, templates, CSS, docs, and tests work.

- [ ] **Step 2: Prepare handoff summary**

Write a short summary for the user with:

```text
Implemented:
- Tags/directional Rules backend and migrations
- Node x Tag matrix, rule editor, recipes, effective rules
- target-group rule display
- Assign Nodes table picker reconciliation

Verification:
- python3 -m unittest tests.test_oss_guard_scan tests.test_port_diff_intake
- docker compose run --rm -T web python manage.py test security_groups.tests nodes.tests -v 2
- docker compose run --rm -T web python manage.py makemigrations --check --dry-run
- clean Compose migration smoke
- python3 tools/oss_guard_scan.py
```

Expected: the user can decide whether to push/open a PR or request fixes.
