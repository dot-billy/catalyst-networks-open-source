# Customer App To OSS Port Ledger

This ledger records feature-port decisions from `customer_app` into OSS. Plane tracks execution state; this file records product-boundary decisions so future diffs can be triaged consistently.

Statuses: `observed`, `triaged`, `planned`, `porting`, `review`, `ported`, `rejected`, `watch`.

| ID | Observed | Source | Area | Class | Decision | Source Files | OSS Target | Required Changes | Tests | Guard | Status |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| PORT-2026-06-01-001 | 2026-06-01 | `customer_app origin/main` + `CNCUST-ff0e9d9e/operator-console-ui` | Email | `port:shared` | Keep Resend/Anymail provider selection in both repos. | `open_cvpn/email_settings.py`, email settings/tests | `open_cvpn/email_settings.py`, settings/docs/tests | Preserve explicit backend, Resend, Mailgun, SMTP precedence. | `open_cvpn.tests_email_settings`, invitation email tests | Secret scan covers `RESEND_API_KEY`. | ported |
| PORT-2026-06-01-002 | 2026-06-01 | customer convergence baseline | UI | `port:shared` | OSS should match shared command-center UI while retaining OSS docs/bootstrap/mobile flows. | org detail, base shell, mobile nav, design CSS | org detail, base shell, mobile nav, `ops-*` CSS | Exclude support/licensing/plans/demo UI. | Template smoke and screenshot checks | OSS guard blocks hosted-only terms/paths. | porting |
| PORT-2026-06-01-003 | 2026-06-01 | OSS SSO canonical implementation | SSO | `port:shared` | Standardize both repos on `SSOConfiguration` and `/sso/<slug>/...` routes. | `sso/`, `users/` login/JWT hooks | Same | Keep customer legacy SSO URL aliases. | `sso.tests` | Guard rejects commercial license-gated SSO copy. | porting |
| PORT-2026-06-01-004 | 2026-06-01 | customer hosted/commercial modules | Product Boundary | `port:customer-only` | Do not port commercial hosted surfaces into OSS. | licensing, plans, support, billing, entitlement, demo paths | n/a | Reject unless reclassified as generic shared behavior. | `tests.test_oss_guard_scan` | `tools/oss_guard_scan.py` | watch |
| PORT-2026-06-28-001 | 2026-06-28 | `customer_app` commits `cacea6b`, `e220956`, `90b5ede`, `0fee70c`, `64dee9d`, `5bf9fc4`, `6a5426d`, `722719c`, `9b6a2a2` | Security Groups / Assign Nodes | `port:shared` | Direct cherry-pick current Tags, Rules, Matrix, Recipes, Effective Rules, target-group display, and Assign Nodes picker into OSS. | `security_groups`, `nodes`, `templates/security_groups`, `templates/nodes`, `static/css` | Same OSS paths | Preserve OSS docs/bootstrap/mobile/bulk-node behavior; remove commercial planning/runtime files; reconcile Assign Nodes to the OSS table picker. | `security_groups.tests`, `nodes.tests`, migration smoke | `tools/oss_guard_scan.py` | ported |

## Intake Cadence

- Every customer feature/spec gets a portability decision before merge.
- Before each customer release, review customer changes since the last ledger watermark.
- Security, auth, SSO, email, node API, certificate reliability, and reusable UI changes are same-day triage.
- Hosted-only support, plans, licensing, billing, demo, entitlement, GitOps secrets, and deployment state default to rejected for OSS.
