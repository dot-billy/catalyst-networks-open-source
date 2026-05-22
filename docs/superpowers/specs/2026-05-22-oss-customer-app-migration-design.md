# OSS Customer App Migration Design

Date: 2026-05-22
Plane issue: b1e35b60-f98f-4002-8dce-eb4d4a0c91cb
Branch: CNCUST-b1e35b60/migrate-oss-improvements

## Goal

Selectively migrate reusable improvements from the private `customer_app` project into
`catalyst-networks-open-source` while keeping the open-source project free of business,
commercial, customer-hosted, and private deployment concerns.

The migration must preserve target-only open-source work that already exists in
`catalyst-networks-open-source`, including in-app docs, bulk operations, QR/mobile node
flows, and the current uncommitted SAML SSO work.

## Approved Approach

Use a selective migration with OSS guardrails. The private app is a reference source, not
a replacement tree. Changes will be ported by feature area and reconciled against the
open-source codebase. Whole-directory copies and unfiltered cherry-picks are out of
scope because the repositories have diverged and the private app contains business-only
modules.

## Included Scope

- SAML SSO as a normal open-source organization feature, with no plan or license gates.
- Slack notifications as a generic user-configured integration, with no hosted-service
  assumptions.
- Security hardening from the private app where it applies cleanly to OSS:
  `DJANGO_DEBUG=False` by default, env-based allowed hosts, safer node API auth, removal
  of debug/direct access bypasses, and sanitized auth logging.
- Certificate and configuration reliability fixes:
  regeneration when cert files are missing or stale, correct cert claims for node groups
  and networks, safer zip names, renewal behavior, and cleanup scheduling where useful.
- Security policy workflow improvements for source-to-destination policy management.
- Public/auth shell, error page, and static asset cache fixes that are generic and useful
  to OSS deployments.
- Minimal deployment improvements required to smoke test a temporary DigitalOcean
  deployment with Docker Compose.

## Excluded Scope

- Commercial/business modules: `licensing/`, `plans/`, `support/`, `analytics/`.
- License checks, paid edition logic, plan limits, demo-mode flows, upgrade banners, SLA
  pages, support-ticket workflows, and hosted-service customer copy.
- Private notification/customer operations that are not needed for user-owned Slack
  notifications.
- Private deployment automation, GitOps workflows, Docker Hub publishing, production
  cluster manifests, internal domains, build logs, local notes, generated runtime state,
  cert/key stores, and `.env` files.
- Any copied secret values, bearer tokens, API keys, customer-specific references, or
  private operational paths.

## Guardrails

Before completing the migration, scan staged and working tree changes for:

- Secret-like keys and values: `SECRET_KEY`, `JWT_SECRET_KEY`, `FIELD_ENCRYPTION_KEY`,
  `AWS_*`, `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `MAILGUN_API_KEY`, `DATABASE_URL`,
  `PRIVATE KEY`, `Bearer`, `x-api-key`, `sessionid`, and registration tokens.
- Excluded directories and runtime state: `licensing/`, `plans/`, `support/`,
  `analytics/`, `certs_data/`, `media/`, `staticfiles/`, `.superpowers/`, `.claude/`,
  `.cursor/`, `.codex/`, `.agents/`, `.env`, `cookies.txt`, `debug.log`, and build logs.
- Private/business copy: `catalystnetworks.io`, `catalystnetworks.com`,
  `app.catalystnetworks.io`, `demo.catalystnetworks.io`, `/etc/catalyst`,
  `customer-app-secrets`, `do-prod`, `license`, `edition`, `enterprise`, `pro`, `trial`,
  `billing`, `subscription`, `upgrade`, `demo`, `customer administration`, `SLA`,
  `telemetry`, and `analytics`.

Matches may be allowed only when they are generic open-source documentation or existing
intentional project branding, not private business logic or credentials.

## Implementation Order

1. Keep the current OSS branch and uncommitted SSO work as the baseline.
2. Add tests or focused checks around changed behavior before implementation where
   practical.
3. Port safe shared hardening first: settings, allowed hosts, node auth, and node API
   behavior.
4. Port certificate/config reliability fixes and Celery scheduling that are useful in
   OSS deployments.
5. Reconcile SAML SSO:
   keep the OSS implementation shape, remove all licensing assumptions, add missing route
   or settings consistency, and cover login enforcement behavior.
6. Port Slack notifications as an OSS integration:
   user-owned incoming webhook URL, encrypted or otherwise protected storage as needed,
   event fan-out from core lifecycle events, and no hosted support/demo coupling.
7. Port security policy UX improvements while preserving open-source docs and existing
   bulk/node mobile flows.
8. Port public/auth shell and static cache fixes if they remain generic after copy review.
9. Update documentation and environment examples without copying private defaults.

## Verification

Local verification must include:

- Django test suite through Docker Compose.
- Migration application on a clean database.
- Health, login, dashboard, organization, node, SSO configuration, and Slack notification
  smoke checks.
- Secret/business-term scan across changed files.
- Docker build or compose startup check.

DigitalOcean smoke verification must include:

- Provision a temporary, clearly tagged droplet through `doctl`.
- Configure generated secrets on the droplet, not copied local `.env` values.
- Restrict app and SSH exposure as much as practical for the smoke test.
- Run Docker Compose, migrations, and service health checks.
- Verify `/health/`, unauthenticated login redirects, login page, dashboard access after
  admin creation, disposable organization creation, SSO settings page load, and Redis not
  publicly reachable.
- Tear down the droplet and confirm it is gone before marking the task complete.

## Risks

- The target repo already has uncommitted SSO changes. Those changes must be preserved and
  reconciled rather than overwritten.
- Source requirements and Docker files cannot replace target files wholesale because the
  OSS repo contains target-only QR/docs/bulk operation dependencies and templates.
- Slack notifications can accidentally pull in hosted notification, unsubscribe, or
  support workflows. Only generic user-configured notification behavior belongs in OSS.
- Production packaging from the private app may contain private registry, GitOps, or
  hosted deployment assumptions. Only generic Docker/Compose improvements should be
  migrated.
