# OSS Customer App Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Selectively migrate reusable private `customer_app` improvements into `catalyst-networks-open-source` while excluding business-only logic and smoke testing the result on a temporary DigitalOcean droplet.

**Architecture:** Treat `catalyst-networks-open-source` as the target of truth and port private code by feature area. Each migrated feature must be reconciled with existing OSS docs, QR/mobile node flows, bulk operations, and the current SAML SSO working tree. Private modules are reference material only and must not be copied wholesale.

**Tech Stack:** Django 5.2, Django REST Framework, SimpleJWT, django-simple-history, Celery, Redis, PostgreSQL, HTMX/templates, Docker Compose, python3-saml, DigitalOcean `doctl`.

---

## File Structure

- `tools/oss_guard_scan.py`: repo-local guardrail scanner for secrets, excluded paths, private domains, and business-only terms.
- `open_cvpn/settings.py`, `open_cvpn/settings-prod.py`, `open_cvpn/urls.py`, `open_cvpn/celery.py`: generic security, app wiring, scheduling, and route changes.
- `nodes/authentication.py`, `nodes/api_registration.py`, `nodes/api_views.py`, `nodes/tasks.py`, `nodes/tests.py`: node auth hardening and certificate/config reliability.
- `sso/*`, `templates/base/login.html`, `templates/organizations/detail.html`, `users/views.py`, `users/tests.py`: SAML SSO as an OSS feature.
- `notifications/*`, `templates/notifications/preferences.html`, `templates/notifications/slack.html`: generic Slack notification integration.
- `webhooks/models.py`, `webhooks/tests.py`: shared event vocabulary, only if Slack integration needs reuse.
- `security_groups/views.py`, `security_groups/urls_org.py`, `security_groups/tests.py`, `templates/security_groups/org_policy_*.html`: source-to-destination policy workflow.
- `templates/base/auth_base.html`, `templates/400.html`, `templates/403.html`, `templates/404.html`, `templates/500.html`, `templates/502.html`, `static/css/fonts.css`: generic public/auth shell and static cache fixes.
- `Dockerfile`, `docker-compose.yml`, `docker-entrypoint.sh`, `.env.example`, `.env.prod.example`, `README.md`: generic deployment/docs updates needed for local and DigitalOcean smoke tests.

## Task 1: Guardrail Scanner

**Files:**
- Create: `tools/oss_guard_scan.py`
- Modify: none
- Test: command-line scan against the repository

- [ ] **Step 1: Create the scanner**

Create `tools/oss_guard_scan.py` with this content:

```python
#!/usr/bin/env python3
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

BLOCKED_PATHS = re.compile(
    r"(^|/)(licensing|plans|support|analytics|certs_data|media|staticfiles|"
    r"\.superpowers|\.claude|\.cursor|\.codex|\.agents|venv|__pycache__)(/|$)|"
    r"(^|/)(\.env(\..*)?|cookies\.txt|debug\.log|build_deploy_logs\.json|celerybeat-schedule)$"
)

SECRET_PATTERNS = re.compile(
    r"(SECRET_KEY\s*=|JWT_SECRET_KEY\s*=|FIELD_ENCRYPTION_KEY\s*=|AWS_ACCESS_KEY_ID\s*=|"
    r"AWS_SECRET_ACCESS_KEY\s*=|POSTGRES_PASSWORD\s*=|REDIS_PASSWORD\s*=|MAILGUN_API_KEY\s*=|"
    r"SUPPORT_GATEWAY_SECRET\s*=|DATABASE_URL\s*=|BEGIN [A-Z ]*PRIVATE KEY|"
    r"Authorization:\s*Bearer|x-api-key\s*[:=]|sessionid\s*=|csrftoken\s*=|"
    r"NEBULA_(API_PASSWORD|REGISTRATION_TOKEN|REFRESH_TOKEN)\s*=)",
    re.IGNORECASE,
)

BUSINESS_PATTERNS = re.compile(
    r"(catalystnetworks\.io|catalystnetworks\.com|app\.catalystnetworks\.io|"
    r"demo\.catalystnetworks\.io|/etc/catalyst|customer-app-secrets|do-prod|"
    r"\blicens(e|ing)\b|\bedition\b|\benterprise\b|\bpro\b|\btrial\b|\bbilling\b|"
    r"\bsubscription\b|\bupgrade\b|\bdemo\b|customer administration|\bSLA\b|"
    r"\btelemetry\b|\banalytics\b)",
    re.IGNORECASE,
)

ALLOWLIST = {
    "docs/superpowers/specs/2026-05-22-oss-customer-app-migration-design.md",
    "docs/superpowers/plans/2026-05-22-oss-customer-app-migration.md",
    "tools/oss_guard_scan.py",
}


def changed_files() -> list[Path]:
    proc = subprocess.run(
        ["git", "diff", "--name-only", "--cached", "HEAD"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    if not names:
        proc = subprocess.run(
            ["git", "diff", "--name-only", "HEAD"],
            cwd=ROOT,
            check=True,
            text=True,
            capture_output=True,
        )
        names = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return [ROOT / name for name in names]


def scan_file(path: Path) -> list[str]:
    relative = path.relative_to(ROOT).as_posix()
    findings: list[str] = []
    if relative in ALLOWLIST:
        return findings
    if BLOCKED_PATHS.search(relative):
        findings.append(f"{relative}: blocked path")
        return findings
    if not path.is_file():
        return findings
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        findings.append(f"{relative}: non-text file needs manual review")
        return findings
    for lineno, line in enumerate(text.splitlines(), 1):
        if SECRET_PATTERNS.search(line):
            findings.append(f"{relative}:{lineno}: secret-like value")
        if BUSINESS_PATTERNS.search(line):
            findings.append(f"{relative}:{lineno}: business/private term")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("paths", nargs="*", help="Optional paths to scan. Defaults to changed files.")
    args = parser.parse_args()
    paths = [ROOT / p for p in args.paths] if args.paths else changed_files()
    findings: list[str] = []
    for path in paths:
        findings.extend(scan_file(path.resolve()))
    if findings:
        print("OSS guard scan failed:")
        for finding in findings:
            print(f"  - {finding}")
        return 1
    print("OSS guard scan passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
```

- [ ] **Step 2: Make it executable**

Run:

```bash
chmod +x tools/oss_guard_scan.py
```

- [ ] **Step 3: Run the scanner**

Run:

```bash
python tools/oss_guard_scan.py tools/oss_guard_scan.py
```

Expected: `OSS guard scan passed.`

- [ ] **Step 4: Commit**

Run:

```bash
git add tools/oss_guard_scan.py
git commit -m "chore: add OSS migration guard scanner"
```

## Task 2: Security And Node API Hardening

**Files:**
- Modify: `open_cvpn/settings.py`
- Modify: `.env.example`
- Modify: `.env.prod.example`
- Modify: `nodes/authentication.py`
- Modify: `nodes/api_registration.py`
- Modify: `nodes/api_views.py`
- Modify: `nodes/tests.py`

- [ ] **Step 1: Write settings and node auth tests**

Add tests to `nodes/tests.py` that assert:

```python
def test_master_registration_token_is_not_accepted_for_node_config(self):
    response = self.client.get(
        reverse("nodes:node-config", kwargs={"org_slug": self.organization.slug, "node_id": self.node.id}),
        HTTP_AUTHORIZATION="Bearer master-registration-token-change-me",
    )
    self.assertIn(response.status_code, {401, 403})
```

Use existing test fixtures in `nodes/tests.py`; do not create a second organization/model setup style.

- [ ] **Step 2: Run the focused test and verify it fails or exposes current behavior**

Run:

```bash
docker compose run --rm web python manage.py test nodes.tests
```

Expected before implementation: failure if master token or debug path is still accepted.

- [ ] **Step 3: Port hardening**

Apply source hardening manually:

- `open_cvpn/settings.py`: default `DJANGO_DEBUG` to `False`.
- `open_cvpn/settings.py`: replace `ALLOWED_HOSTS = ['*']` with `DJANGO_ALLOWED_HOSTS` parsing and local defaults.
- `.env.example`: add `DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1`.
- `nodes/api_registration.py`: do not allow global registration master tokens to fetch node config or bypass org-scoped token checks.
- `nodes/authentication.py`: avoid printing or logging token values; error messages must not include supplied secrets.
- `nodes/api_views.py`: remove or protect any debug/direct access endpoint that bypasses object permission checks.

- [ ] **Step 4: Re-run tests**

Run:

```bash
docker compose run --rm web python manage.py test nodes.tests
```

Expected: all `nodes.tests` pass.

- [ ] **Step 5: Guard scan and commit**

Run:

```bash
python tools/oss_guard_scan.py open_cvpn/settings.py .env.example .env.prod.example nodes/authentication.py nodes/api_registration.py nodes/api_views.py nodes/tests.py
git add open_cvpn/settings.py .env.example .env.prod.example nodes/authentication.py nodes/api_registration.py nodes/api_views.py nodes/tests.py
git commit -m "fix: harden OSS node API settings"
```

## Task 3: Certificate And Config Reliability

**Files:**
- Modify: `nodes/api_registration.py`
- Modify: `nodes/tasks.py`
- Modify: `open_cvpn/celery.py`
- Modify: `nodes/tests.py`
- Modify: `.env.example`
- Modify: `.env.prod.example`

- [ ] **Step 1: Add regression tests**

Add focused tests in `nodes/tests.py` that cover:

```python
def test_config_download_regenerates_missing_certificate_files(self):
    self.node.cert_path = "certs/missing.crt"
    self.node.key_path = "certs/missing.key"
    self.node.save(update_fields=["cert_path", "key_path"])
    response = self.client.get(self.config_url, HTTP_AUTHORIZATION=f"Bearer {self.node.api_token}")
    self.assertEqual(response.status_code, 200)
    self.node.refresh_from_db()
    self.assertTrue(self.node.cert_path)
    self.assertTrue(self.node.key_path)
```

Also add a zip naming assertion for generated bundles:

```python
self.assertIn("node.crt", zip_file.namelist())
self.assertIn("node.key", zip_file.namelist())
```

Adapt names to the existing helpers in `nodes/tests.py`.

- [ ] **Step 2: Run the focused tests**

Run:

```bash
docker compose run --rm web python manage.py test nodes.tests
```

Expected before implementation: at least one reliability assertion fails if the target lacks the source fix.

- [ ] **Step 3: Port certificate regeneration behavior**

Manually port the source logic from private `customer_app/nodes/api_registration.py` and `nodes/tasks.py`:

- Regenerate node cert/key files when saved paths are missing from storage.
- Regenerate certs when certificate claims no longer match node groups or networks.
- Include security group names in renewed cert claims when the source code already supports that.
- Use stable bundle entry names `node.crt` and `node.key`.
- Add stale certificate cleanup scheduling only if it is generic and does not reference private deployment paths.

- [ ] **Step 4: Re-run tests**

Run:

```bash
docker compose run --rm web python manage.py test nodes.tests certificates.tests
```

Expected: tests pass.

- [ ] **Step 5: Guard scan and commit**

Run:

```bash
python tools/oss_guard_scan.py nodes/api_registration.py nodes/tasks.py open_cvpn/celery.py nodes/tests.py .env.example .env.prod.example
git add nodes/api_registration.py nodes/tasks.py open_cvpn/celery.py nodes/tests.py .env.example .env.prod.example
git commit -m "fix: improve OSS certificate regeneration"
```

## Task 4: SAML SSO As OSS

**Files:**
- Modify: `sso/models.py`
- Modify: `sso/saml.py`
- Modify: `sso/urls.py`
- Modify: `sso/views.py`
- Modify: `sso/forms.py`
- Modify: `sso/admin.py`
- Modify: `sso/migrations/0001_initial.py`
- Modify: `templates/base/login.html`
- Modify: `templates/organizations/detail.html`
- Modify: `users/views.py`
- Modify: `users/tests.py`
- Modify: `Dockerfile`
- Modify: `requirements.txt`

- [ ] **Step 1: Add SSO tests**

Add tests to `users/tests.py` or `sso/tests.py`:

```python
def test_password_login_is_blocked_when_org_enforces_sso(self):
    config = SSOConfiguration.objects.create(
        organization=self.organization,
        is_enabled=True,
        enforce_sso=True,
        idp_entity_id="https://idp.example.test/metadata",
        idp_sso_url="https://idp.example.test/sso",
        idp_x509_cert="test-cert",
    )
    response = self.client.post(reverse("login"), {"email": self.user.email, "password": "password"})
    self.assertEqual(response.status_code, 200)
    self.assertContains(response, "requires SSO login")
```

```python
def test_sso_metadata_route_is_public_for_enabled_org(self):
    SSOConfiguration.objects.create(
        organization=self.organization,
        is_enabled=True,
        idp_entity_id="https://idp.example.test/metadata",
        idp_sso_url="https://idp.example.test/sso",
        idp_x509_cert="test-cert",
    )
    response = self.client.get(reverse("sso:metadata", kwargs={"org_slug": self.organization.slug}))
    self.assertIn(response.status_code, {200, 500})
```

Use existing model names from the current OSS `sso/` app. Avoid private source model names if they differ.

- [ ] **Step 2: Remove licensing assumptions**

Search:

```bash
grep -RInE "license|licensing|enterprise|pro|edition|plan" sso templates/base/login.html templates/organizations/detail.html users/views.py
```

Remove any SSO license gate, paid copy, or plan references. SAML SSO is an open-source org feature.

- [ ] **Step 3: Reconcile route consistency**

Ensure `sso/saml.py` does not emit SLS URLs unless `sso/urls.py` provides the matching route. Either add a working logout route or omit SLS from generated settings/metadata.

- [ ] **Step 4: Run SSO tests**

Run:

```bash
docker compose run --rm web python manage.py test users.tests sso
```

Expected: login enforcement and SSO route tests pass.

- [ ] **Step 5: Guard scan and commit**

Run:

```bash
python tools/oss_guard_scan.py sso templates/base/login.html templates/organizations/detail.html users/views.py users/tests.py Dockerfile requirements.txt
git add sso templates/base/login.html templates/organizations/detail.html users/views.py users/tests.py Dockerfile requirements.txt
git commit -m "feat: add OSS SAML SSO"
```

## Task 5: Slack Notifications As OSS

**Files:**
- Create: `notifications/__init__.py`
- Create: `notifications/apps.py`
- Create: `notifications/crypto.py`
- Create: `notifications/dispatch.py`
- Create: `notifications/models.py`
- Create: `notifications/tasks.py`
- Create: `notifications/urls_org.py`
- Create: `notifications/views.py`
- Create: `notifications/tests.py`
- Create: `notifications/migrations/0001_initial.py`
- Create: `notifications/migrations/__init__.py`
- Create: `templates/notifications/preferences.html`
- Create: `templates/notifications/slack.html`
- Modify: `open_cvpn/settings.py`
- Modify: `open_cvpn/urls.py`
- Modify: `open_cvpn/celery.py`
- Modify: `requirements.txt`
- Modify: `templates/components/mobile_nav.html`

- [ ] **Step 1: Copy only generic notification files**

Use private `customer_app/notifications` as reference. Do not copy:

- unsubscribe views/templates
- email templates
- support/SLA copy
- license/plan checks
- analytics hooks

Keep only organization notification preferences, Slack incoming webhook configuration, encrypted/protected webhook URL handling, dispatch, Celery task, org routes, and tests.

- [ ] **Step 2: Add model tests**

In `notifications/tests.py`, include:

```python
def test_slack_webhook_url_is_not_stored_plaintext(self):
    integration = NotificationIntegration.objects.create(
        organization=self.organization,
        kind=NotificationIntegration.Kind.SLACK,
        name="Ops",
    )
    integration.set_secret_url("https://hooks.slack.com/services/T000/B000/secret")
    integration.save()
    raw = NotificationIntegration.objects.filter(pk=integration.pk).values_list("secret_url", flat=True).get()
    self.assertNotIn("hooks.slack.com", raw)
    self.assertEqual(integration.get_secret_url(), "https://hooks.slack.com/services/T000/B000/secret")
```

```python
@mock.patch("notifications.dispatch.requests.post")
def test_dispatch_posts_slack_message(self, post):
    integration = self.enabled_slack_integration()
    dispatch_notification(self.organization, "node.registered", {"node": "node-1"})
    self.assertTrue(post.called)
```

- [ ] **Step 3: Wire app and routes**

Add `notifications` to `INSTALLED_APPS`, add org routes under existing organization URL patterns, and expose navigation links only for org owners/admins. Do not add public unsubscribe routes.

- [ ] **Step 4: Run tests**

Run:

```bash
docker compose run --rm web python manage.py test notifications webhooks.tests
```

Expected: notification tests and existing webhook tests pass.

- [ ] **Step 5: Guard scan and commit**

Run:

```bash
python tools/oss_guard_scan.py notifications templates/notifications open_cvpn/settings.py open_cvpn/urls.py open_cvpn/celery.py requirements.txt templates/components/mobile_nav.html
git add notifications templates/notifications open_cvpn/settings.py open_cvpn/urls.py open_cvpn/celery.py requirements.txt templates/components/mobile_nav.html
git commit -m "feat: add OSS Slack notifications"
```

## Task 6: Security Policy UX

**Files:**
- Modify: `security_groups/views.py`
- Modify: `security_groups/urls_org.py`
- Modify: `security_groups/tests.py`
- Create: `templates/security_groups/org_policy_list.html`
- Create: `templates/security_groups/org_policy_form.html`
- Create: `templates/security_groups/org_policy_delete.html`
- Modify: `templates/security_groups/detail.html`

- [ ] **Step 1: Add policy workflow tests**

In `security_groups/tests.py`, add tests for:

```python
def test_owner_can_create_source_to_destination_policy(self):
    self.client.force_login(self.owner)
    response = self.client.post(
        reverse("security_groups:org_policy_create", kwargs={"org_slug": self.organization.slug}),
        {
            "source_groups": [self.source_group.id],
            "destination_group": self.destination_group.id,
            "protocol": "tcp",
            "port": "443",
            "description": "Allow HTTPS",
        },
    )
    self.assertEqual(response.status_code, 302)
    self.assertTrue(FirewallRule.objects.filter(destination_group=self.destination_group, port="443").exists())
```

Adapt field names to `security_groups/models.py`.

- [ ] **Step 2: Port views and URLs**

Manually port source `security_groups/views.py` and `urls_org.py` policy list/create/edit/delete functions. Keep OSS permission helpers and org-scoped URL style.

- [ ] **Step 3: Port templates**

Copy only `org_policy_list.html`, `org_policy_form.html`, and `org_policy_delete.html` after removing any business copy or upgrade/license messaging.

- [ ] **Step 4: Run tests**

Run:

```bash
docker compose run --rm web python manage.py test security_groups.tests
```

Expected: security group tests pass.

- [ ] **Step 5: Guard scan and commit**

Run:

```bash
python tools/oss_guard_scan.py security_groups templates/security_groups
git add security_groups/views.py security_groups/urls_org.py security_groups/tests.py templates/security_groups/org_policy_list.html templates/security_groups/org_policy_form.html templates/security_groups/org_policy_delete.html templates/security_groups/detail.html
git commit -m "feat: add security policy workflow"
```

## Task 7: Public/Auth Shell And Static Assets

**Files:**
- Create: `templates/base/auth_base.html`
- Modify: `templates/base/login.html`
- Modify: `templates/base/register.html`
- Modify: `templates/base/password_reset.html`
- Modify: `templates/base/password_reset_done.html`
- Modify: `templates/base/password_reset_confirm.html`
- Modify: `templates/base/password_reset_complete.html`
- Modify: `templates/400.html`
- Modify: `templates/403.html`
- Modify: `templates/404.html`
- Modify: `templates/500.html`
- Modify: `templates/502.html`
- Create: `static/css/fonts.css`
- Modify: `open_cvpn/context_processors.py`
- Modify: `open_cvpn/settings.py`
- Modify: `open_cvpn/settings-prod.py`
- Modify: `users/tests.py`

- [ ] **Step 1: Add auth page tests**

Add tests in `users/tests.py`:

```python
def test_login_page_uses_public_auth_shell(self):
    response = self.client.get(reverse("login"))
    self.assertEqual(response.status_code, 200)
    self.assertContains(response, "Create one")
```

```python
def test_register_success_redirect_does_not_500(self):
    response = self.client.post(reverse("register"), {
        "email": "new-user@example.test",
        "password1": "StrongPassword123!",
        "password2": "StrongPassword123!",
    })
    self.assertNotEqual(response.status_code, 500)
```

- [ ] **Step 2: Port generic templates**

Port the private app public/auth shell and error templates only after replacing private support email/domain copy with generic OSS copy or `DEFAULT_FROM_EMAIL`.

- [ ] **Step 3: Add static asset versioning**

Add `_read_project_version()` and `STATIC_ASSET_VERSION` from source `open_cvpn/settings.py`. Ensure template usage does not break when `pyproject.toml` is absent.

- [ ] **Step 4: Run tests**

Run:

```bash
docker compose run --rm web python manage.py test users.tests
```

Expected: user/auth tests pass.

- [ ] **Step 5: Guard scan and commit**

Run:

```bash
python tools/oss_guard_scan.py templates/base templates/400.html templates/403.html templates/404.html templates/500.html templates/502.html static/css/fonts.css open_cvpn/context_processors.py open_cvpn/settings.py open_cvpn/settings-prod.py users/tests.py
git add templates/base templates/400.html templates/403.html templates/404.html templates/500.html templates/502.html static/css/fonts.css open_cvpn/context_processors.py open_cvpn/settings.py open_cvpn/settings-prod.py users/tests.py
git commit -m "fix: improve public auth pages"
```

## Task 8: Local Verification And DigitalOcean Smoke

**Files:**
- Modify: `README.md`
- Modify: `.env.example`
- Modify: `.env.prod.example`
- Modify: `docker-compose.yml`
- Modify: `Dockerfile`

- [ ] **Step 1: Run full local tests**

Run:

```bash
docker compose run --rm web python manage.py test
```

Expected: all tests pass.

- [ ] **Step 2: Run migrations on a clean compose database**

Run:

```bash
docker compose down -v
docker compose up --build -d db redis
docker compose run --rm web python manage.py migrate
```

Expected: all migrations apply.

- [ ] **Step 3: Run full compose stack**

Run:

```bash
docker compose up --build -d
docker compose ps
curl -fsS http://localhost:8000/health/
```

Expected: web, db, redis, celery, and celery-beat are running; health returns `{"status":"ok"}`.

- [ ] **Step 4: Run guard scan over changed files**

Run:

```bash
python tools/oss_guard_scan.py
```

Expected: `OSS guard scan passed.`

- [ ] **Step 5: Provision temporary DigitalOcean droplet**

Run read-only discovery first:

```bash
doctl compute size list
doctl compute image list-distribution --public | grep -i ubuntu | head
doctl compute ssh-key list
```

Create the droplet with the smallest Docker-capable size available in the chosen region:

```bash
SSH_KEY_ID="$(doctl compute ssh-key list --format ID --no-header | head -n 1)"
SMOKE_NAME="catalyst-oss-smoke-$(date +%Y%m%d%H%M)"
doctl compute droplet create "${SMOKE_NAME}" \
  --region nyc3 \
  --image ubuntu-24-04-x64 \
  --size s-1vcpu-1gb \
  --tag-names catalyst-oss-smoke,delete-after-2026-05-22 \
  --ssh-keys "${SSH_KEY_ID}" \
  --wait
doctl compute droplet get "${SMOKE_NAME}" --format ID,Name,PublicIPv4,Status
```

- [ ] **Step 6: Deploy to the droplet**

SSH to the droplet and run:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-plugin git
git clone https://github.com/dot-billy/catalyst-networks-open-source.git app
cd app
git checkout CNCUST-b1e35b60/migrate-oss-improvements
cp .env.example .env
python3 - <<'PY' >> .env
from django.core.management.utils import get_random_secret_key
import secrets
print(f"DJANGO_SECRET_KEY={get_random_secret_key()}")
print(f"JWT_SECRET_KEY={secrets.token_urlsafe(48)}")
print(f"REGISTRATION_MASTER_TOKEN={secrets.token_urlsafe(32)}")
print("DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1,0.0.0.0")
PY
sudo docker compose up --build -d
sudo docker compose exec -T web python manage.py migrate
```

- [ ] **Step 7: Smoke test droplet**

From local machine:

```bash
SMOKE_IP="$(doctl compute droplet list --tag-name catalyst-oss-smoke --format PublicIPv4 --no-header | tail -n 1)"
curl -fsS "http://${SMOKE_IP}:8000/health/"
curl -fsSI "http://${SMOKE_IP}:8000/login/"
curl -fsSI "http://${SMOKE_IP}:6379/" || true
```

Expected:

- Health returns `{"status":"ok"}`.
- Login returns HTTP 200.
- Redis is not reachable publicly or does not return a useful Redis response.

- [ ] **Step 8: Tear down the droplet**

Run:

```bash
SMOKE_ID="$(doctl compute droplet list --tag-name catalyst-oss-smoke --format ID --no-header | tail -n 1)"
doctl compute droplet delete "${SMOKE_ID}" --force
doctl compute droplet get "${SMOKE_ID}"
```

Expected: delete succeeds; the follow-up get returns not found.

- [ ] **Step 9: Final commit for docs/deployment updates**

Run:

```bash
git add README.md .env.example .env.prod.example docker-compose.yml Dockerfile
git commit -m "docs: document OSS deployment smoke path"
```

## Completion Checklist

- [ ] `git status --short` contains only intentional untracked/local runtime files or is clean.
- [ ] `python tools/oss_guard_scan.py` passes.
- [ ] `docker compose run --rm web python manage.py test` passes.
- [ ] `docker compose run --rm web python manage.py migrate` passes on clean DB.
- [ ] DigitalOcean droplet smoke test passes.
- [ ] DigitalOcean droplet is deleted and verified gone.
- [ ] Plane issue has a final comment summarizing local tests, DO smoke result, and teardown confirmation.
