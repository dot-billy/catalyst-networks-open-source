# Resend Email Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Configure both customer app repositories to send transactional email through Resend via Django's existing mail APIs.

**Architecture:** Add a small `open_cvpn.email_settings` helper that selects the configured email provider from environment variables, then wire `open_cvpn/settings.py` to use it. Existing invitation, password reset, support, and notification email producers continue using Django `send_mail` and `EmailMessage`.

**Tech Stack:** Django 5.2, django-anymail Resend backend, Django `SimpleTestCase`/`TestCase`, Docker Compose test runner.

---

## Repositories

- Regular customer app: `/home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support`
- Open-source customer app: `/home/uwadmin/Development/catalyst-networks-open-source`

## File Structure

Regular customer app:

- Create: `open_cvpn/email_settings.py` for provider selection.
- Create: `open_cvpn/tests_email_settings.py` for pure helper and settings import tests.
- Create: `organizations/tests_invitation_email.py` for the Django mail API regression test.
- Modify: `open_cvpn/settings.py` to use the helper.
- Modify: `requirements.in` and generated `requirements.txt` for `django-anymail[resend]`.
- Modify: `.env.example`, `.env.prod.example`, and `README.md` for Resend configuration.

Open-source customer app:

- Create: `open_cvpn/email_settings.py` for provider selection.
- Create: `open_cvpn/tests_email_settings.py` for pure helper and settings import tests.
- Create: `organizations/tests_invitation_email.py` for the Django mail API regression test.
- Modify: `open_cvpn/settings.py` to use the helper.
- Modify: `requirements.txt` for `django-anymail[resend]`.
- Modify: `.env.example`, `.env.prod.example`, and `README.md` for Resend configuration.

---

### Task 1: Add Email Provider Selection Helper

**Files:**
- Create in both repos: `open_cvpn/email_settings.py`
- Create in both repos: `open_cvpn/tests_email_settings.py`

- [ ] **Step 1: Write the failing helper tests in both repos**

Create `open_cvpn/tests_email_settings.py` with this content in both repositories:

```python
from django.test import SimpleTestCase

from open_cvpn.email_settings import (
    MAILGUN_EMAIL_BACKEND,
    RESEND_EMAIL_BACKEND,
    SMTP_EMAIL_BACKEND,
    build_email_settings,
)


class EmailSettingsHelperTests(SimpleTestCase):
    def test_resend_backend_selected_when_api_key_present_without_explicit_backend(self):
        config = build_email_settings(
            {
                "RESEND_API_KEY": "re_test_key",
                "DEFAULT_FROM_EMAIL": "Catalyst <noreply@example.test>",
            },
            default_from_email="fallback@example.test",
        )

        self.assertEqual(config["EMAIL_BACKEND"], RESEND_EMAIL_BACKEND)
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "Catalyst <noreply@example.test>")
        self.assertEqual(config["RESEND_API_KEY"], "re_test_key")
        self.assertEqual(config["ANYMAIL"], {"RESEND_API_KEY": "re_test_key"})

    def test_explicit_email_backend_wins_over_resend(self):
        config = build_email_settings(
            {
                "EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend",
                "RESEND_API_KEY": "re_test_key",
            },
            default_from_email="fallback@example.test",
        )

        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.locmem.EmailBackend")
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "fallback@example.test")
        self.assertEqual(config["RESEND_API_KEY"], "re_test_key")
        self.assertNotIn("ANYMAIL", config)

    def test_mailgun_backend_remains_available_when_resend_is_not_configured(self):
        config = build_email_settings(
            {
                "MAILGUN_API_KEY": "mailgun-key",
                "MAILGUN_DOMAIN": "mg.example.test",
            },
            default_from_email="fallback@example.test",
        )

        self.assertEqual(config["EMAIL_BACKEND"], MAILGUN_EMAIL_BACKEND)
        self.assertEqual(config["MAILGUN_ACCESS_KEY"], "mailgun-key")
        self.assertEqual(config["MAILGUN_SERVER_NAME"], "mg.example.test")

    def test_smtp_backend_is_default_when_no_provider_is_configured(self):
        config = build_email_settings({}, default_from_email="fallback@example.test")

        self.assertEqual(config["EMAIL_BACKEND"], SMTP_EMAIL_BACKEND)
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "fallback@example.test")
        self.assertEqual(config["RESEND_API_KEY"], "")
        self.assertEqual(config["MAILGUN_API_KEY"], "")
        self.assertEqual(config["MAILGUN_DOMAIN"], "")
```

- [ ] **Step 2: Run the helper tests and verify they fail**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
DJANGO_SECRET_KEY=test-secret POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
DJANGO_SECRET_KEY=test-secret REGISTRATION_MASTER_TOKEN=test-token POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Expected: both commands fail with `ModuleNotFoundError: No module named 'open_cvpn.email_settings'`.

- [ ] **Step 3: Create the email settings helper in both repos**

Create `open_cvpn/email_settings.py` with this content in both repositories:

```python
import os


SMTP_EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
RESEND_EMAIL_BACKEND = "anymail.backends.resend.EmailBackend"
MAILGUN_EMAIL_BACKEND = "django_mailgun.MailgunBackend"


def _env_value(env, name):
    value = env.get(name)
    if value is None:
        return ""
    return str(value).strip()


def build_email_settings(env=None, *, default_from_email):
    """Build Django email settings from environment variables."""
    if env is None:
        env = os.environ

    explicit_backend = _env_value(env, "EMAIL_BACKEND")
    resend_api_key = _env_value(env, "RESEND_API_KEY")
    mailgun_api_key = _env_value(env, "MAILGUN_API_KEY")
    mailgun_domain = _env_value(env, "MAILGUN_DOMAIN")

    config = {
        "EMAIL_BACKEND": SMTP_EMAIL_BACKEND,
        "DEFAULT_FROM_EMAIL": _env_value(env, "DEFAULT_FROM_EMAIL") or default_from_email,
        "RESEND_API_KEY": resend_api_key,
        "MAILGUN_API_KEY": mailgun_api_key,
        "MAILGUN_DOMAIN": mailgun_domain,
    }

    if explicit_backend:
        config["EMAIL_BACKEND"] = explicit_backend
        return config

    if resend_api_key:
        config["EMAIL_BACKEND"] = RESEND_EMAIL_BACKEND
        config["ANYMAIL"] = {"RESEND_API_KEY": resend_api_key}
        return config

    if mailgun_api_key and mailgun_domain:
        config["EMAIL_BACKEND"] = MAILGUN_EMAIL_BACKEND
        config["MAILGUN_ACCESS_KEY"] = mailgun_api_key
        config["MAILGUN_SERVER_NAME"] = mailgun_domain
        return config

    return config
```

- [ ] **Step 4: Run the helper tests and verify they pass**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
DJANGO_SECRET_KEY=test-secret POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
DJANGO_SECRET_KEY=test-secret REGISTRATION_MASTER_TOKEN=test-token POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Expected: both commands pass all 4 helper tests.

- [ ] **Step 5: Commit the helper in each repo**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
git add open_cvpn/email_settings.py open_cvpn/tests_email_settings.py
git commit -m "feat: add email provider settings helper"
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
git add open_cvpn/email_settings.py open_cvpn/tests_email_settings.py
git commit -m "feat: add email provider settings helper"
```

---

### Task 2: Wire Django Settings To The Helper

**Files:**
- Modify in both repos: `open_cvpn/tests_email_settings.py`
- Modify in both repos: `open_cvpn/settings.py`

- [ ] **Step 1: Add failing project settings tests in both repos**

Append this content to `open_cvpn/tests_email_settings.py` in both repositories:

```python
import json
import os
import subprocess
import sys
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def load_project_settings(extra_env):
    env = os.environ.copy()
    for key in [
        "EMAIL_BACKEND",
        "RESEND_API_KEY",
        "MAILGUN_API_KEY",
        "MAILGUN_DOMAIN",
        "DEFAULT_FROM_EMAIL",
        "ANYMAIL_RESEND_API_KEY",
    ]:
        env.pop(key, None)
    env.update(
        {
            "DJANGO_SECRET_KEY": "test-secret",
            "REGISTRATION_MASTER_TOKEN": "test-token",
            "POSTGRES_DB": "open_cvpn",
            "POSTGRES_USER": "postgres",
            "POSTGRES_PASSWORD": "postgres",
            "POSTGRES_HOST": "db",
        }
    )
    env.update(extra_env)

    script = """
import json
from open_cvpn import settings

print(json.dumps({
    "EMAIL_BACKEND": settings.EMAIL_BACKEND,
    "DEFAULT_FROM_EMAIL": settings.DEFAULT_FROM_EMAIL,
    "RESEND_API_KEY": getattr(settings, "RESEND_API_KEY", ""),
    "ANYMAIL": getattr(settings, "ANYMAIL", {}),
    "MAILGUN_ACCESS_KEY": getattr(settings, "MAILGUN_ACCESS_KEY", ""),
    "MAILGUN_SERVER_NAME": getattr(settings, "MAILGUN_SERVER_NAME", ""),
}))
"""

    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BASE_DIR,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


class ProjectEmailSettingsTests(SimpleTestCase):
    def test_project_settings_select_resend_when_api_key_is_configured(self):
        config = load_project_settings(
            {
                "RESEND_API_KEY": "re_project_test",
                "DEFAULT_FROM_EMAIL": "noreply@resend.example.test",
            }
        )

        self.assertEqual(config["EMAIL_BACKEND"], RESEND_EMAIL_BACKEND)
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "noreply@resend.example.test")
        self.assertEqual(config["RESEND_API_KEY"], "re_project_test")
        self.assertEqual(config["ANYMAIL"], {"RESEND_API_KEY": "re_project_test"})

    def test_project_settings_keep_explicit_backend_override(self):
        config = load_project_settings(
            {
                "EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend",
                "RESEND_API_KEY": "re_project_test",
            }
        )

        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.locmem.EmailBackend")
        self.assertEqual(config["ANYMAIL"], {})

    def test_project_settings_keep_mailgun_fallback_without_resend(self):
        config = load_project_settings(
            {
                "MAILGUN_API_KEY": "mailgun-key",
                "MAILGUN_DOMAIN": "mg.example.test",
            }
        )

        self.assertEqual(config["EMAIL_BACKEND"], MAILGUN_EMAIL_BACKEND)
        self.assertEqual(config["MAILGUN_ACCESS_KEY"], "mailgun-key")
        self.assertEqual(config["MAILGUN_SERVER_NAME"], "mg.example.test")
```

- [ ] **Step 2: Run settings tests and verify the Resend/Mailgun tests fail**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
DJANGO_SECRET_KEY=test-secret POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
DJANGO_SECRET_KEY=test-secret REGISTRATION_MASTER_TOKEN=test-token POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Expected: both commands fail because `open_cvpn/settings.py` still contains inline email provider selection and does not expose `ANYMAIL` for Resend.

- [ ] **Step 3: Import the helper in both settings modules**

In both `open_cvpn/settings.py` files, add this import immediately after the `django.core.files.storage` import:

```python
from open_cvpn.email_settings import build_email_settings
```

- [ ] **Step 4: Replace the regular app email settings block**

In `/home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support/open_cvpn/settings.py`, replace the existing `# Email settings` and `# Mailgun settings` block with:

```python
# Email settings
_email_settings = build_email_settings(default_from_email='noreply@catalystnetworks.io')
EMAIL_BACKEND = _email_settings['EMAIL_BACKEND']
DEFAULT_FROM_EMAIL = _email_settings['DEFAULT_FROM_EMAIL']
RESEND_API_KEY = _email_settings['RESEND_API_KEY']
ANYMAIL = _email_settings.get('ANYMAIL', {})
MAILGUN_API_KEY = _email_settings['MAILGUN_API_KEY']
MAILGUN_DOMAIN = _email_settings['MAILGUN_DOMAIN']
MAILGUN_ACCESS_KEY = _email_settings.get('MAILGUN_ACCESS_KEY')
MAILGUN_SERVER_NAME = _email_settings.get('MAILGUN_SERVER_NAME')
```

- [ ] **Step 5: Replace the open-source app email settings block**

In `/home/uwadmin/Development/catalyst-networks-open-source/open_cvpn/settings.py`, replace the existing `# Email settings` and `# Mailgun settings` block with:

```python
# Email settings
_email_settings = build_email_settings(default_from_email='noreply@example.com')
EMAIL_BACKEND = _email_settings['EMAIL_BACKEND']
DEFAULT_FROM_EMAIL = _email_settings['DEFAULT_FROM_EMAIL']
RESEND_API_KEY = _email_settings['RESEND_API_KEY']
ANYMAIL = _email_settings.get('ANYMAIL', {})
MAILGUN_API_KEY = _email_settings['MAILGUN_API_KEY']
MAILGUN_DOMAIN = _email_settings['MAILGUN_DOMAIN']
MAILGUN_ACCESS_KEY = _email_settings.get('MAILGUN_ACCESS_KEY')
MAILGUN_SERVER_NAME = _email_settings.get('MAILGUN_SERVER_NAME')
```

- [ ] **Step 6: Run settings tests and verify they pass**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
DJANGO_SECRET_KEY=test-secret POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
DJANGO_SECRET_KEY=test-secret REGISTRATION_MASTER_TOKEN=test-token POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings
```

Expected: both commands pass all 7 email settings tests.

- [ ] **Step 7: Commit settings wiring in each repo**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
git add open_cvpn/settings.py open_cvpn/tests_email_settings.py
git commit -m "feat: configure Resend email backend selection"
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
git add open_cvpn/settings.py open_cvpn/tests_email_settings.py
git commit -m "feat: configure Resend email backend selection"
```

---

### Task 3: Add Dependencies And Configuration Documentation

**Files:**
- Modify regular app: `requirements.in`, `requirements.txt`, `.env.example`, `.env.prod.example`, `README.md`
- Modify open-source app: `requirements.txt`, `.env.example`, `.env.prod.example`, `README.md`

- [ ] **Step 1: Add django-anymail to the regular app input requirements**

In `/home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support/requirements.in`, add this line immediately after `django-mailgun-mime==0.1.1`:

```text
django-anymail[resend]>=15.0
```

- [ ] **Step 2: Regenerate the regular app lock-style requirements file**

Run:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
python -m piptools compile --output-file requirements.txt requirements.in
```

Expected: `requirements.txt` contains `django-anymail` and its Resend webhook dependency entries resolved by pip-tools.

- [ ] **Step 3: Add django-anymail to the open-source requirements file**

In `/home/uwadmin/Development/catalyst-networks-open-source/requirements.txt`, add this line immediately after `django-mailgun-mime==0.1.1`:

```text
django-anymail[resend]>=15.0
```

- [ ] **Step 4: Update regular app `.env.example` email settings**

Replace the regular app `.env.example` email block with:

```dotenv
# Email Settings
DEFAULT_FROM_EMAIL=noreply@catasyn.io
# Optional Resend API email delivery. Leave EMAIL_BACKEND unset to enable this.
# RESEND_API_KEY=
# Optional explicit backend override for local console, SMTP, or tests.
# EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend

# Optional Mailgun Settings
# Used only when RESEND_API_KEY and EMAIL_BACKEND are unset.
# MAILGUN_API_KEY=
# MAILGUN_DOMAIN=
```

- [ ] **Step 5: Update regular app `.env.prod.example` email settings**

Replace the regular app `.env.prod.example` email block with:

```dotenv
# Email Settings (optional)
# Verify this sender domain in Resend before enabling RESEND_API_KEY.
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
# RESEND_API_KEY=
# EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend

# Optional Mailgun Settings
# Used only when RESEND_API_KEY and EMAIL_BACKEND are unset.
# MAILGUN_API_KEY=
# MAILGUN_DOMAIN=
```

- [ ] **Step 6: Add regular app README email provider section**

In the regular app `README.md`, insert this section between Setup and Development:

```markdown
## Email Providers

Transactional email uses Django's configured email backend. To send through Resend:

1. Verify the sender domain in Resend.
2. Create a Resend API key with sending access.
3. Set `DEFAULT_FROM_EMAIL` to an address on the verified domain.
4. Set `RESEND_API_KEY`.
5. Leave `EMAIL_BACKEND` unset unless intentionally using SMTP, console, locmem, or another explicit backend.

If `RESEND_API_KEY` is not set, the app keeps the existing Mailgun fallback when `MAILGUN_API_KEY` and `MAILGUN_DOMAIN` are both present. Otherwise it uses Django SMTP settings.
```

- [ ] **Step 7: Update open-source `.env.example` email settings**

Replace the open-source `.env.example` email block with:

```dotenv
# Email Settings
DEFAULT_FROM_EMAIL=noreply@example.com
# Optional Resend API email delivery. Leave EMAIL_BACKEND unset to enable this.
# RESEND_API_KEY=
# Optional explicit backend override for local console, SMTP, or tests.
# EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend

# Optional Mailgun Settings
# Used only when RESEND_API_KEY and EMAIL_BACKEND are unset.
# MAILGUN_API_KEY=
# MAILGUN_DOMAIN=
```

- [ ] **Step 8: Update open-source `.env.prod.example` email settings**

Replace the open-source `.env.prod.example` email block with:

```dotenv
# Email Settings (optional)
# Verify this sender domain in Resend before enabling RESEND_API_KEY.
DEFAULT_FROM_EMAIL=noreply@yourdomain.com
# RESEND_API_KEY=
# EMAIL_BACKEND=django.core.mail.backends.smtp.EmailBackend

# Optional Mailgun Settings
# Used only when RESEND_API_KEY and EMAIL_BACKEND are unset.
# MAILGUN_API_KEY=
# MAILGUN_DOMAIN=
```

- [ ] **Step 9: Update open-source README configuration table**

In the open-source `README.md` configuration table, add these rows near the existing `DEFAULT_FROM_EMAIL` row:

```markdown
| `EMAIL_BACKEND` | Optional explicit Django email backend override; leave unset to allow Resend or Mailgun auto-selection | Empty |
| `RESEND_API_KEY` | Optional Resend API key with sending access for transactional email | Empty |
```

Replace the existing `DEFAULT_FROM_EMAIL` row with:

```markdown
| `DEFAULT_FROM_EMAIL` | Sender email address; use a Resend-verified domain when `RESEND_API_KEY` is set | `noreply@example.com` |
```

After the configuration table, add:

```markdown
For Resend delivery, verify the sender domain in Resend, set `DEFAULT_FROM_EMAIL`
to that domain, set `RESEND_API_KEY`, and leave `EMAIL_BACKEND` unset. If
`RESEND_API_KEY` is not set, Mailgun remains available when `MAILGUN_API_KEY`
and `MAILGUN_DOMAIN` are both present. Otherwise Django uses SMTP settings.
```

- [ ] **Step 10: Run dependency and docs checks**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
rg -n "django-anymail|RESEND_API_KEY|EMAIL_BACKEND|DEFAULT_FROM_EMAIL" requirements.in requirements.txt .env.example .env.prod.example README.md
git diff --check
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
rg -n "django-anymail|RESEND_API_KEY|EMAIL_BACKEND|DEFAULT_FROM_EMAIL" requirements.txt .env.example .env.prod.example README.md
git diff --check
```

Expected: `rg` shows the new Resend dependency and configuration docs in each repo, and `git diff --check` exits with no whitespace errors.

- [ ] **Step 11: Commit dependencies and docs in each repo**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
git add requirements.in requirements.txt .env.example .env.prod.example README.md
git commit -m "docs: document Resend email configuration"
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
git add requirements.txt .env.example .env.prod.example README.md
git commit -m "docs: document Resend email configuration"
```

---

### Task 4: Add Existing Invitation Email Regression Test

**Files:**
- Create in both repos: `organizations/tests_invitation_email.py`

- [ ] **Step 1: Add invitation email regression test in both repos**

Create `organizations/tests_invitation_email.py` with this content in both repositories:

```python
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings

from organizations.emails import send_invitation_email
from organizations.models import Invitation, Membership, Organization


User = get_user_model()


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="noreply@example.test",
    BASE_URL="https://app.example.test",
)
class InvitationEmailTests(TestCase):
    def setUp(self):
        self.inviter = User.objects.create_user(
            email="owner@example.test",
            password="testpass",
        )
        self.organization = Organization.objects.create(
            name="Example Org",
            created_by=self.inviter,
        )
        Membership.objects.create(
            user=self.inviter,
            organization=self.organization,
            role="owner",
        )

    def test_invitation_email_uses_configured_django_mail_backend(self):
        invitation = Invitation.objects.create(
            organization=self.organization,
            email="invitee@example.test",
            inviter=self.inviter,
            role="member",
        )

        send_invitation_email(invitation)

        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.from_email, "noreply@example.test")
        self.assertEqual(message.to, ["invitee@example.test"])
        self.assertIn("Example Org", message.subject)
        self.assertIn(
            f"https://app.example.test/organizations/invitations/accept/{invitation.token}/",
            message.body,
        )
```

- [ ] **Step 2: Run the new invitation email regression test**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
DJANGO_SECRET_KEY=test-secret POSTGRES_HOST=db python manage.py test organizations.tests_invitation_email
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
DJANGO_SECRET_KEY=test-secret REGISTRATION_MASTER_TOKEN=test-token POSTGRES_HOST=db python manage.py test organizations.tests_invitation_email
```

Expected: both commands pass and confirm an existing mail path still uses Django's configured backend.

- [ ] **Step 3: Commit invitation email regression tests in each repo**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
git add organizations/tests_invitation_email.py
git commit -m "test: cover invitation email backend usage"
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
git add organizations/tests_invitation_email.py
git commit -m "test: cover invitation email backend usage"
```

---

### Task 5: Final Verification

**Files:**
- No new files.

- [ ] **Step 1: Run focused tests in the regular customer app**

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
DJANGO_SECRET_KEY=test-secret POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings organizations.tests_invitation_email
```

Expected: all focused Resend/email tests pass.

- [ ] **Step 2: Run focused tests in the open-source customer app**

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
DJANGO_SECRET_KEY=test-secret REGISTRATION_MASTER_TOKEN=test-token POSTGRES_HOST=db python manage.py test open_cvpn.tests_email_settings organizations.tests_invitation_email
```

Expected: all focused Resend/email tests pass.

- [ ] **Step 3: Run repository whitespace checks**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
git diff --check
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
git diff --check
```

Expected: both commands exit with no output.

- [ ] **Step 4: Confirm git status**

Regular customer app:

```bash
cd /home/uwadmin/Development/.worktrees/customer_app/CNCUST-bb9d2cc7-resend-email-support
git status --short --branch
```

Open-source customer app:

```bash
cd /home/uwadmin/Development/catalyst-networks-open-source
git status --short --branch
```

Expected: both repositories are on `CNCUST-bb9d2cc7/resend-email-support` with clean working trees after the task commits.
