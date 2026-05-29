import json
import os
import subprocess
import sys
from pathlib import Path

from django.core.mail import get_connection
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
                "RESEND_API_KEY": "your-resend-api-key",
                "DEFAULT_FROM_EMAIL": "Catalyst <noreply@example.test>",
            },
            default_from_email="fallback@example.test",
        )

        self.assertEqual(config["EMAIL_BACKEND"], RESEND_EMAIL_BACKEND)
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "Catalyst <noreply@example.test>")
        self.assertEqual(config["RESEND_API_KEY"], "your-resend-api-key")
        self.assertEqual(config["ANYMAIL"], {"RESEND_API_KEY": "your-resend-api-key"})

    def test_explicit_email_backend_wins_over_resend(self):
        config = build_email_settings(
            {
                "EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend",
                "RESEND_API_KEY": "your-resend-api-key",
            },
            default_from_email="fallback@example.test",
        )

        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.locmem.EmailBackend")
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "fallback@example.test")
        self.assertEqual(config["RESEND_API_KEY"], "your-resend-api-key")
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

BASE_DIR = Path(__file__).resolve().parent.parent


def load_project_settings(extra_env):
    env = os.environ.copy()
    env.update(
        {
            "EMAIL_BACKEND": "",
            "RESEND_API_KEY": "",
            "MAILGUN_API_KEY": "",
            "MAILGUN_DOMAIN": "",
            "DEFAULT_FROM_EMAIL": "",
            "ANYMAIL_RESEND_API_KEY": "",
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
    "INSTALLED_APPS": list(settings.INSTALLED_APPS),
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
    def test_project_settings_register_anymail_app(self):
        config = load_project_settings({})

        self.assertIn("anymail", config["INSTALLED_APPS"])

    def test_resend_backend_connection_is_importable(self):
        connection = get_connection(
            backend=RESEND_EMAIL_BACKEND,
            api_key="re_project_test",
        )

        self.assertEqual(connection.__class__.__module__, "anymail.backends.resend")

    def test_project_settings_select_resend_when_api_key_is_configured(self):
        config = load_project_settings(
            {
                "RESEND_API_KEY": "your-resend-api-key",
                "DEFAULT_FROM_EMAIL": "noreply@resend.example.test",
            }
        )

        self.assertEqual(config["EMAIL_BACKEND"], RESEND_EMAIL_BACKEND)
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "noreply@resend.example.test")
        self.assertEqual(config["RESEND_API_KEY"], "your-resend-api-key")
        self.assertEqual(config["ANYMAIL"], {"RESEND_API_KEY": "your-resend-api-key"})

    def test_project_settings_keep_explicit_backend_override(self):
        config = load_project_settings(
            {
                "EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend",
                "RESEND_API_KEY": "your-resend-api-key",
            }
        )

        self.assertEqual(config["EMAIL_BACKEND"], "django.core.mail.backends.locmem.EmailBackend")
        self.assertEqual(config["DEFAULT_FROM_EMAIL"], "noreply@example.com")
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
