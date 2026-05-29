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
