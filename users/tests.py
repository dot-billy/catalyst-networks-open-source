from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse


class PublicAuthPageTests(TestCase):
    def assert_auth_shell_with_versioned_assets(self, response):
        self.assertTemplateUsed(response, "base/auth_base.html")
        self.assertContains(
            response,
            f"css/fonts.css?v={settings.STATIC_ASSET_VERSION}",
        )

    def test_login_page_renders_registration_sso_and_versioned_auth_shell(self):
        response = self.client.get(reverse("login"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create one")
        self.assertContains(response, "Organization slug")
        self.assertContains(response, "SSO Login")
        self.assert_auth_shell_with_versioned_assets(response)

    def test_password_reset_page_renders_versioned_auth_shell(self):
        response = self.client.get(reverse("password_reset"))

        self.assertEqual(response.status_code, 200)
        self.assert_auth_shell_with_versioned_assets(response)

    @override_settings(AUTHENTICATION_BACKENDS=["axes.backends.AxesBackend"])
    def test_registration_post_with_valid_data_does_not_return_500(self):
        response = self.client.post(
            reverse("register"),
            {
                "email": "new-user@example.test",
                "password1": "StrongPassword123!",
                "password2": "StrongPassword123!",
            },
        )

        self.assertNotEqual(response.status_code, 500)
