"""Tests for opt-in TOTP enforcement and the Django admin IP allowlist."""

from io import StringIO

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase, override_settings


User = get_user_model()


class OtpWiringTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            email='staff@example.com',
            password='testpass',
            is_staff=True,
        )

    def test_django_otp_apps_installed(self):
        self.assertIn('django_otp', settings.INSTALLED_APPS)
        self.assertIn('django_otp.plugins.otp_totp', settings.INSTALLED_APPS)

    def test_otp_middleware_installed_after_authentication(self):
        auth_index = settings.MIDDLEWARE.index(
            'django.contrib.auth.middleware.AuthenticationMiddleware'
        )
        otp_index = settings.MIDDLEWARE.index('django_otp.middleware.OTPMiddleware')
        self.assertEqual(otp_index, auth_index + 1)

    def test_admin_security_defaults_are_disabled(self):
        self.assertFalse(settings.ADMIN_REQUIRE_OTP)
        self.assertEqual(settings.ADMIN_IP_ALLOWLIST, [])

    def test_grace_mode_admin_reachable_without_device(self):
        self.client.force_login(self.staff)
        self.assertEqual(self.client.get('/admin/').status_code, 200)

    def test_totp_device_admin_registered_for_enrollment(self):
        from django.contrib import admin
        from django_otp.plugins.otp_totp.models import TOTPDevice

        self.assertIn(TOTPDevice, admin.site._registry)


class OtpEnforcementTests(TestCase):
    def setUp(self):
        from django.contrib import admin

        self._original_admin_class = admin.site.__class__
        self.addCleanup(self._restore_admin_class)
        self.staff = User.objects.create_user(
            email='staff2fa@example.com',
            password='testpass',
            is_staff=True,
        )

    def _restore_admin_class(self):
        from django.contrib import admin

        admin.site.__class__ = self._original_admin_class

    def _enforce(self):
        from open_cvpn.admin_config import configure_admin_site

        with self.settings(ADMIN_REQUIRE_OTP=True):
            configure_admin_site()

    def test_flag_off_leaves_admin_site_class_unchanged(self):
        from django.contrib import admin
        from django_otp.admin import OTPAdminSite
        from open_cvpn.admin_config import configure_admin_site

        with self.settings(ADMIN_REQUIRE_OTP=False):
            configure_admin_site()
        self.assertNotIsInstance(admin.site, OTPAdminSite)

    def test_unverified_staff_is_redirected_to_admin_login(self):
        self._enforce()
        self.client.force_login(self.staff)
        response = self.client.get('/admin/')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/admin/login/', response.url)

    def test_verified_staff_reaches_admin(self):
        from django_otp.plugins.otp_totp.models import TOTPDevice

        self._enforce()
        device = TOTPDevice.objects.create(
            user=self.staff,
            name='default',
            confirmed=True,
        )
        self.client.force_login(self.staff)
        session = self.client.session
        session['otp_device_id'] = device.persistent_id
        session.save()
        self.assertEqual(self.client.get('/admin/').status_code, 200)

    def test_full_login_with_valid_totp_token(self):
        from django_otp.oath import totp
        from django_otp.plugins.otp_totp.models import TOTPDevice

        self._enforce()
        device = TOTPDevice.objects.create(
            user=self.staff,
            name='default',
            confirmed=True,
        )
        token = totp(
            device.bin_key,
            step=device.step,
            t0=device.t0,
            digits=device.digits,
        )
        response = self.client.post(
            '/admin/login/',
            {
                'username': 'staff2fa@example.com',
                'password': 'testpass',
                'otp_token': str(token).zfill(device.digits),
                'next': '/admin/',
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, '/admin/')


class ProvisionTotpCommandTests(TestCase):
    def setUp(self):
        self.staff = User.objects.create_user(
            email='enrollme@example.com',
            password='testpass',
            is_staff=True,
        )

    def test_creates_confirmed_device_and_prints_otpauth_url(self):
        from django_otp.plugins.otp_totp.models import TOTPDevice

        output = StringIO()
        call_command('provision_totp', 'enrollme@example.com', stdout=output)
        self.assertTrue(TOTPDevice.objects.get(user=self.staff).confirmed)
        self.assertIn('otpauth://totp/', output.getvalue())

    def test_unknown_user_raises_command_error(self):
        with self.assertRaises(CommandError):
            call_command('provision_totp', 'nobody@example.com')

    def test_existing_device_requires_reset_flag(self):
        from django_otp.plugins.otp_totp.models import TOTPDevice

        TOTPDevice.objects.create(user=self.staff, name='default', confirmed=True)
        with self.assertRaises(CommandError):
            call_command('provision_totp', 'enrollme@example.com')

    def test_reset_replaces_existing_device(self):
        from django_otp.plugins.otp_totp.models import TOTPDevice

        old = TOTPDevice.objects.create(user=self.staff, name='default', confirmed=True)
        call_command('provision_totp', 'enrollme@example.com', '--reset', stdout=StringIO())
        self.assertFalse(TOTPDevice.objects.filter(pk=old.pk).exists())
        self.assertEqual(TOTPDevice.objects.filter(user=self.staff).count(), 1)


class AdminIPAllowlistTests(TestCase):
    def test_disabled_when_allowlist_empty(self):
        with override_settings(ADMIN_IP_ALLOWLIST=[]):
            response = self.client.get('/admin/login/')
        self.assertEqual(response.status_code, 200)

    def test_remote_addr_inside_cidr_allowed(self):
        with override_settings(
            ADMIN_IP_ALLOWLIST=['10.46.0.0/16'],
            ADMIN_TRUSTED_PROXY_HOPS=0,
        ):
            response = self.client.get('/admin/login/', REMOTE_ADDR='10.46.0.5')
        self.assertEqual(response.status_code, 200)

    def test_remote_addr_outside_cidr_gets_404(self):
        with override_settings(
            ADMIN_IP_ALLOWLIST=['10.46.0.0/16'],
            ADMIN_TRUSTED_PROXY_HOPS=0,
        ):
            response = self.client.get('/admin/login/', REMOTE_ADDR='203.0.113.7')
        self.assertEqual(response.status_code, 404)

    def test_trusted_proxy_hops_ignore_spoofed_prefix(self):
        with override_settings(
            ADMIN_IP_ALLOWLIST=['10.46.0.0/16'],
            ADMIN_TRUSTED_PROXY_HOPS=2,
        ):
            response = self.client.get(
                '/admin/login/',
                REMOTE_ADDR='10.42.1.9',
                HTTP_X_FORWARDED_FOR='10.46.0.99, 203.0.113.7, 10.46.0.20',
            )
        self.assertEqual(response.status_code, 404)

    def test_non_admin_paths_are_unaffected(self):
        with override_settings(
            ADMIN_IP_ALLOWLIST=['10.46.0.0/16'],
            ADMIN_TRUSTED_PROXY_HOPS=0,
        ):
            response = self.client.get('/health/', REMOTE_ADDR='203.0.113.7')
        self.assertNotEqual(response.status_code, 404)
