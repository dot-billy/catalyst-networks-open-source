from types import SimpleNamespace
from unittest.mock import patch

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.urls import Resolver404, resolve, reverse

from organizations.models import Membership, Organization

from .models import SSOConfiguration
from .saml import get_saml_settings, get_sp_urls

User = get_user_model()


class AllauthWiringTests(SimpleTestCase):
    def test_allauth_is_configured_for_catalyst_sso(self):
        self.assertIn('django.contrib.sites', settings.INSTALLED_APPS)
        self.assertIn('allauth', settings.INSTALLED_APPS)
        self.assertIn('allauth.account', settings.INSTALLED_APPS)
        self.assertIn('allauth.socialaccount', settings.INSTALLED_APPS)
        self.assertIn('allauth.socialaccount.providers.google', settings.INSTALLED_APPS)
        self.assertIn('allauth.socialaccount.providers.openid_connect', settings.INSTALLED_APPS)
        self.assertIn(
            'allauth.account.auth_backends.AuthenticationBackend',
            settings.AUTHENTICATION_BACKENDS,
        )
        self.assertEqual(settings.SOCIALACCOUNT_ADAPTER, 'sso.adapters.CatalystSocialAccountAdapter')
        self.assertEqual(settings.SITE_ID, 1)

    def test_allauth_urls_are_mounted(self):
        self.assertEqual(reverse('socialaccount_connections'), '/accounts/3rdparty/')

    def test_allauth_account_login_and_signup_are_not_exposed(self):
        with self.assertRaises(Resolver404):
            resolve('/accounts/login/')
        with self.assertRaises(Resolver404):
            resolve('/accounts/signup/')
        with self.assertRaises(Resolver404):
            resolve('/accounts/3rdparty/signup/')
        with self.assertRaises(Resolver404):
            resolve('/accounts/google/login/token/')


class SSOLoginEnforcementTests(TestCase):
    def test_password_login_blocked_when_org_enforces_sso(self):
        user = User.objects.create_user(email='member@example.com', password='testpass')
        organization = Organization.objects.create(name='SSO Org', created_by=user)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            enforce_sso=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )

        response = self.client.post(reverse('login'), {
            'email': 'member@example.com',
            'password': 'testpass',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'requires SSO login')
        self.assertNotIn('_auth_user_id', self.client.session)

    def test_api_token_rejected_when_org_enforces_sso(self):
        user = User.objects.create_user(email='api-member@example.com', password='testpass')
        organization = Organization.objects.create(name='API SSO Org', created_by=user)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            enforce_sso=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )

        with self.assertLogs('django.request', level='WARNING'):
            response = self.client.post(reverse('token_obtain_pair'), {
                'email': 'api-member@example.com',
                'password': 'testpass',
            })

        self.assertNotEqual(response.status_code, 200)
        self.assertNotIn('access', response.json())
        self.assertIn('requires SSO login', str(response.content))

    def test_password_login_blocked_when_org_enforces_oidc_sso(self):
        user = User.objects.create_user(email='oidc-member@example.com', password='testpass')
        organization = Organization.objects.create(name='OIDC SSO Org', created_by=user)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client',
            is_enabled=True,
            enforce_sso=True,
        )

        response = self.client.post(reverse('login'), {
            'email': 'oidc-member@example.com',
            'password': 'testpass',
        })

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'requires SSO login')
        self.assertNotIn('_auth_user_id', self.client.session)


class SSOConfigurationProviderModelTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='provider-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Provider Org', created_by=self.owner)

    def test_defaults_remain_saml(self):
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )

        self.assertEqual(config.provider_type, SSOConfiguration.PROVIDER_SAML)
        self.assertTrue(config.is_saml)
        self.assertFalse(config.is_oidc)

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_oidc_secret_is_encrypted_at_rest(self):
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GENERIC,
            oidc_display_name='Okta',
            oidc_issuer_url='https://okta.example.com/oauth2/default',
            oidc_client_id='client-id',
        )

        config.set_oidc_client_secret('plain-secret')
        config.save(update_fields=['oidc_client_secret_encrypted'])
        config.refresh_from_db()

        self.assertNotIn('plain-secret', config.oidc_client_secret_encrypted)
        self.assertEqual(config.get_oidc_client_secret(), 'plain-secret')

    @override_settings(FIELD_ENCRYPTION_KEY='')
    def test_oidc_secret_encryption_requires_key(self):
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='client-id',
        )

        with self.assertRaises(ImproperlyConfigured):
            config.set_oidc_client_secret('plain-secret')


class SSOLoginServicesTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='service-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Service Org', created_by=self.owner)

    def test_complete_sso_login_auto_provisions_user_and_membership(self):
        from sso.services import SSOLoginIdentity, complete_sso_login

        config = SSOConfiguration.objects.create(
            organization=self.organization,
            is_enabled=True,
            auto_create_users=True,
            default_role='admin',
        )
        identity = SSOLoginIdentity(
            email='New-Admin@Example.com',
            subject='saml-subject',
            provider='saml',
            first_name='New',
            last_name='Admin',
        )

        user = complete_sso_login(config, identity)

        self.assertEqual(user.email, 'new-admin@example.com')
        self.assertEqual(user.first_name, 'New')
        self.assertFalse(user.has_usable_password())
        self.assertTrue(Membership.objects.filter(user=user, organization=self.organization, role='admin').exists())

    def test_complete_sso_login_rejects_oidc_email_outside_allowed_domain(self):
        from sso.services import SSOLoginIdentity, SSOLoginRejected, complete_sso_login

        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_allowed_domain='example.com',
            auto_create_users=True,
        )
        identity = SSOLoginIdentity(
            email='person@other.example',
            subject='oidc-subject',
            provider='google',
            first_name='Other',
            last_name='Domain',
        )

        with self.assertRaises(SSOLoginRejected):
            complete_sso_login(config, identity)

        self.assertFalse(User.objects.filter(email='person@other.example').exists())


class SSOAllauthSocialAppSyncTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='sync-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Sync Org', created_by=self.owner)

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_generic_oidc_config_syncs_to_allauth_social_app(self):
        from allauth.socialaccount.models import SocialApp
        from django.contrib.sites.models import Site
        from sso.services import sync_allauth_app_for_config

        Site.objects.update_or_create(
            id=settings.SITE_ID,
            defaults={'domain': 'testserver', 'name': 'testserver'},
        )
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GENERIC,
            oidc_display_name='Okta Workforce',
            oidc_issuer_url='https://idp.example.com/oauth2/default',
            oidc_client_id='client-id',
        )
        config.set_oidc_client_secret('client-secret')
        config.save(update_fields=['oidc_client_secret_encrypted'])

        app = sync_allauth_app_for_config(config)
        config.refresh_from_db()

        self.assertEqual(app.provider, 'openid_connect')
        self.assertEqual(app.provider_id, f'org-{self.organization.slug}')
        self.assertEqual(app.name, 'Okta Workforce')
        self.assertEqual(app.client_id, 'client-id')
        self.assertEqual(app.secret, '')
        self.assertEqual(app.settings['server_url'], 'https://idp.example.com/oauth2/default')
        self.assertEqual(app.settings['scope'], ['openid', 'email', 'profile'])
        self.assertTrue(app.settings['fetch_userinfo'])
        self.assertTrue(app.settings['oauth_pkce_enabled'])
        self.assertEqual(app.settings['uid_field'], 'sub')
        self.assertEqual(config.oidc_provider_id, f'org-{self.organization.slug}')
        self.assertEqual(config.allauth_app_id, app.id)
        self.assertTrue(app.sites.filter(id=settings.SITE_ID).exists())
        self.assertEqual(SocialApp.objects.count(), 1)

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_google_config_syncs_to_google_provider(self):
        from django.contrib.sites.models import Site
        from sso.services import sync_allauth_app_for_config

        Site.objects.update_or_create(
            id=settings.SITE_ID,
            defaults={'domain': 'testserver', 'name': 'testserver'},
        )
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client',
            oidc_allowed_domain='example.com',
        )
        config.set_oidc_client_secret('google-secret')
        config.save(update_fields=['oidc_client_secret_encrypted'])

        app = sync_allauth_app_for_config(config)
        config.refresh_from_db()

        self.assertEqual(app.provider, 'google')
        self.assertEqual(app.provider_id, '')
        self.assertEqual(app.client_id, 'google-client')
        self.assertEqual(app.secret, '')
        self.assertEqual(app.settings['scope'], ['openid', 'email', 'profile'])
        self.assertEqual(config.allauth_app_id, app.id)

    def test_sync_rejects_saml_config(self):
        from sso.services import sync_allauth_app_for_config

        config = SSOConfiguration.objects.create(
            organization=self.organization,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )

        with self.assertRaises(ValueError):
            sync_allauth_app_for_config(config)

    def test_generated_oidc_provider_id_fits_allauth_provider_id_limit(self):
        from sso.services import oidc_provider_id_for_config

        config = SimpleNamespace(organization=SimpleNamespace(slug='a' * 255))

        provider_id = oidc_provider_id_for_config(config)

        self.assertLessEqual(len(provider_id), 200)
        self.assertTrue(provider_id.startswith('org-'))


class SSOProviderAwareLoginRouteTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='route-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Route Org', created_by=self.owner)

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_provider_neutral_login_routes_google_oidc_to_allauth(self):
        from django.contrib.sites.models import Site

        Site.objects.update_or_create(
            id=settings.SITE_ID,
            defaults={'domain': 'testserver', 'name': 'testserver'},
        )
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client',
            oidc_allowed_domain='example.com',
        )
        config.set_oidc_client_secret('google-secret')
        config.save(update_fields=['oidc_client_secret_encrypted'])

        response = self.client.get(reverse('sso:login', kwargs={'slug': self.organization.slug}), {'next': '/dashboard/'})

        self.assertRedirects(
            response,
            '/accounts/google/login/?process=login&next=%2Fdashboard%2F',
            fetch_redirect_response=False,
        )
        session = self.client.session
        self.assertEqual(session['sso_org_slug'], self.organization.slug)
        self.assertEqual(session['sso_next'], '/dashboard/')

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_generic_oidc_login_uses_provider_id_route(self):
        from django.contrib.sites.models import Site

        Site.objects.update_or_create(
            id=settings.SITE_ID,
            defaults={'domain': 'testserver', 'name': 'testserver'},
        )
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GENERIC,
            oidc_issuer_url='https://idp.example.com/oauth2/default',
            oidc_client_id='generic-client',
        )
        config.set_oidc_client_secret('generic-secret')
        config.save(update_fields=['oidc_client_secret_encrypted'])

        response = self.client.get(reverse('sso:oidc_login', kwargs={'slug': self.organization.slug}))
        config.refresh_from_db()

        self.assertEqual(config.oidc_provider_id, f'org-{self.organization.slug}')
        self.assertRedirects(
            response,
            f'/accounts/oidc/{config.oidc_provider_id}/login/?process=login',
            fetch_redirect_response=False,
        )


class SSOConfigurationUITests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='ui-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='UI SSO Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        self.client.force_login(self.owner)

    def _post_config(self, overrides=None):
        data = {
            'provider_type': SSOConfiguration.PROVIDER_OIDC,
            'oidc_mode': SSOConfiguration.OIDC_GOOGLE,
            'oidc_display_name': 'UI Google',
            'oidc_issuer_url': '',
            'oidc_client_id': 'google-client-id',
            'oidc_client_secret': 'google-client-secret',
            'oidc_allowed_domain': 'example.com',
            'oidc_scopes': 'openid email profile',
            'oidc_email_claim': 'email',
            'oidc_first_name_claim': 'given_name',
            'oidc_last_name_claim': 'family_name',
            'oidc_subject_claim': 'sub',
            'idp_entity_id': '',
            'idp_sso_url': '',
            'idp_slo_url': '',
            'idp_x509_cert': '',
            'attribute_email': 'email',
            'attribute_first_name': 'given_name',
            'attribute_last_name': 'family_name',
            'auto_create_users': 'on',
            'default_role': 'member',
        }
        if overrides:
            data.update(overrides)
        return self.client.post(reverse('sso:configure', kwargs={'slug': self.organization.slug}), data)

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_owner_can_save_google_oidc_configuration_and_sync_allauth(self):
        with patch('sso.views.sync_allauth_app_for_config') as sync_allauth:
            response = self._post_config()

        self.assertRedirects(response, reverse('sso:configure', kwargs={'slug': self.organization.slug}))
        config = self.organization.sso_config
        self.assertEqual(config.provider_type, SSOConfiguration.PROVIDER_OIDC)
        self.assertEqual(config.oidc_mode, SSOConfiguration.OIDC_GOOGLE)
        self.assertEqual(config.oidc_client_id, 'google-client-id')
        self.assertEqual(config.get_oidc_client_secret(), 'google-client-secret')
        sync_allauth.assert_called_once_with(config)

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_google_oidc_configuration_requires_allowed_domain(self):
        response = self._post_config({'oidc_allowed_domain': ''})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Google Workspace SSO requires an allowed email domain.')
        config = self.organization.sso_config
        self.assertEqual(config.provider_type, SSOConfiguration.PROVIDER_SAML)
        self.assertEqual(config.oidc_client_id, '')

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_owner_can_save_generic_oidc_configuration(self):
        response = self._post_config({
            'oidc_mode': SSOConfiguration.OIDC_GENERIC,
            'oidc_display_name': 'Okta Workforce',
            'oidc_issuer_url': 'https://idp.example.com/oauth2/default',
            'oidc_client_id': 'generic-client-id',
            'oidc_client_secret': 'generic-client-secret',
        })

        self.assertRedirects(response, reverse('sso:configure', kwargs={'slug': self.organization.slug}))
        config = self.organization.sso_config
        self.assertEqual(config.provider_type, SSOConfiguration.PROVIDER_OIDC)
        self.assertEqual(config.oidc_mode, SSOConfiguration.OIDC_GENERIC)
        self.assertEqual(config.oidc_issuer_url, 'https://idp.example.com/oauth2/default')
        self.assertEqual(config.get_oidc_client_secret(), 'generic-client-secret')

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_blank_oidc_secret_preserves_existing_secret(self):
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='old-client-id',
        )
        config.set_oidc_client_secret('existing-secret-value')
        config.save(update_fields=['oidc_client_secret_encrypted'])
        encrypted_secret = config.oidc_client_secret_encrypted

        with patch('sso.views.sync_allauth_app_for_config'):
            response = self._post_config({
                'oidc_client_id': 'new-client-id',
                'oidc_client_secret': '',
            })

        self.assertRedirects(response, reverse('sso:configure', kwargs={'slug': self.organization.slug}))
        config.refresh_from_db()
        self.assertEqual(config.oidc_client_id, 'new-client-id')
        self.assertEqual(config.oidc_client_secret_encrypted, encrypted_secret)
        self.assertEqual(config.get_oidc_client_secret(), 'existing-secret-value')

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_configure_page_exposes_saml_google_and_generic_oidc_without_secret_value(self):
        config = SSOConfiguration.objects.create(
            organization=self.organization,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='client-id',
        )
        config.set_oidc_client_secret('do-not-render-this-secret')
        config.save(update_fields=['oidc_client_secret_encrypted'])

        response = self.client.get(reverse('sso:configure', kwargs={'slug': self.organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'SAML')
        self.assertContains(response, 'Sign in with Google')
        self.assertContains(response, 'Generic OIDC')
        self.assertContains(response, 'http://testserver/accounts/google/login/callback/')
        self.assertContains(response, f'http://testserver/sso/{self.organization.slug}/oidc/login/')
        self.assertNotContains(response, 'do-not-render-this-secret')

    def test_unsynced_generic_oidc_configure_page_uses_deterministic_callback_provider_id(self):
        response = self.client.get(reverse('sso:configure', kwargs={'slug': self.organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(
            response,
            f'http://testserver/accounts/oidc/org-{self.organization.slug}/login/callback/',
        )


class CatalystSocialAccountAdapterTests(TestCase):
    def test_generate_state_param_binds_org_context_into_oauth_state(self):
        from sso.adapters import CatalystSocialAccountAdapter, SSO_STATE_KEY

        adapter = CatalystSocialAccountAdapter()
        adapter.request = SimpleNamespace(session={
            'sso_org_slug': 'state-org',
            'sso_config_id': 123,
            'sso_allauth_app_id': 456,
        })
        state = {'process': 'login'}

        adapter.generate_state_param(state)

        self.assertEqual(state[SSO_STATE_KEY], {
            'org_slug': 'state-org',
            'config_id': '123',
            'app_id': '456',
        })

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_get_app_uses_org_session_to_select_google_social_app(self):
        from django.contrib.sites.models import Site
        from sso.adapters import CatalystSocialAccountAdapter
        from sso.services import sync_allauth_app_for_config

        Site.objects.update_or_create(
            id=settings.SITE_ID,
            defaults={'domain': 'testserver', 'name': 'testserver'},
        )
        owner = User.objects.create_user(email='adapter-owner-google@example.com', password='testpass')
        org_a = Organization.objects.create(name='Adapter Google A', created_by=owner)
        org_b = Organization.objects.create(name='Adapter Google B', created_by=owner)
        config_a = SSOConfiguration.objects.create(
            organization=org_a,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client-a',
        )
        config_a.set_oidc_client_secret('google-secret-a')
        config_a.save(update_fields=['oidc_client_secret_encrypted'])
        config_b = SSOConfiguration.objects.create(
            organization=org_b,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client-b',
        )
        config_b.set_oidc_client_secret('google-secret-b')
        config_b.save(update_fields=['oidc_client_secret_encrypted'])
        app_a = sync_allauth_app_for_config(config_a)
        sync_allauth_app_for_config(config_b)
        request = SimpleNamespace(session={'sso_org_slug': org_a.slug})

        selected_app = CatalystSocialAccountAdapter().get_app(request, 'google')

        self.assertEqual(selected_app, app_a)
        self.assertEqual(selected_app.secret, 'google-secret-a')

    @override_settings(FIELD_ENCRYPTION_KEY=Fernet.generate_key().decode())
    def test_get_app_rejects_callback_when_state_and_session_org_do_not_match(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from allauth.socialaccount.internal.statekit import STATES_SESSION_KEY
        from django.contrib.sites.models import Site
        from sso.adapters import CatalystSocialAccountAdapter, SSO_STATE_KEY
        from sso.services import sync_allauth_app_for_config

        Site.objects.update_or_create(
            id=settings.SITE_ID,
            defaults={'domain': 'testserver', 'name': 'testserver'},
        )
        owner = User.objects.create_user(email='state-mismatch-owner@example.com', password='testpass')
        org_a = Organization.objects.create(name='State Mismatch A', created_by=owner)
        org_b = Organization.objects.create(name='State Mismatch B', created_by=owner)
        config_a = SSOConfiguration.objects.create(
            organization=org_a,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client-a',
        )
        config_a.set_oidc_client_secret('google-secret-a')
        config_a.save(update_fields=['oidc_client_secret_encrypted'])
        config_b = SSOConfiguration.objects.create(
            organization=org_b,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_client_id='google-client-b',
        )
        config_b.set_oidc_client_secret('google-secret-b')
        config_b.save(update_fields=['oidc_client_secret_encrypted'])
        app_a = sync_allauth_app_for_config(config_a)
        app_b = sync_allauth_app_for_config(config_b)
        request = RequestFactory().get('/accounts/google/login/callback/', {'state': 'state-a'})
        request.session = {
            'sso_org_slug': org_b.slug,
            'sso_config_id': config_b.pk,
            'sso_allauth_app_id': app_b.pk,
            STATES_SESSION_KEY: {
                'state-a': ({
                    'process': 'login',
                    SSO_STATE_KEY: {
                        'org_slug': org_a.slug,
                        'config_id': str(config_a.pk),
                        'app_id': str(app_a.pk),
                    },
                }, 0),
            },
        }
        request._messages = FallbackStorage(request)

        with self.assertRaises(ImmediateHttpResponse) as response:
            CatalystSocialAccountAdapter().get_app(request, 'google')

        self.assertEqual(response.exception.response.url, reverse('login'))

    def test_pre_social_login_approves_user_in_org_sso_session(self):
        from sso.adapters import CatalystSocialAccountAdapter

        owner = User.objects.create_user(email='adapter-owner@example.com', password='testpass')
        user = User.objects.create_user(email='member@example.com', password='testpass', first_name='')
        organization = Organization.objects.create(name='Adapter Org', created_by=owner)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_allowed_domain='example.com',
        )
        request = SimpleNamespace(session={'sso_org_slug': organization.slug, 'sso_next': '/dashboard/'})
        sociallogin = SimpleNamespace(
            account=SimpleNamespace(extra_data={
                'email': 'member@example.com',
                'email_verified': True,
                'hd': 'example.com',
                'sub': 'google-subject',
                'given_name': 'Member',
                'family_name': 'Example',
            }),
            user=None,
        )

        CatalystSocialAccountAdapter().pre_social_login(request, sociallogin)

        user.refresh_from_db()
        self.assertEqual(sociallogin.user, user)
        self.assertEqual(user.first_name, 'Member')
        self.assertNotIn('sso_org_slug', request.session)
        self.assertNotIn('sso_next', request.session)

    def test_pre_social_login_links_new_social_account_to_approved_user(self):
        from allauth.socialaccount.models import SocialAccount
        from sso.adapters import CatalystSocialAccountAdapter

        owner = User.objects.create_user(email='link-owner@example.com', password='testpass')
        user = User.objects.create_user(email='link-member@example.com', password='testpass')
        organization = Organization.objects.create(name='Link Org', created_by=owner)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_allowed_domain='example.com',
        )
        request = SimpleNamespace(session={'sso_org_slug': organization.slug})
        sociallogin = SimpleNamespace(
            account=SocialAccount(provider='google', uid='google-subject', extra_data={
                'email': 'link-member@example.com',
                'email_verified': True,
                'hd': 'example.com',
                'sub': 'google-subject',
            }),
            user=None,
        )

        CatalystSocialAccountAdapter().pre_social_login(request, sociallogin)

        account = SocialAccount.objects.get(provider='google', uid='google-subject')
        self.assertEqual(account.user, user)
        self.assertEqual(sociallogin.account, account)
        self.assertEqual(sociallogin.user, user)

    def test_pre_social_login_rejects_unverified_google_email(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from sso.adapters import CatalystSocialAccountAdapter

        owner = User.objects.create_user(email='unverified-owner@example.com', password='testpass')
        user = User.objects.create_user(email='unverified@example.com', password='testpass')
        organization = Organization.objects.create(name='Unverified Org', created_by=owner)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GOOGLE,
            oidc_allowed_domain='example.com',
        )
        request = RequestFactory().get('/accounts/google/login/callback/')
        request.session = {'sso_org_slug': organization.slug}
        request._messages = FallbackStorage(request)
        sociallogin = SimpleNamespace(
            account=SimpleNamespace(provider='google', extra_data={
                'email': 'unverified@example.com',
                'email_verified': False,
                'hd': 'example.com',
                'sub': 'google-subject',
            }),
            user=None,
        )

        with self.assertRaises(ImmediateHttpResponse) as response:
            CatalystSocialAccountAdapter().pre_social_login(request, sociallogin)

        self.assertEqual(response.exception.response.url, reverse('login'))
        self.assertIsNone(sociallogin.user)

    def test_pre_social_login_rejects_generic_oidc_unverified_email(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from sso.adapters import CatalystSocialAccountAdapter

        owner = User.objects.create_user(email='generic-unverified-owner@example.com', password='testpass')
        user = User.objects.create_user(email='generic-unverified@example.com', password='testpass')
        organization = Organization.objects.create(name='Generic Unverified Org', created_by=owner)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GENERIC,
            oidc_provider_id=f'org-{organization.slug}',
            oidc_issuer_url='https://idp.example.com/oauth2/default',
        )
        request = RequestFactory().get(f'/accounts/oidc/org-{organization.slug}/login/callback/')
        request.session = {'sso_org_slug': organization.slug}
        request._messages = FallbackStorage(request)
        sociallogin = SimpleNamespace(
            account=SimpleNamespace(provider=f'org-{organization.slug}', extra_data={
                'userinfo': {
                    'email': 'generic-unverified@example.com',
                    'email_verified': False,
                    'sub': 'subject',
                },
                'id_token': {
                    'iss': 'https://idp.example.com/oauth2/default',
                },
            }),
            user=None,
        )

        with self.assertRaises(ImmediateHttpResponse) as response:
            CatalystSocialAccountAdapter().pre_social_login(request, sociallogin)

        self.assertEqual(response.exception.response.url, reverse('login'))
        self.assertIsNone(sociallogin.user)

    def test_pre_social_login_without_org_session_rejects_direct_allauth_flow(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from sso.adapters import CatalystSocialAccountAdapter

        request = RequestFactory().get('/accounts/google/login/callback/')
        request.session = {}
        request._messages = FallbackStorage(request)
        sociallogin = SimpleNamespace(
            account=SimpleNamespace(extra_data={'email': 'person@example.com'}),
            user='allauth-user',
        )

        with self.assertRaises(ImmediateHttpResponse) as response:
            CatalystSocialAccountAdapter().pre_social_login(request, sociallogin)

        self.assertEqual(response.exception.response.url, reverse('login'))
        self.assertEqual(sociallogin.user, 'allauth-user')

    def test_get_app_without_org_session_rejects_direct_allauth_flow(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from sso.adapters import CatalystSocialAccountAdapter

        request = RequestFactory().get('/accounts/google/login/')
        request.session = {}
        request._messages = FallbackStorage(request)

        with self.assertRaises(ImmediateHttpResponse) as response:
            CatalystSocialAccountAdapter().get_app(request, 'google')

        self.assertEqual(response.exception.response.url, reverse('login'))

    def test_pre_social_login_rejects_generic_oidc_issuer_mismatch(self):
        from allauth.core.exceptions import ImmediateHttpResponse
        from sso.adapters import CatalystSocialAccountAdapter

        owner = User.objects.create_user(email='issuer-mismatch-owner@example.com', password='testpass')
        user = User.objects.create_user(email='issuer-mismatch@example.com', password='testpass')
        organization = Organization.objects.create(name='Issuer Mismatch Org', created_by=owner)
        Membership.objects.create(user=user, organization=organization, role='member')
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            provider_type=SSOConfiguration.PROVIDER_OIDC,
            oidc_mode=SSOConfiguration.OIDC_GENERIC,
            oidc_provider_id=f'org-{organization.slug}',
            oidc_issuer_url='https://idp.example.com/oauth2/default',
        )
        request = RequestFactory().get(f'/accounts/oidc/org-{organization.slug}/login/callback/')
        request.session = {'sso_org_slug': organization.slug}
        request._messages = FallbackStorage(request)
        sociallogin = SimpleNamespace(
            account=SimpleNamespace(provider=f'org-{organization.slug}', extra_data={
                'userinfo': {'email': 'issuer-mismatch@example.com', 'sub': 'subject'},
                'id_token': {'iss': 'https://evil.example.com/oauth2/default'},
            }),
            user=None,
        )

        with self.assertRaises(ImmediateHttpResponse) as response:
            CatalystSocialAccountAdapter().pre_social_login(request, sociallogin)

        self.assertEqual(response.exception.response.url, reverse('login'))
        self.assertIsNone(sociallogin.user)


class SSOMetadataTests(TestCase):
    def test_metadata_route_is_public_for_enabled_org(self):
        owner = User.objects.create_user(email='owner@example.com', password='testpass')
        organization = Organization.objects.create(name='Metadata Org', created_by=owner)
        SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )
        settings = SimpleNamespace(
            get_sp_metadata=lambda: '<EntityDescriptor>metadata</EntityDescriptor>',
            validate_metadata=lambda metadata: [],
        )
        auth = SimpleNamespace(get_settings=lambda: settings)

        with patch('sso.views.init_saml_auth', return_value=auth):
            response = self.client.get(reverse('sso:metadata', kwargs={'slug': organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/xml')
        self.assertContains(response, '<EntityDescriptor>metadata</EntityDescriptor>')


class SSOACSTests(TestCase):
    def test_existing_non_member_assertion_is_rejected_without_creating_membership(self):
        existing_user = User.objects.create_user(email='existing@example.com', password='testpass')
        other_org = Organization.objects.create(name='Other Org', created_by=existing_user)
        Membership.objects.create(user=existing_user, organization=other_org, role='member')
        target_org = Organization.objects.create(name='Target Org', created_by=existing_user)
        SSOConfiguration.objects.create(
            organization=target_org,
            is_enabled=True,
            auto_create_users=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )
        auth = SimpleNamespace(
            process_response=lambda: None,
            get_errors=lambda: [],
            is_authenticated=lambda: True,
            get_attributes=lambda: {
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': [
                    'existing@example.com',
                ],
            },
            get_nameid=lambda: 'existing@example.com',
        )

        with patch('sso.views.init_saml_auth', return_value=auth):
            response = self.client.post(reverse('sso:acs', kwargs={'slug': target_org.slug}))

        self.assertRedirects(response, reverse('login'))
        self.assertNotIn('_auth_user_id', self.client.session)
        self.assertFalse(Membership.objects.filter(user=existing_user, organization=target_org).exists())
        self.assertEqual(Membership.objects.filter(user=existing_user).count(), 1)

    def test_auto_created_sso_user_gets_unusable_password(self):
        owner = User.objects.create_user(email='owner-acs@example.com', password='testpass')
        target_org = Organization.objects.create(name='Auto Create Org', created_by=owner)
        SSOConfiguration.objects.create(
            organization=target_org,
            is_enabled=True,
            auto_create_users=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )
        auth = SimpleNamespace(
            process_response=lambda: None,
            get_errors=lambda: [],
            is_authenticated=lambda: True,
            get_attributes=lambda: {
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': [
                    'new-sso@example.com',
                ],
            },
            get_nameid=lambda: 'new-sso@example.com',
        )

        with patch('sso.views.init_saml_auth', return_value=auth):
            response = self.client.post(reverse('sso:acs', kwargs={'slug': target_org.slug}))

        self.assertRedirects(response, '/dashboard/')
        user = User.objects.get(email='new-sso@example.com')
        self.assertFalse(user.has_usable_password())
        self.assertTrue(Membership.objects.filter(user=user, organization=target_org, role='member').exists())

    def test_acs_rejects_unsafe_relay_state(self):
        owner = User.objects.create_user(email='owner-relay@example.com', password='testpass')
        target_org = Organization.objects.create(name='Relay Org', created_by=owner)
        SSOConfiguration.objects.create(
            organization=target_org,
            is_enabled=True,
            auto_create_users=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )
        auth = SimpleNamespace(
            process_response=lambda: None,
            get_errors=lambda: [],
            is_authenticated=lambda: True,
            get_attributes=lambda: {
                'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress': [
                    'relay-sso@example.com',
                ],
            },
            get_nameid=lambda: 'relay-sso@example.com',
        )

        with patch('sso.views.init_saml_auth', return_value=auth):
            response = self.client.post(
                reverse('sso:acs', kwargs={'slug': target_org.slug}),
                {'RelayState': 'https://evil.example/phish'},
            )

        self.assertRedirects(response, '/dashboard/')


class SAMLSettingsTests(TestCase):
    def test_sp_settings_do_not_emit_sls_without_matching_route(self):
        owner = User.objects.create_user(email='owner-settings@example.com', password='testpass')
        organization = Organization.objects.create(name='Settings Org', created_by=owner)
        sso_config = SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )

        saml_settings = get_saml_settings(sso_config, request=None)

        self.assertNotIn('singleLogoutService', saml_settings['sp'])

    @override_settings(BASE_URL='https://sso.example.test')
    def test_sp_settings_use_canonical_route_helper_urls(self):
        owner = User.objects.create_user(email='owner-urls@example.com', password='testpass')
        organization = Organization.objects.create(name='URL Org', created_by=owner)
        sso_config = SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )

        sp_urls = get_sp_urls(sso_config)
        saml_settings = get_saml_settings(sso_config, request=None)

        self.assertEqual(sp_urls['metadata'], 'https://sso.example.test/sso/url-org/metadata/')
        self.assertEqual(sp_urls['acs'], 'https://sso.example.test/sso/url-org/acs/')
        self.assertEqual(sp_urls['login'], 'https://sso.example.test/sso/url-org/login/')
        self.assertEqual(saml_settings['sp']['entityId'], sp_urls['metadata'])
        self.assertEqual(saml_settings['sp']['assertionConsumerService']['url'], sp_urls['acs'])

    @override_settings(BASE_URL='https://canonical.example.test')
    def test_configure_view_displays_runtime_sp_urls(self):
        owner = User.objects.create_user(email='owner-configure@example.com', password='testpass')
        organization = Organization.objects.create(name='Configure Org', created_by=owner)
        Membership.objects.create(user=owner, organization=organization, role='owner')
        sso_config = SSOConfiguration.objects.create(
            organization=organization,
            is_enabled=True,
            idp_entity_id='https://idp.example.com/metadata',
            idp_sso_url='https://idp.example.com/sso',
            idp_x509_cert='test-cert',
        )
        sp_urls = get_sp_urls(sso_config)
        self.client.force_login(owner)

        response = self.client.get(reverse('sso:configure', kwargs={'slug': organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['sp_metadata_url'], sp_urls['metadata'])
        self.assertEqual(response.context['sp_acs_url'], sp_urls['acs'])
        self.assertEqual(response.context['sp_login_url'], sp_urls['login'])
        self.assertContains(response, sp_urls['metadata'])
        self.assertContains(response, sp_urls['acs'])
        self.assertContains(response, sp_urls['login'])
