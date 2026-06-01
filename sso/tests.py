from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from organizations.models import Membership, Organization

from .models import SSOConfiguration
from .saml import get_saml_settings, get_sp_urls

User = get_user_model()


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
