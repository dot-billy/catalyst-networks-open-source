from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse

from organizations.models import Membership, Organization

from .models import SSOConfiguration
from .saml import get_saml_settings

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
