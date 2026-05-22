import io
import json
import subprocess
import zipfile
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory

from certificates.models import CertificateAuthority
from nodes.api_registration import NodeRegistrationView
from nodes.models import Node
from nodes.permissions import NodeAccessPermission
from organizations.models import Membership, NetworkRange, Organization
from security_groups.models import SecurityGroup

User = get_user_model()


class NodeOrgUrlExportTests(SimpleTestCase):
    def test_bulk_org_views_are_reexported_for_urlconf(self):
        from nodes import views

        for view_name in (
            'org_node_export_csv',
            'org_node_import_csv',
            'org_node_bulk_delete',
            'org_node_bulk_renew',
        ):
            with self.subTest(view_name=view_name):
                self.assertTrue(callable(getattr(views, view_name, None)))


class NodeAccessPermissionTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_user(email='owner@example.com', password='testpass')
        self.member = User.objects.create_user(email='member@example.com', password='testpass')
        self.outsider = User.objects.create_user(email='outsider@example.com', password='testpass')

        self.organization = Organization.objects.create(name='Node Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        Membership.objects.create(user=self.member, organization=self.organization, role='member')
        NetworkRange.objects.create(
            organization=self.organization,
            cidr='10.42.0.0/24',
            description='test range',
        )

        self.ca = CertificateAuthority.objects.create(
            name='Test CA',
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('ca.key', b'key-bytes'),
        )

        self.node = Node.objects.create(
            name='node-1',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.42.0.10',
            created_by=self.owner,
        )
        self.other_node = Node.objects.create(
            name='node-2',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.42.0.11',
            created_by=self.owner,
        )

    def _request(self, path, user=None, node=None, slug=None):
        request = self.factory.get(path)
        request.user = user
        request.parser_context = {'kwargs': {'slug': slug or self.organization.slug}}
        if node is not None:
            request.node = node
        return request

    def test_manager_has_permission_for_org_node_action(self):
        permission = NodeAccessPermission()
        request = self._request('/api/org/node-org/nodes/1/', user=self.owner)

        allowed = permission.has_permission(request, SimpleNamespace(action='retrieve'))

        self.assertTrue(allowed)

    def test_permission_logging_does_not_include_authorization_header_value(self):
        permission = NodeAccessPermission()
        supplied_secret = 'node-runtime-token-change-me'
        request = self.factory.get(
            '/api/org/node-org/nodes/1/download_config/',
            HTTP_AUTHORIZATION=' '.join(('Bearer', supplied_secret)),
        )
        request.user = self.outsider
        request.node = self.node
        request.parser_context = {'kwargs': {'slug': self.organization.slug}}

        with self.assertLogs('nodes.permissions', level='INFO') as captured:
            allowed = permission.has_permission(request, SimpleNamespace(action='download_config'))

        self.assertTrue(allowed)
        log_output = '\n'.join(captured.output)
        self.assertNotIn(supplied_secret, log_output)
        self.assertNotIn('Authorization', log_output)

    def test_member_lacks_manager_permission_for_org_node_action(self):
        permission = NodeAccessPermission()
        request = self._request('/api/org/node-org/nodes/1/', user=self.member)

        allowed = permission.has_permission(request, SimpleNamespace(action='retrieve'))

        self.assertFalse(allowed)

    def test_node_token_access_requires_matching_organization_slug(self):
        permission = NodeAccessPermission()
        request = self._request(
            '/api/org/other-org/nodes/1/download_config/',
            user=self.outsider,
            node=self.node,
            slug='other-org',
        )

        allowed = permission.has_permission(request, SimpleNamespace(action='download_config'))

        self.assertFalse(allowed)

    def test_node_can_access_its_own_object(self):
        permission = NodeAccessPermission()
        request = self._request(
            '/api/org/node-org/nodes/1/download_config/',
            user=self.outsider,
            node=self.node,
        )

        allowed = permission.has_object_permission(
            request,
            SimpleNamespace(action='download_config'),
            self.node,
        )

        self.assertTrue(allowed)

    def test_node_cannot_access_another_node_object(self):
        permission = NodeAccessPermission()
        request = self._request(
            '/api/org/node-org/nodes/2/download_config/',
            user=self.outsider,
            node=self.node,
        )

        allowed = permission.has_object_permission(
            request,
            SimpleNamespace(action='download_config'),
            self.other_node,
        )

        self.assertFalse(allowed)

    def test_manager_has_object_permission_on_node(self):
        permission = NodeAccessPermission()
        request = self.factory.get('/api/org/node-org/nodes/1/')
        request.user = self.owner

        allowed = permission.has_object_permission(
            request,
            SimpleNamespace(action='retrieve'),
            self.node,
        )

        self.assertTrue(allowed)


class NodeAPIMasterTokenRegressionTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.owner = User.objects.create_user(email='owner-api@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Node API Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        NetworkRange.objects.create(
            organization=self.organization,
            cidr='10.43.0.0/24',
            description='test range',
        )
        self.ca = CertificateAuthority.objects.create(
            name='API Test CA',
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('api-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('api-ca.key', b'key-bytes'),
        )
        self.node = Node.objects.create(
            name='api-node-1',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.43.0.10',
            created_by=self.owner,
            api_token='node-api-token',
        )

    @override_settings(**{'REGISTRATION_MASTER_TOKEN': 'master-registration-token-change-me'})
    def test_master_registration_token_cannot_access_node_runtime_endpoints(self):
        auth_value = ' '.join(('Bearer', 'master-registration-token-change-me'))
        self.client.credentials(HTTP_AUTHORIZATION=auth_value)
        base_url = f'/api/org/{self.organization.slug}/nodes/{self.node.id}'

        config_response = self.client.get(f'{base_url}/download_config/')
        checkin_response = self.client.post(f'{base_url}/checkin/')

        self.assertIn(config_response.status_code, (401, 403))
        self.assertIn(checkin_response.status_code, (401, 403))
        self.node.refresh_from_db()
        self.assertIsNone(self.node.last_checkin)


class NodeCertificateReliabilityTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.client.raise_request_exception = False
        self.owner = User.objects.create_user(email='cert-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Certificate Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        NetworkRange.objects.create(
            organization=self.organization,
            cidr='10.44.0.0/24',
            description='test range',
        )
        self.ca = CertificateAuthority.objects.create(
            name='Certificate Test CA',
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('cert-ca.crt', b'ca-certificate-bytes'),
            ca_key=SimpleUploadedFile('cert-ca.key', b'ca-key-bytes'),
        )
        self.node = Node.objects.create(
            name='cert-node-1',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.44.0.10',
            created_by=self.owner,
            api_token='node-cert-token',
        )
        self.config_url = f'/api/org/{self.organization.slug}/nodes/{self.node.id}/download_config/'

    def _save_node_certificate_files(self, cert_data=b'node-certificate-bytes', key_data=b'node-key-bytes'):
        self.node.cert_path.save('node-current.crt', ContentFile(cert_data), save=False)
        self.node.key_path.save('node-current.key', ContentFile(key_data), save=False)
        self.node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
        self.node.save(update_fields=['cert_path', 'key_path', 'cert_expiration'])
        self.node.refresh_from_db()

    def test_config_download_regenerates_missing_certificate_files(self):
        self.node.cert_path = 'certs/missing.crt'
        self.node.key_path = 'certs/missing.key'
        self.node.save(update_fields=['cert_path', 'key_path'])

        def regenerate(_view, node):
            node.cert_path.save('node-regenerated.crt', ContentFile(b'regenerated-cert'), save=False)
            node.key_path.save('node-regenerated.key', ContentFile(b'regenerated-key'), save=False)
            node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
            node.save(update_fields=['cert_path', 'key_path', 'cert_expiration'])

        with mock.patch.object(NodeRegistrationView, '_generate_certificate', autospec=True, side_effect=regenerate):
            response = self.client.get(
                self.config_url,
                HTTP_AUTHORIZATION=' '.join(('Bearer', self.node.api_token)),
            )

        self.assertEqual(response.status_code, 200)
        self.node.refresh_from_db()
        self.assertTrue(self.node.cert_path)
        self.assertTrue(self.node.key_path)
        self.assertIn('regenerated-cert', response.json()['certificate'])
        self.assertIn('regenerated-key', response.json()['key'])

    def test_zip_config_bundle_uses_stable_certificate_names(self):
        self._save_node_certificate_files()

        with mock.patch.object(NodeRegistrationView, '_certificate_needs_regeneration', return_value=False, create=True):
            response = NodeRegistrationView()._prepare_node_package(self.node, 'zip')

        bundle = b''.join(response.streaming_content)
        with zipfile.ZipFile(io.BytesIO(bundle)) as zip_file:
            names = zip_file.namelist()

        self.assertIn('node.crt', names)
        self.assertIn('node.key', names)

    def test_certificate_regenerates_when_security_group_claims_are_stale(self):
        self._save_node_certificate_files()
        security_group = SecurityGroup.objects.create(
            name='web',
            organization=self.organization,
            description='web nodes',
        )
        self.node.security_groups.add(security_group)

        cert_info = {
            'details': {
                'groups': [],
                'networks': ['10.44.0.10/24'],
            }
        }
        completed = subprocess.CompletedProcess(
            args=['nebula-cert', 'print'],
            returncode=0,
            stdout=json.dumps(cert_info),
            stderr='',
        )

        with mock.patch('nodes.api_registration.subprocess.run', return_value=completed):
            needs_regeneration = NodeRegistrationView()._certificate_needs_regeneration(self.node)

        self.assertTrue(needs_regeneration)

    def test_certificate_renewal_includes_security_group_claims(self):
        security_group = SecurityGroup.objects.create(
            name='web',
            organization=self.organization,
            description='web nodes',
        )
        self.node.security_groups.add(security_group)

        sign_commands = []

        def run_nebula_cert(command, *args, **kwargs):
            if command[:2] == ['nebula-cert', 'sign']:
                sign_commands.append(command)
                cert_path = command[command.index('-out-crt') + 1]
                key_path = command[command.index('-out-key') + 1]
                with open(cert_path, 'wb') as cert_file:
                    cert_file.write(b'renewed-cert')
                with open(key_path, 'wb') as key_file:
                    key_file.write(b'renewed-key')
                return subprocess.CompletedProcess(command, 0, '', '')
            if command[:2] == ['nebula-cert', 'print']:
                return subprocess.CompletedProcess(
                    command,
                    0,
                    'Not After: 2030-01-01 00:00:00 +0000 UTC\n',
                    '',
                )
            raise AssertionError(f'Unexpected command: {command}')

        with mock.patch('nodes.tasks.subprocess.run', side_effect=run_nebula_cert):
            from nodes.tasks import renew_node_certificate

            result = renew_node_certificate(self.node.id)

        self.assertTrue(result['success'])
        self.assertTrue(sign_commands)
        sign_command = sign_commands[0]
        self.assertIn('-groups', sign_command)
        self.assertEqual(sign_command[sign_command.index('-groups') + 1], 'web')
