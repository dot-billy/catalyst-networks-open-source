from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory

from certificates.models import CertificateAuthority
from nodes.models import Node
from nodes.permissions import NodeAccessPermission
from organizations.models import Membership, NetworkRange, Organization

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

        self.assertNotEqual(config_response.status_code, 200)
        self.assertNotEqual(checkin_response.status_code, 200)
        self.node.refresh_from_db()
        self.assertIsNone(self.node.last_checkin)
