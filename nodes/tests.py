import io
import json
import os
import subprocess
import zipfile
from datetime import timedelta, timezone as datetime_timezone
from types import SimpleNamespace
from unittest import mock
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.test import APIClient, APIRequestFactory

from nodes.api_views import NodeViewSet, OrgNodeViewSet
from certificates.models import CertificateAuthority
from nodes.api_registration import NodeRegistrationView
from nodes.models import Node, NodeRegistrationToken
from nodes.permissions import NodeAccessPermission
from organizations.models import Membership, NetworkRange, Organization
from security_groups.models import FirewallRule, SecurityGroup

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
            api_token='node-token-1',
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

    def test_checkin_action_accepts_nested_org_url_kwargs(self):
        request = self.factory.post('/api/org/node-org/nodes/1/checkin/')
        request.node = self.node

        view = NodeViewSet()
        view.request = request
        view.kwargs = {'slug': self.organization.slug, 'pk': self.node.pk}

        response = view.checkin(request, pk=self.node.pk, slug=self.organization.slug)

        self.assertEqual(response.status_code, 200)
        self.node.refresh_from_db()
        self.assertIsNotNone(self.node.last_checkin)

    def test_org_node_checkin_route_updates_last_checkin(self):
        view = OrgNodeViewSet.as_view({'post': 'checkin'})
        request = self.factory.post(
            f'/api/org/{self.organization.slug}/nodes/{self.node.pk}/checkin/',
            HTTP_AUTHORIZATION='Bearer node-token-1',
        )

        response = view(request, slug=self.organization.slug, pk=self.node.pk)

        self.assertEqual(response.status_code, 200)
        self.node.refresh_from_db()
        self.assertIsNotNone(self.node.last_checkin)

class NodeWebExternalPortTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='node-web-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Node Web Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        NetworkRange.objects.create(
            organization=self.organization,
            cidr='10.42.0.0/24',
            description='node web range',
        )
        self.ca = CertificateAuthority.objects.create(
            name='Node Web CA',
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('node-web-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('node-web-ca.key', b'key-bytes'),
        )
        self.node = Node.objects.create(
            name='node-web-1',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.42.0.20',
            external_port=4242,
            created_by=self.owner,
        )
        self.client.force_login(self.owner)

    @mock.patch('nodes.web_views.regenerate_certificate', return_value=True)
    def test_external_port_can_be_updated_for_standard_node(self, regenerate_certificate):
        response = self.client.post(
            reverse('nodes_org:edit', kwargs={'slug': self.organization.slug, 'pk': self.node.id}),
            {
                'name': self.node.name,
                'external_port': '4343',
            },
        )

        self.assertRedirects(
            response,
            reverse('nodes_org:detail', kwargs={'slug': self.organization.slug, 'pk': self.node.id}),
        )
        self.node.refresh_from_db()
        self.assertFalse(self.node.is_lighthouse)
        self.assertEqual(self.node.external_port, 4343)
        regenerate_certificate.assert_called_once_with(self.node)

    def test_external_port_rejects_out_of_range_value(self):
        response = self.client.post(
            reverse('nodes_org:edit', kwargs={'slug': self.organization.slug, 'pk': self.node.id}),
            {
                'name': self.node.name,
                'external_port': '70000',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'External port must be a number between 1 and 65535.')
        self.node.refresh_from_db()
        self.assertEqual(self.node.external_port, 4242)


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


class NodeRegistrationNotificationTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email='registration-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Registration Notify Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        NetworkRange.objects.create(
            organization=self.organization,
            cidr='10.54.0.0/24',
            description='registration range',
        )
        self.ca = CertificateAuthority.objects.create(
            name='Registration Test CA',
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('registration-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('registration-ca.key', b'key-bytes'),
        )

    @mock.patch('notifications.dispatch.queue_notification_event')
    def test_api_registration_queues_non_secret_lifecycle_notifications(self, queue_notification_event):
        view = NodeRegistrationView()

        with (
            mock.patch.object(NodeRegistrationView, '_generate_certificate', return_value=None),
            mock.patch.object(
                NodeRegistrationView,
                '_prepare_node_package',
                return_value=Response({'certificate': 'cert-secret', 'key': 'key-secret'}),
            ),
        ):
            response = view._create_node(
                organization=self.organization,
                node_name='api-registered-node',
                is_lighthouse=True,
                public_ip='203.0.113.10',
                fqdn=None,
                external_port=4242,
                created_by=self.owner,
                token=None,
            )

        self.assertEqual(response.status_code, 200)
        self.assertIn('api_token', response.data)
        queued = [(call.args[0], call.args[1], call.args[2]) for call in queue_notification_event.call_args_list]
        self.assertEqual(
            [event_type for event_type, _, _ in queued],
            ['node.registered', 'node.created', 'cert.issued', 'ip.allocated'],
        )
        for event_type, organization_id, payload in queued:
            with self.subTest(event_type=event_type):
                self.assertEqual(organization_id, self.organization.id)
                self.assertEqual(payload['node_name'], 'api-registered-node')
                serialized_payload = json.dumps(payload)
                self.assertNotIn(response.data['api_token'], serialized_payload)
                self.assertNotIn('cert-secret', serialized_payload)
                self.assertNotIn('key-secret', serialized_payload)


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

    def _mark_node_checked_in_before_retention(self, days=60):
        old_time = timezone.now() - timezone.timedelta(days=days)
        Node.objects.filter(pk=self.node.pk).update(
            created_at=old_time,
            last_checkin=timezone.now(),
        )
        self.node.refresh_from_db()

    def _set_certificate_file_mtime(self, modified_at):
        timestamp = modified_at.timestamp()
        os.utime(self.node.cert_path.path, (timestamp, timestamp))
        os.utime(self.node.key_path.path, (timestamp, timestamp))

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

    def _create_foreign_source_node(self):
        foreign_owner = User.objects.create_user(email='foreign-cert-owner@example.com', password='testpass')
        foreign_org = Organization.objects.create(name='Foreign Cert Org', created_by=foreign_owner)
        Membership.objects.create(user=foreign_owner, organization=foreign_org, role='owner')
        NetworkRange.objects.create(
            organization=foreign_org,
            cidr='10.45.0.0/24',
            description='foreign range',
        )
        foreign_ca = CertificateAuthority.objects.create(
            name='Foreign Certificate Test CA',
            organization=foreign_org,
            created_by=foreign_owner,
            ca_cert=SimpleUploadedFile('foreign-cert-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('foreign-cert-ca.key', b'key-bytes'),
        )
        foreign_group = SecurityGroup.objects.create(
            name='foreign-web',
            organization=foreign_org,
            description='foreign source group',
        )
        foreign_node = Node.objects.create(
            name='foreign-source-node',
            organization=foreign_org,
            certificate_authority=foreign_ca,
            nebula_ip='10.45.0.10',
            created_by=foreign_owner,
        )
        return foreign_group, foreign_node

    def test_config_filters_foreign_legacy_source_groups(self):
        self._save_node_certificate_files()
        destination_group = SecurityGroup.objects.create(
            name='app',
            organization=self.organization,
            description='app nodes',
        )
        local_source_group = SecurityGroup.objects.create(
            name='local-web',
            organization=self.organization,
            description='local source group',
        )
        foreign_group, _foreign_node = self._create_foreign_source_node()
        self.node.security_groups.add(destination_group)
        rule = FirewallRule.objects.create(
            security_group=destination_group,
            protocol='tcp',
            port_min=443,
            port_max=443,
            description='mixed source groups',
            match_type='groups',
        )
        rule.source_groups.set([local_source_group, foreign_group])

        with mock.patch.object(NodeRegistrationView, '_certificate_needs_regeneration', return_value=False, create=True):
            response = NodeRegistrationView()._prepare_node_package(self.node, 'json')

        config_yaml = response.data['config_yaml']
        self.assertIn('local-web', config_yaml)
        self.assertNotIn('foreign-web', config_yaml)

    def test_config_filters_foreign_legacy_source_nodes(self):
        self._save_node_certificate_files()
        destination_group = SecurityGroup.objects.create(
            name='db',
            organization=self.organization,
            description='db nodes',
        )
        local_source_node = Node.objects.create(
            name='local-source-node',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.44.0.11',
            created_by=self.owner,
        )
        _foreign_group, foreign_node = self._create_foreign_source_node()
        self.node.security_groups.add(destination_group)
        rule = FirewallRule.objects.create(
            security_group=destination_group,
            protocol='tcp',
            port_min=5432,
            port_max=5432,
            description='mixed source nodes',
            match_type='host',
        )
        rule.source_nodes.set([local_source_node, foreign_node])

        with mock.patch.object(NodeRegistrationView, '_certificate_needs_regeneration', return_value=False, create=True):
            response = NodeRegistrationView()._prepare_node_package(self.node, 'json')

        config_yaml = response.data['config_yaml']
        self.assertIn(local_source_node.nebula_ip, config_yaml)
        self.assertNotIn(foreign_node.name, config_yaml)
        self.assertNotIn(foreign_node.nebula_ip, config_yaml)

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

    def test_certificate_freshness_uses_nebula_json_ips(self):
        self._save_node_certificate_files()
        cert_info = {
            'details': {
                'groups': [],
                'ips': ['10.44.0.10/24'],
            }
        }
        completed = subprocess.CompletedProcess(
            args=['nebula-cert', 'print'],
            returncode=0,
            stdout=json.dumps(cert_info),
            stderr='',
        )

        with mock.patch('nodes.api_registration.subprocess.run', return_value=completed) as run:
            needs_regeneration = NodeRegistrationView()._certificate_needs_regeneration(self.node)

        self.assertFalse(needs_regeneration)
        self.assertEqual(run.call_args.args[0][:3], ['nebula-cert', 'print', '-json'])

    def test_download_reuses_certificate_when_claims_match_node_state(self):
        self._save_node_certificate_files()
        group = SecurityGroup.objects.create(name='admins', organization=self.organization)
        self.node.tags.add(group)
        cert_info = {
            'details': {
                'groups': ['admins'],
                'ips': ['10.44.0.10/24'],
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

        self.assertFalse(needs_regeneration)

    def test_download_reuses_v17_certificate_ips_when_claims_match_node_state(self):
        self._save_node_certificate_files()
        group = SecurityGroup.objects.create(name='admins', organization=self.organization)
        self.node.tags.add(group)
        cert_info = {
            'details': {
                'groups': ['admins'],
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

        self.assertFalse(needs_regeneration)

    @mock.patch('notifications.dispatch.queue_notification_event')
    def test_mobile_node_creation_queues_lifecycle_notifications(self, queue_notification_event):
        self.client.force_login(self.owner)

        with mock.patch('nodes.web_views.regenerate_certificate', return_value=True):
            response = self.client.post(
                reverse('nodes_org:create_mobile', kwargs={'slug': self.organization.slug}),
                {
                    'name': 'mobile-node-1',
                    'assigned_user': str(self.owner.id),
                },
            )

        self.assertEqual(response.status_code, 302)
        node = Node.objects.get(name='mobile-node-1')
        self.assertEqual(response.url, reverse('nodes_org:detail', kwargs={'slug': self.organization.slug, 'pk': node.id}))
        queued = [(call.args[0], call.args[1], call.args[2]) for call in queue_notification_event.call_args_list]
        self.assertEqual(
            [event_type for event_type, _, _ in queued],
            ['node.created', 'cert.issued', 'ip.allocated'],
        )
        for event_type, organization_id, payload in queued:
            with self.subTest(event_type=event_type):
                self.assertEqual(organization_id, self.organization.id)
                self.assertEqual(payload['node_name'], 'mobile-node-1')
                self.assertEqual(payload['nebula_ip'], node.nebula_ip)

    @mock.patch('notifications.dispatch.queue_notification_event')
    def test_node_delete_queues_revoked_notification(self, queue_notification_event):
        self.client.force_login(self.owner)
        node_id = self.node.id
        node_name = self.node.name
        node_ip = self.node.nebula_ip

        response = self.client.post(reverse('nodes_org:delete', kwargs={'slug': self.organization.slug, 'pk': node_id}))

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Node.objects.filter(id=node_id).exists())
        queue_notification_event.assert_called_once_with(
            'node.revoked',
            self.organization.id,
            mock.ANY,
        )
        payload = queue_notification_event.call_args.args[2]
        self.assertEqual(payload['node_id'], node_id)
        self.assertEqual(payload['node_name'], node_name)
        self.assertEqual(payload['nebula_ip'], node_ip)

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

    @mock.patch('notifications.dispatch.queue_notification_event')
    def test_certificate_renewal_queues_slack_notification(self, dispatch_event):
        def run_nebula_cert(command, *args, **kwargs):
            if command[:2] == ['nebula-cert', 'sign']:
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
        dispatch_event.assert_called_once()
        event_type, organization_id, payload = dispatch_event.call_args.args
        self.assertEqual(event_type, 'cert.renewed')
        self.assertEqual(organization_id, self.organization.id)
        self.assertEqual(payload['node_name'], self.node.name)
        self.assertTrue(payload['renewal'])

    def test_cleanup_stale_cert_files_keeps_fresh_files_for_old_checked_in_node(self):
        self._save_node_certificate_files()
        self._mark_node_checked_in_before_retention()
        self._set_certificate_file_mtime(timezone.now())
        original_cert_name = self.node.cert_path.name
        original_key_name = self.node.key_path.name
        cert_path = self.node.cert_path.path
        key_path = self.node.key_path.path

        from nodes.tasks import cleanup_stale_cert_files

        result = cleanup_stale_cert_files()

        self.assertEqual(result['cleaned_nodes'], 0)
        self.node.refresh_from_db()
        self.assertEqual(self.node.cert_path.name, original_cert_name)
        self.assertEqual(self.node.key_path.name, original_key_name)
        self.assertTrue(os.path.exists(cert_path))
        self.assertTrue(os.path.exists(key_path))

    def test_cleanup_stale_cert_files_clears_fields_after_old_files_are_deleted(self):
        self._save_node_certificate_files()
        self._mark_node_checked_in_before_retention()
        old_file_time = timezone.now() - timezone.timedelta(days=60)
        self._set_certificate_file_mtime(old_file_time)
        cert_path = self.node.cert_path.path
        key_path = self.node.key_path.path

        from nodes.tasks import cleanup_stale_cert_files

        result = cleanup_stale_cert_files()

        self.assertEqual(result['cleaned_nodes'], 1)
        self.node.refresh_from_db()
        self.assertFalse(self.node.cert_path)
        self.assertFalse(self.node.key_path)
        self.assertFalse(os.path.exists(cert_path))
        self.assertFalse(os.path.exists(key_path))

    def test_certificate_renewal_parses_json_expiration(self):
        json_expiration = '2030-01-01T00:00:00Z'

        def run_nebula_cert(command, *args, **kwargs):
            if command[:2] == ['nebula-cert', 'sign']:
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
                    json.dumps({'details': {'notAfter': json_expiration}}),
                    '',
                )
            raise AssertionError(f'Unexpected command: {command}')

        with mock.patch('nodes.tasks.subprocess.run', side_effect=run_nebula_cert):
            from nodes.tasks import renew_node_certificate

            result = renew_node_certificate(self.node.id)

        self.assertTrue(result['success'])
        self.node.refresh_from_db()
        self.assertEqual(self.node.cert_expiration, timezone.datetime(2030, 1, 1, tzinfo=datetime_timezone.utc))
        self.assertEqual(result['new_expiration'], self.node.cert_expiration.isoformat())


class MasterTokenRegistrationRegressionTests(TestCase):
    """F-01: the REGISTRATION_MASTER_TOKEN cross-tenant fallback must stay deleted.

    A global master token allowed registering nodes in any organization. Token
    registration must only succeed against a per-org NodeRegistrationToken row.
    """

    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_user(email='f01-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='F01 Org', created_by=self.owner)

    def _register(self, token_value):
        request = self.factory.post(
            f'/api/org/{self.organization.slug}/nodes/register/',
            {
                'organization_slug': self.organization.slug,
                'node_name': 'f01-node',
                'registration_token': token_value,
            },
            format='json',
        )
        return NodeRegistrationView.as_view()(request, slug=self.organization.slug)

    def test_master_token_env_var_does_not_authorize_registration(self):
        with patch.dict(os.environ, {'REGISTRATION_MASTER_TOKEN': 'leaked-master-token'}):
            response = self._register('leaked-master-token')

        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.data['error'], 'Invalid Registration Token')
        self.assertEqual(Node.objects.count(), 0)

    def test_per_org_token_still_reaches_node_creation(self):
        org_token = NodeRegistrationToken.objects.create(
            organization=self.organization,
            description='f01 regression token',
            created_by=self.owner,
            expires_at=timezone.now() + timedelta(days=1),
        )

        from rest_framework import status as drf_status
        from rest_framework.response import Response

        with patch.object(
            NodeRegistrationView, '_create_node',
            return_value=Response({'status': 'success'}, status=drf_status.HTTP_201_CREATED),
        ) as create_node:
            response = self._register(org_token.token)

        self.assertEqual(response.status_code, 201)
        create_node.assert_called_once()
        self.assertEqual(create_node.call_args.kwargs['organization'], self.organization)

class NodeTagsRenameTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        self.owner = User.objects.create_user(email='tags-rename@example.com', password='pw')
        self.org = Organization.objects.create(name='Tags Rename Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.44.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.node = Node.objects.create(
            name='n1', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.44.0.10', external_port=4242, created_by=self.owner)

    def test_node_tags_flattens_into_expected_certificate_groups(self):
        from security_groups.models import Tag
        from nodes.tasks import _expected_certificate_groups
        t = Tag.objects.create(name='admins', organization=self.org)
        self.node.tags.add(t)
        self.assertEqual(_expected_certificate_groups(self.node), ['admins'])


class ResolverTargetGroupsTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        self.owner = User.objects.create_user(email='resolver@example.com', password='pw')
        self.org = Organization.objects.create(name='Resolver Org', created_by=self.owner)
        NetworkRange.objects.create(organization=self.org, cidr='10.45.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.node = Node.objects.create(
            name='n', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.45.0.10', external_port=4242, created_by=self.owner)

    def test_target_groups_rule_is_resolved_for_tagged_node(self):
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='db', organization=self.org)
        self.node.tags.add(tag)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=5432, port_max=5432)
        rule.save()
        rule.target_groups.add(tag)        # new target path
        rule.security_group = None         # clear legacy FK to prove target_groups is used
        rule.save()
        self.assertIn(rule, self.node.get_all_applicable_firewall_rules())


class FirewallRenderEquivalenceTests(TestCase):
    """
    Lock the firewall-render inbound-equivalence guarantee.

    Each test case asserts an EXPLICIT expected YAML fragment so that any future
    renderer change that alters the inbound output is caught immediately.
    """

    def setUp(self):
        from organizations.models import Organization, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        self.owner = User.objects.create_user(email='equiv@example.com', password='pw')
        self.organization = Organization.objects.create(name='Equiv Org', created_by=self.owner)
        NetworkRange.objects.create(organization=self.organization, cidr='10.50.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.organization, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'ca-cert-bytes'),
            ca_key=SimpleUploadedFile('ca.key', b'ca-key-bytes'))

    def _make_node(self, name, ip, suffix=''):
        """Create a node with seeded cert/key files so _prepare_node_package succeeds."""
        from django.core.files.uploadedfile import SimpleUploadedFile
        node = Node.objects.create(
            name=name, organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip=ip, external_port=4242, created_by=self.owner)
        node.cert_path.save(f'{name}.crt', SimpleUploadedFile(f'{name}.crt', b'node-cert'), save=False)
        node.key_path.save(f'{name}.key', SimpleUploadedFile(f'{name}.key', b'node-key'), save=True)
        return node

    def _cert_info(self, node, groups=None):
        return {'details': {'groups': groups or [], 'networks': [f'{node.nebula_ip}/24']}}

    def _render(self, node, groups=None):
        """Call _prepare_node_package with cert-regeneration patched out."""
        with patch.object(NodeRegistrationView, '_certificate_needs_regeneration', return_value=False):
            response = NodeRegistrationView()._prepare_node_package(node)
        return response.data['config_yaml']

    def test_inbound_tag_source_rule_renders_groups_and_port(self):
        """
        direction='in' rule with source_groups=['web'] targeting tag 'db':
        inbound must contain a groups: entry listing 'web' and port 5432 / proto tcp.
        """
        from security_groups.models import Tag, FirewallRule
        db_tag = Tag.objects.create(name='db', organization=self.organization)
        web_tag = Tag.objects.create(name='web', organization=self.organization)
        node = self._make_node('db-node', '10.50.0.10')
        node.tags.add(db_tag)

        # Save-twice pattern: clean() requires a target at initial save.
        rule = FirewallRule(
            security_group=db_tag,
            protocol='tcp',
            port_min=5432,
            port_max=5432,
            direction='in',
            match_type='groups',
        )
        rule.save()
        rule.target_groups.add(db_tag)
        rule.source_groups.add(web_tag)
        rule.security_group = None
        rule.save()

        config_yaml = self._render(node)
        inbound_section = config_yaml.split('inbound:', 1)[1]

        # Must contain proto tcp, port 5432, and the source group name 'web'.
        self.assertIn('tcp', inbound_section)
        self.assertIn('5432', inbound_section)
        self.assertIn('web', inbound_section)
        # Explicit fragment: the groups list entry
        self.assertIn('groups:', inbound_section)

    def test_inbound_cidr_source_rule_renders_cidr_not_host(self):
        """
        direction='in' rule with source_cidr='10.0.0.0/8', port 22:
        inbound must contain cidr: 10.0.0.0/8 (NOT a 'host:' key) with port 22.
        Nebula matches IP/CIDR sources via the 'cidr' key; 'host' matches the
        remote cert NAME and would never match a CIDR.
        """
        from security_groups.models import Tag, FirewallRule
        infra_tag = Tag.objects.create(name='infra', organization=self.organization)
        node = self._make_node('ssh-node', '10.50.0.11')
        node.tags.add(infra_tag)

        rule = FirewallRule(
            security_group=infra_tag, protocol='tcp', port_min=22, port_max=22,
            direction='in', source_cidr='10.0.0.0/8', match_type='cidr')
        rule.save()
        rule.target_groups.add(infra_tag)
        rule.security_group = None
        rule.save()

        config_yaml = self._render(node)
        inbound_section = config_yaml.split('inbound:', 1)[1]

        # Explicit fragment: cidr: 10.0.0.0/8 and port 22
        self.assertIn('cidr: 10.0.0.0/8', inbound_section)
        self.assertIn('22', inbound_section)
        self.assertIn('tcp', inbound_section)
        # CIDR source must use Nebula's 'cidr:' key, NOT 'host:' (host never matches a CIDR)
        self.assertNotIn('host: 10.0.0.0/8', inbound_section)

    def test_inbound_node_source_renders_cidr_slash32(self):
        """
        direction='in' rule with source_nodes=[peer]: inbound must match that peer
        by its Nebula IP as a /32 via 'cidr:', NOT 'host:'.
        """
        from security_groups.models import Tag, FirewallRule
        app_tag = Tag.objects.create(name='app', organization=self.organization)
        node = self._make_node('app-node', '10.50.0.13')
        node.tags.add(app_tag)
        src = self._make_node('peer-node', '10.50.0.20')

        rule = FirewallRule(
            security_group=app_tag, protocol='tcp', port_min=443, port_max=443,
            direction='in', match_type='host')
        rule.save()
        rule.target_groups.add(app_tag)
        rule.source_nodes.add(src)
        rule.security_group = None
        rule.save()

        config_yaml = self._render(node)
        inbound_section = config_yaml.split('inbound:', 1)[1]

        self.assertIn('cidr: 10.50.0.20/32', inbound_section)
        self.assertNotIn('host: 10.50.0.20', inbound_section)

    def test_port_range_renders_min_max_string(self):
        """A TCP rule with port_min != port_max renders 'min-max'."""
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='range', organization=self.organization)
        node = self._make_node('range-node', '10.50.0.14')
        node.tags.add(tag)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=8000, port_max=8100,
                            direction='in', source_cidr='10.0.0.0/8', match_type='cidr')
        rule.save()
        rule.target_groups.add(tag)
        rule.security_group = None
        rule.save()
        inbound_section = self._render(node).split('inbound:', 1)[1]
        self.assertIn('8000-8100', inbound_section)
        self.assertIn('cidr: 10.0.0.0/8', inbound_section)

    def test_proto_any_rule_renders_any_port_any(self):
        """A protocol='any' rule renders proto: any / port: any with its source."""
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='anyp', organization=self.organization)
        node = self._make_node('any-node', '10.50.0.15')
        node.tags.add(tag)
        rule = FirewallRule(
            security_group=tag, protocol='any', direction='in',
            source_cidr='10.0.0.0/8', match_type='cidr')
        rule.save()
        rule.target_groups.add(tag)
        rule.security_group = None
        rule.save()
        inbound_section = self._render(node).split('inbound:', 1)[1]
        self.assertIn('proto: any', inbound_section)
        self.assertIn('cidr: 10.0.0.0/8', inbound_section)

    def test_authored_icmp_rule_renders_with_source(self):
        """An authored icmp rule (distinct from the seed) carries its source, no port."""
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='icmp-tgt', organization=self.organization)
        src = Tag.objects.create(name='icmp-src', organization=self.organization)
        node = self._make_node('icmp-node', '10.50.0.16')
        node.tags.add(tag)
        rule = FirewallRule(security_group=tag, protocol='icmp', direction='in', match_type='groups')
        rule.save()
        rule.target_groups.add(tag)
        rule.source_groups.add(src)
        rule.security_group = None
        rule.save()
        inbound_section = self._render(node).split('inbound:', 1)[1]
        self.assertIn('icmp-src', inbound_section)

    def test_node_direct_rule_renders(self):
        """A rule attached directly to a node (node FK) is resolved + rendered (cidr:/32 source)."""
        from security_groups.models import FirewallRule
        node = self._make_node('direct-node', '10.50.0.17')
        src = self._make_node('direct-src', '10.50.0.27')
        rule = FirewallRule(
            node=node, protocol='tcp', port_min=80, port_max=80,
            direction='in', match_type='host')
        rule.save()
        rule.source_nodes.add(src)
        rule.save()
        inbound_section = self._render(node).split('inbound:', 1)[1]
        self.assertIn('cidr: 10.50.0.27/32', inbound_section)
        self.assertIn('80', inbound_section)

    def test_inbound_match_type_any_renders_host_any(self):
        """A match_type='any' inbound rule renders an explicit Nebula host:any source."""
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='any-in', organization=self.organization)
        node = self._make_node('any-in-node', '10.50.0.18')
        node.tags.add(tag)
        rule = FirewallRule(
            security_group=tag,
            protocol='tcp',
            port_min=22,
            port_max=22,
            direction='in',
            match_type='any',
        )
        rule.save()
        rule.target_groups.add(tag)
        rule.security_group = None
        rule.save()

        inbound_section = self._render(node).split('inbound:', 1)[1]

        self.assertIn('port: 22', inbound_section)
        self.assertIn('proto: tcp', inbound_section)
        self.assertIn('host: any', inbound_section)

    def test_outbound_match_type_any_renders_allow_any_source(self):
        """A match_type='any' outbound rule produces allow-any egress, not an empty list."""
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='any-out', organization=self.organization)
        node = self._make_node('any-out-node', '10.50.0.19')
        node.tags.add(tag)
        rule = FirewallRule(
            security_group=tag,
            protocol='any',
            direction='out',
            match_type='any',
        )
        rule.save()
        rule.target_groups.add(tag)
        rule.security_group = None
        rule.save()

        outbound_section = self._render(node).split('outbound:', 1)[1].split('inbound:', 1)[0]

        self.assertIn('port: any', outbound_section)
        self.assertIn('proto: any', outbound_section)
        self.assertIn('host: any', outbound_section)

    def test_malformed_sourceless_rule_does_not_suppress_allow_all(self):
        """A non-any rule with no source is skipped without removing default allow-all."""
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='nosrc', organization=self.organization)
        node = self._make_node('nosrc-node', '10.50.0.28')
        node.tags.add(tag)
        rule = FirewallRule(
            security_group=tag,
            protocol='tcp',
            port_min=22,
            port_max=22,
            direction='in',
            match_type='groups',
        )
        rule.save()
        rule.target_groups.add(tag)  # target set, but NO source
        rule.security_group = None
        rule.save()
        inbound_section = self._render(node).split('inbound:', 1)[1]
        self.assertIn('proto: icmp', inbound_section)   # seed still present
        self.assertIn('port: any', inbound_section)     # allow-all still present
        self.assertNotIn('22', inbound_section)         # sourceless rule rendered nothing

    def test_node_with_no_applicable_rules_has_icmp_seed_and_allow_all(self):
        """
        A node with no applicable firewall rules must have BOTH the ICMP seed
        (proto: icmp, host: any) AND the default allow-all (port: any, proto: any,
        host: any) in the inbound section.
        """
        node = self._make_node('bare-node', '10.50.0.12')

        config_yaml = self._render(node)
        inbound_section = config_yaml.split('inbound:', 1)[1]

        # ICMP seed must be present
        self.assertIn('host: any', inbound_section)
        # Default allow-all must also be present (added when no explicit rules)
        self.assertIn('port: any', inbound_section)
        # Both 'host: any' entries — verify two distinct fragments co-exist
        self.assertIn('proto: icmp', inbound_section)
        self.assertIn('proto: any', inbound_section)


class PrepareNodePackageDirectionTests(TestCase):
    """Renderer must split applicable rules by direction into inbound/outbound."""

    def setUp(self):
        from organizations.models import Organization, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        self.owner = User.objects.create_user(email='direction@example.com', password='pw')
        self.organization = Organization.objects.create(name='Direction Org', created_by=self.owner)
        NetworkRange.objects.create(organization=self.organization, cidr='10.46.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.organization, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'ca-cert-bytes'),
            ca_key=SimpleUploadedFile('ca.key', b'ca-key-bytes'))
        self.node = Node.objects.create(
            name='n', organization=self.organization, certificate_authority=self.ca,
            nebula_ip='10.46.0.10', external_port=4242, created_by=self.owner)
        # _prepare_node_package reads cert/key from disk; seed them so the call
        # succeeds without certificate regeneration.
        self.node.cert_path.save('node.crt', SimpleUploadedFile('node.crt', b'node-cert'), save=False)
        self.node.key_path.save('node.key', SimpleUploadedFile('node.key', b'node-key'), save=True)

    def _cert_info(self):
        return {'details': {'groups': [], 'networks': [f'{self.node.nebula_ip}/24']}}

    def test_outbound_rule_renders_in_outbound_block(self):
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='db', organization=self.organization)
        self.node.tags.add(tag)
        out_rule = FirewallRule(
            security_group=tag, protocol='tcp', port_min=5432, port_max=5432,
            direction='out', source_cidr='10.0.0.0/8', match_type='cidr')
        out_rule.save()
        out_rule.target_groups.add(tag)
        out_rule.security_group = None
        out_rule.save()

        with patch.object(NodeRegistrationView, '_certificate_needs_regeneration', return_value=False):
            response = NodeRegistrationView()._prepare_node_package(self.node)

        config_yaml = response.data['config_yaml']

        # The explicit outbound rule must land in the outbound: block, carrying
        # port 5432 / proto tcp, and the bare allow-all must no longer be the
        # sole outbound entry (deny-by-default egress once authored).
        outbound_section = config_yaml.split('outbound:', 1)[1].split('inbound:', 1)[0]
        self.assertIn('5432', outbound_section)
        self.assertIn('tcp', outbound_section)
        # Allow-all egress was dropped: 'host: any' should not be the lone entry.
        self.assertNotIn("proto: any", outbound_section)

        # Inbound must NOT have picked up the outbound rule's port.
        inbound_section = config_yaml.split('inbound:', 1)[1]
        self.assertNotIn('5432', inbound_section)


class OrgNodeSecurityGroupsPageTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        self.owner = User.objects.create_user(email='sg-page@example.com', password='pw')
        self.org = Organization.objects.create(name='SG Page Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.70.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.node = Node.objects.create(
            name='page-node', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.70.0.10', external_port=4242, created_by=self.owner)
        self.client.force_login(self.owner)

    def test_per_node_security_groups_page_renders(self):
        # Both {% url %} tags sit inside guards: one in {% for group in
        # assigned_groups %} (node must have a tag), one in {% if security_groups %}
        # with an UNassigned tag. Create two tags and assign one so BOTH tags
        # render — otherwise the broken org_id= tag never executes (vacuous test).
        from security_groups.models import Tag
        assigned = Tag.objects.create(name='assigned-tag', organization=self.org)
        Tag.objects.create(name='unassigned-tag', organization=self.org)
        self.node.tags.add(assigned)

        url = reverse('nodes_org:assign_security_group', kwargs={'slug': self.org.slug, 'pk': self.node.id})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

        detail_url = reverse('nodes_org:detail', kwargs={'slug': self.org.slug, 'pk': self.node.id})
        legacy_url = f'/nodes/org/{self.org.id}/{self.node.id}/'
        self.assertContains(response, f'href="{detail_url}"')
        self.assertNotContains(response, f'href="{legacy_url}"')
