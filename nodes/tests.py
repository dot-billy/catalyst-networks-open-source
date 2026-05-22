import io
import json
import os
import subprocess
import zipfile
from datetime import timezone as datetime_timezone
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework.response import Response
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
