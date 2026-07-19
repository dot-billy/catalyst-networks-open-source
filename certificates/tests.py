import os
import tempfile
from contextlib import contextmanager
from types import SimpleNamespace
from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.storage import FileSystemStorage
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from certificates.models import CertificateAuthority
from nodes.models import Node
from organizations.models import Membership, NetworkRange, Organization

from .tasks import check_expiring_certificates


User = get_user_model()


@contextmanager
def temporary_certificate_storage():
    cert_field = CertificateAuthority._meta.get_field('ca_cert')
    key_field = CertificateAuthority._meta.get_field('ca_key')
    original_cert_storage = cert_field.storage
    original_key_storage = key_field.storage
    with tempfile.TemporaryDirectory() as cert_root:
        storage = FileSystemStorage(location=cert_root)
        cert_field.storage = storage
        key_field.storage = storage
        try:
            with override_settings(CERT_STORAGE_ROOT=cert_root, CERT_STORAGE=storage):
                yield
        finally:
            cert_field.storage = original_cert_storage
            key_field.storage = original_key_storage


class CertificateNotificationTaskTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email="cert-owner@example.com", password="testpass")
        self.organization = Organization.objects.create(name="Cert Notify Org", created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role="owner")
        NetworkRange.objects.create(
            organization=self.organization,
            cidr="10.55.0.0/24",
            description="test range",
        )
        self.ca = CertificateAuthority.objects.create(
            name="Notify CA",
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile("notify-ca.crt", b"certificate-bytes"),
            ca_key=SimpleUploadedFile("notify-ca.key", b"key-bytes"),
        )

    @mock.patch("notifications.dispatch.queue_notification_event")
    def test_expiring_certificate_notification_queues_slack_even_without_webhooks(self, dispatch_event):
        Node.objects.create(
            name="expiring-node",
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip="10.55.0.10",
            created_by=self.owner,
            cert_expiration=timezone.now() + timezone.timedelta(days=5),
        )

        check_expiring_certificates()

        dispatch_event.assert_called_once()
        event_type, organization_id, payload = dispatch_event.call_args.args
        self.assertEqual(event_type, "cert.expiring")
        self.assertEqual(organization_id, self.organization.id)
        self.assertEqual(payload["count"], 1)
        self.assertEqual(payload["expiring_certificates"][0]["node_name"], "expiring-node")


class CertificateAuthorityCreateViewTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='ca-create-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='CA Create Org', created_by=self.user)
        Membership.objects.create(user=self.user, organization=self.organization, role='owner')
        self.client.force_login(self.user)

    def test_org_create_redirects_to_org_scoped_ca_detail(self):
        def fake_nebula_ca_run(cmd, **kwargs):
            cert_path = cmd[cmd.index('-out-crt') + 1]
            key_path = cmd[cmd.index('-out-key') + 1]
            os.makedirs(os.path.dirname(cert_path), exist_ok=True)
            with open(cert_path, 'wb') as cert_file:
                cert_file.write(b'ca-cert')
            with open(key_path, 'wb') as key_file:
                key_file.write(b'ca-key')
            return SimpleNamespace(stdout='')

        with temporary_certificate_storage(), mock.patch(
            'certificates.views.subprocess.run', side_effect=fake_nebula_ca_run
        ):
            response = self.client.post(
                reverse('certificates_org:create', kwargs={'slug': self.organization.slug}),
                {
                    'name': 'New Root CA',
                    'common_name': 'ca-create.example.test',
                    'validity_days': '365',
                },
            )

        ca = CertificateAuthority.objects.get(organization=self.organization, name='New Root CA')
        self.assertRedirects(
            response,
            reverse(
                'certificates_org:detail',
                kwargs={'slug': self.organization.slug, 'pk': ca.id},
            ),
            fetch_redirect_response=False,
        )
