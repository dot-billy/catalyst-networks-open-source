from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import TestCase
from django.utils import timezone

from certificates.models import CertificateAuthority
from nodes.models import Node
from organizations.models import Membership, NetworkRange, Organization

from .tasks import check_expiring_certificates


User = get_user_model()


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
