from unittest import mock

from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from organizations.models import Membership, Organization

from .dispatch import dispatch_notification
from .models import NotificationIntegration


User = get_user_model()


@override_settings(**{"FIELD_ENCRYPTION_KEY": Fernet.generate_key().decode()})
class NotificationIntegrationTests(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(email="owner@example.com", password="testpass")
        self.member = User.objects.create_user(email="member@example.com", password="testpass")
        self.organization = Organization.objects.create(name="Notify Org", created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role="owner")
        Membership.objects.create(user=self.member, organization=self.organization, role="member")

    def enabled_slack_integration(self, events=None):
        integration = NotificationIntegration.objects.create(
            organization=self.organization,
            kind=NotificationIntegration.Kind.SLACK,
            events=events or ["node.registered"],
            active=True,
        )
        integration.set_secret_url("https://hooks.slack.com/services/T000/B000/secret")
        integration.save()
        return integration

    def test_slack_webhook_url_is_not_stored_plaintext(self):
        integration = NotificationIntegration.objects.create(
            organization=self.organization,
            kind=NotificationIntegration.Kind.SLACK,
        )

        integration.set_secret_url("https://hooks.slack.com/services/T000/B000/secret")
        integration.save()

        raw = NotificationIntegration.objects.filter(pk=integration.pk).values_list("secret_url", flat=True).get()
        self.assertNotIn("hooks.slack.com", raw)
        self.assertEqual(
            integration.get_secret_url(),
            "https://hooks.slack.com/services/T000/B000/secret",
        )

    @mock.patch("notifications.dispatch.requests.post")
    def test_dispatch_posts_slack_message(self, post):
        post.return_value.status_code = 200
        post.return_value.raise_for_status.return_value = None
        self.enabled_slack_integration()

        dispatch_notification(self.organization, "node.registered", {"node": "node-1"})

        self.assertTrue(post.called)
        args, kwargs = post.call_args
        self.assertEqual(args[0], "https://hooks.slack.com/services/T000/B000/secret")
        self.assertIn("node-1", kwargs["json"]["text"])

    @mock.patch("notifications.dispatch.requests.post")
    def test_dispatch_filters_inactive_and_unsubscribed_events(self, post):
        integration = self.enabled_slack_integration(events=["cert.expiring"])

        dispatch_notification(self.organization, "node.registered", {"node": "node-1"})
        integration.active = False
        integration.save(update_fields=["active"])
        dispatch_notification(self.organization, "cert.expiring", {"node": "node-1"})

        post.assert_not_called()

    def test_slack_webhook_url_is_not_displayed_in_ui(self):
        self.enabled_slack_integration()
        self.client.force_login(self.owner)

        response = self.client.get(reverse("notifications_org:slack", kwargs={"slug": self.organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, "https://hooks.slack.com/services/T000/B000/secret")
        self.assertContains(response, "Encrypted webhook saved")

    def test_org_member_cannot_manage_slack_notifications(self):
        self.client.force_login(self.member)

        response = self.client.get(reverse("notifications_org:slack", kwargs={"slug": self.organization.slug}))

        self.assertEqual(response.status_code, 403)
