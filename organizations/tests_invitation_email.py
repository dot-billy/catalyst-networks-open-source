from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings

from organizations.emails import send_invitation_email
from organizations.models import Invitation, Membership, Organization


User = get_user_model()


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="noreply@example.test",
    BASE_URL="https://app.example.test",
)
class InvitationEmailTests(TestCase):
    def setUp(self):
        self.inviter = User.objects.create_user(
            email="owner@example.test",
            password="testpass",
        )
        self.organization = Organization.objects.create(
            name="Example Org",
            created_by=self.inviter,
        )
        Membership.objects.create(
            user=self.inviter,
            organization=self.organization,
            role="owner",
        )

    def test_invitation_email_uses_configured_django_mail_backend(self):
        invitation = Invitation.objects.create(
            organization=self.organization,
            email="invitee@example.test",
            inviter=self.inviter,
            role="member",
        )

        send_invitation_email(invitation)

        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        self.assertEqual(message.from_email, "noreply@example.test")
        self.assertEqual(message.to, ["invitee@example.test"])
        self.assertIn("Example Org", message.subject)
        self.assertIn(
            f"https://app.example.test/organizations/invitations/accept/{invitation.token}/",
            message.body,
        )
