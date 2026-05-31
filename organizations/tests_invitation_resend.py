from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core import mail
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from organizations.emails import send_invitation_email
from organizations.models import Invitation, Membership, Organization


User = get_user_model()


@override_settings(
    BASE_URL="https://app.example.test",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="noreply@example.test",
)
class InvitationResendControlsTests(TestCase):
    password = "StrongPassword123!"

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.test",
            password=self.password,
        )
        self.organization = Organization.objects.create(
            name="Resend Org",
            created_by=self.owner,
        )
        Membership.objects.create(
            organization=self.organization,
            user=self.owner,
            role="owner",
        )
        self.invitation = Invitation.objects.create(
            organization=self.organization,
            email="invitee@example.test",
            inviter=self.owner,
            role="member",
        )

    def resend_url(self, invitation=None):
        invitation = invitation or self.invitation
        return reverse(
            "organizations:resend_invitation",
            kwargs={
                "slug": self.organization.slug,
                "invitation_id": invitation.id,
            },
        )

    def login_owner(self):
        self.client.force_login(self.owner)

    def test_organization_detail_renders_post_resend_form(self):
        self.login_owner()

        response = self.client.get(
            reverse("organizations:detail", kwargs={"slug": self.organization.slug})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'action="{self.resend_url()}"')
        self.assertContains(response, 'method="post"')
        self.assertContains(response, 'name="next"')
        self.assertContains(response, "Resend")
        self.assertNotContains(response, "response.json()")

    def test_members_partial_renders_htmx_resend_form(self):
        self.login_owner()

        response = self.client.get(
            reverse("organizations:members", kwargs={"slug": self.organization.slug}),
            {"partial": "1"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'action="{self.resend_url()}"')
        self.assertContains(response, f'hx-post="{self.resend_url()}"')
        self.assertContains(response, 'hx-target="#members-table"')
        self.assertContains(response, "Resend")
        self.assertNotContains(response, 'onclick="resendInvitation')

    def test_invitation_list_renders_resend_form_with_live_url(self):
        self.login_owner()

        response = self.client.get(
            reverse("organizations:invitation_list", kwargs={"slug": self.organization.slug})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, f'action="{self.resend_url()}"')
        self.assertContains(response, "Resend")

    def test_web_resend_extends_expiration_sends_email_and_returns_to_next(self):
        self.login_owner()
        original_expiration = self.invitation.expires_at
        next_url = reverse("organizations:detail", kwargs={"slug": self.organization.slug})
        mail.outbox.clear()

        response = self.client.post(self.resend_url(), {"next": next_url})

        self.assertRedirects(response, next_url)
        self.invitation.refresh_from_db()
        self.assertGreater(self.invitation.expires_at, original_expiration)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["invitee@example.test"])

    def test_invitation_email_uses_catalyst_workspace_copy(self):
        mail.outbox.clear()

        send_invitation_email(self.invitation)

        self.assertEqual(len(mail.outbox), 1)
        message = mail.outbox[0]
        html_body = message.alternatives[0][0]
        self.assertIn("Catalyst Networks workspace invitation", message.body)
        self.assertIn(
            "Catalyst Networks helps teams securely manage private network access",
            message.body,
        )
        self.assertIn("The Catalyst Networks Team", message.body)
        self.assertIn("Secure workspace access", html_body)


@override_settings(
    BASE_URL="https://app.example.test",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="noreply@example.test",
)
class InvitationAdminResendTests(TestCase):
    password = "StrongPassword123!"

    def setUp(self):
        self.operator = User.objects.create_superuser(
            email="ops@example.test",
            password=self.password,
        )
        self.organization = Organization.objects.create(
            name="Admin Resend Org",
            created_by=self.operator,
        )
        self.invitation = Invitation.objects.create(
            organization=self.organization,
            email="invitee@example.test",
            inviter=self.operator,
            role="owner",
        )
        self.client.force_login(self.operator)

    def test_admin_can_resend_selected_pending_invitations(self):
        changelist_url = reverse("admin:organizations_invitation_changelist")
        original_expiration = self.invitation.expires_at
        mail.outbox.clear()

        response = self.client.post(
            changelist_url,
            {
                "action": "resend_selected_invitations",
                "_selected_action": [str(self.invitation.pk)],
                "index": "0",
            },
            follow=True,
        )

        self.assertEqual(response.status_code, 200)
        self.invitation.refresh_from_db()
        self.assertGreater(self.invitation.expires_at, original_expiration)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, ["invitee@example.test"])
        self.assertContains(response, "Resent 1 invitation email.")

    def test_admin_action_is_registered(self):
        invitation_admin = admin.site._registry[Invitation]
        request = RequestFactory().get(reverse("admin:organizations_invitation_changelist"))
        request.user = self.operator

        self.assertIn(
            "resend_selected_invitations",
            invitation_admin.get_actions(request),
        )
