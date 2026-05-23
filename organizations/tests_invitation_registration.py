from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse

from organizations.models import Invitation, Membership, Organization


User = get_user_model()


@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
)
class InvitationRegistrationRoutingTests(TestCase):
    password = "StrongPassword123!"

    def setUp(self):
        self.owner = User.objects.create_user(
            email="owner@example.test",
            password=self.password,
        )
        self.organization = Organization.objects.create(
            name="Routing Org",
            created_by=self.owner,
        )
        Membership.objects.create(
            organization=self.organization,
            user=self.owner,
            role="owner",
        )

    def create_invitation(self, email="invitee@example.test", **overrides):
        invitation_attrs = {
            "organization": self.organization,
            "email": email,
            "inviter": self.owner,
            "role": "member",
        }
        invitation_attrs.update(overrides)
        return Invitation.objects.create(**invitation_attrs)

    def accept_url(self, invitation):
        return reverse(
            "organizations:invitation_accept",
            kwargs={"token": invitation.token},
        )

    def test_anonymous_valid_invitation_for_new_email_redirects_to_registration(self):
        invitation = self.create_invitation()
        expected_url = f"{reverse('register')}?{urlencode({'invitation': invitation.token})}"

        response = self.client.get(self.accept_url(invitation))

        self.assertRedirects(response, expected_url, fetch_redirect_response=False)

    def test_anonymous_valid_invitation_for_existing_email_redirects_to_login(self):
        invitation = self.create_invitation(email="existing@example.test")
        User.objects.create_user(
            email="EXISTING@example.test",
            password=self.password,
        )
        accept_url = self.accept_url(invitation)
        expected_url = f"{reverse('login')}?{urlencode({'next': accept_url})}"

        response = self.client.get(accept_url)

        self.assertRedirects(response, expected_url, fetch_redirect_response=False)

    def test_anonymous_invalid_invitation_redirects_to_login_without_membership(self):
        invitation = self.create_invitation(
            email="revoked@example.test",
            status="revoked",
        )

        response = self.client.get(self.accept_url(invitation))

        self.assertRedirects(response, reverse("login"), fetch_redirect_response=False)
        self.assertEqual(self.organization.memberships.count(), 1)

    def test_authenticated_matching_user_accepts_invitation_and_gets_membership(self):
        invitation = self.create_invitation(email="member@example.test")
        user = User.objects.create_user(
            email="member@example.test",
            password=self.password,
        )
        self.client.force_login(user)

        response = self.client.get(self.accept_url(invitation))

        self.assertRedirects(
            response,
            reverse("organizations:detail", kwargs={"slug": self.organization.slug}),
        )
        self.assertTrue(
            Membership.objects.filter(
                organization=self.organization,
                user=user,
                role="member",
            ).exists()
        )

    def test_authenticated_different_email_cannot_accept_invitation_without_membership(self):
        invitation = self.create_invitation(email="invitee@example.test")
        user = User.objects.create_user(
            email="other@example.test",
            password=self.password,
        )
        self.client.force_login(user)

        response = self.client.get(self.accept_url(invitation))

        self.assertRedirects(response, reverse("organizations:list"))
        self.assertFalse(
            Membership.objects.filter(
                organization=self.organization,
                user=user,
            ).exists()
        )
