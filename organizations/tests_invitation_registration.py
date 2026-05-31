from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import TestCase, override_settings
from django.urls import reverse

from organizations.emails import send_invitation_email
from organizations.models import Invitation, Membership, Organization


User = get_user_model()


@override_settings(
    ALLOW_PUBLIC_REGISTRATION=False,
    ALLOW_BOOTSTRAP_REGISTRATION=True,
    BASE_URL="https://app.example.test",
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
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

    def registration_data(self, invitation, **overrides):
        data = {
            "invitation": invitation.token,
            "email": "posted@example.test",
            "password1": self.password,
            "password2": self.password,
        }
        data.update(overrides)
        return data

    def email_accept_url(self, invitation):
        send_invitation_email(invitation)

        self.assertEqual(len(mail.outbox), 1)
        accept_url = self.accept_url(invitation)
        full_accept_url = f"https://app.example.test{accept_url}"
        self.assertIn(full_accept_url, mail.outbox[0].body)
        return accept_url

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

    def test_email_link_drives_new_user_registration_and_invitation_acceptance(self):
        invitation = self.create_invitation(email="invitee@example.test")
        accept_url = self.email_accept_url(invitation)

        accept_response = self.client.get(accept_url)

        self.assertRedirects(
            accept_response,
            f"{reverse('register')}?{urlencode({'invitation': invitation.token})}",
            fetch_redirect_response=False,
        )

        form_response = self.client.get(
            reverse("register"),
            {"invitation": invitation.token},
        )
        self.assertEqual(form_response.status_code, 200)
        self.assertContains(form_response, "Join Routing Org")
        self.assertContains(form_response, "Create an account to accept your invitation.")
        self.assertContains(form_response, 'value="invitee@example.test"')
        self.assertContains(form_response, "readonly")
        self.assertContains(form_response, "Create account and join")

        response = self.client.post(reverse("register"), self.registration_data(invitation))

        self.assertRedirects(response, reverse("dashboard:dashboard"))
        user = User.objects.get(email="invitee@example.test")
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, "accepted")
        self.assertFalse(User.objects.filter(email="posted@example.test").exists())
        self.assertTrue(
            Membership.objects.filter(
                organization=self.organization,
                user=user,
                role="member",
            ).exists()
        )
        self.assertEqual(str(self.client.session["_auth_user_id"]), str(user.pk))

    def test_email_link_drives_existing_user_login_and_invitation_acceptance(self):
        invitation = self.create_invitation(email="member@example.test")
        User.objects.create_user(
            email="member@example.test",
            password=self.password,
        )
        accept_url = self.email_accept_url(invitation)

        accept_response = self.client.get(accept_url)

        self.assertRedirects(
            accept_response,
            f"{reverse('login')}?{urlencode({'next': accept_url})}",
            fetch_redirect_response=False,
        )

        login_response = self.client.get(reverse("login"), {"next": accept_url})
        self.assertContains(login_response, f'name="next" value="{accept_url}"')

        response = self.client.post(
            reverse("login"),
            {
                "email": "member@example.test",
                "password": self.password,
                "next": accept_url,
            },
            follow=True,
        )

        self.assertIn((accept_url, 302), response.redirect_chain)
        self.assertEqual(response.request["PATH_INFO"], f"/organizations/{self.organization.slug}/")
        self.assertTrue(
            Membership.objects.filter(
                organization=self.organization,
                user__email="member@example.test",
                role="member",
            ).exists()
        )

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
