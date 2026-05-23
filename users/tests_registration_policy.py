from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.utils import timezone

from organizations.models import Invitation, Membership, Organization
from users.registration_policy import (
    get_registration_state,
    get_valid_registration_invitation,
    public_signup_link_available,
)

User = get_user_model()


class RegistrationPolicyTests(TestCase):
    def create_existing_user(self, email='existing@example.test'):
        return User.objects.create_user(email=email, password='testpass123')

    def create_invitation(self, *, expires_at=None):
        inviter = self.create_existing_user(email='inviter@example.test')
        organization = Organization.objects.create(
            name='Invitation Org',
            created_by=inviter,
        )
        Membership.objects.create(
            user=inviter,
            organization=organization,
            role='owner',
        )
        return Invitation.objects.create(
            organization=organization,
            email='invitee@example.test',
            inviter=inviter,
            expires_at=expires_at or timezone.now() + timezone.timedelta(days=1),
        )

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_bootstrap_available_when_no_users_exist(self):
        state = get_registration_state()

        self.assertEqual(state.mode, 'bootstrap')
        self.assertTrue(state.can_register)
        self.assertIsNone(state.invitation)
        self.assertTrue(public_signup_link_available())

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_registration_closed_after_any_user_exists(self):
        self.create_existing_user()

        state = get_registration_state()

        self.assertEqual(state.mode, 'closed')
        self.assertFalse(state.can_register)
        self.assertFalse(public_signup_link_available())

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=False,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_bootstrap_can_be_disabled_even_with_no_users(self):
        state = get_registration_state()

        self.assertEqual(state.mode, 'closed')
        self.assertFalse(state.can_register)
        self.assertFalse(public_signup_link_available())

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=True,
    )
    def test_public_registration_setting_allows_public_mode_after_existing_user(self):
        self.create_existing_user()

        state = get_registration_state()

        self.assertEqual(state.mode, 'public')
        self.assertTrue(state.can_register)
        self.assertTrue(public_signup_link_available())

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_valid_invitation_allows_invitation_mode(self):
        invitation = self.create_invitation()

        valid_invitation = get_valid_registration_invitation(invitation.token)
        state = get_registration_state(invitation.token)

        self.assertEqual(valid_invitation, invitation)
        self.assertEqual(state.mode, 'invitation')
        self.assertTrue(state.can_register)
        self.assertEqual(state.submit_label, 'Create account and join')
        self.assertEqual(state.invitation, invitation)

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=True,
    )
    def test_valid_invitation_takes_precedence_when_public_registration_is_also_true(self):
        invitation = self.create_invitation()

        state = get_registration_state(invitation.token)

        self.assertEqual(state.mode, 'invitation')
        self.assertTrue(state.can_register)
        self.assertEqual(state.submit_label, 'Create account and join')
        self.assertEqual(state.invitation, invitation)

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_expired_invitation_does_not_allow_registration(self):
        invitation = self.create_invitation(
            expires_at=timezone.now() - timezone.timedelta(days=1),
        )

        valid_invitation = get_valid_registration_invitation(invitation.token)
        state = get_registration_state(invitation.token)

        self.assertIsNone(valid_invitation)
        self.assertEqual(state.mode, 'closed')
        self.assertFalse(state.can_register)
