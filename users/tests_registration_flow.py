from unittest.mock import patch
from urllib.parse import urlencode

from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone

from organizations.models import Invitation, Membership, Organization
from users.forms import UserRegistrationForm

User = get_user_model()


class RegistrationFlowTestMixin:
    password = 'ComplexPass123!'

    def registration_data(self, email='new-user@example.test', **overrides):
        data = {
            'email': email,
            'password1': self.password,
            'password2': self.password,
        }
        data.update(overrides)
        return data

    def create_user(self, email='existing@example.test', **extra_fields):
        return User.objects.create_user(
            email=email,
            password=self.password,
            **extra_fields,
        )

    def create_invitation(self, email='invitee@example.test', **overrides):
        inviter = self.create_user(email='owner@example.test')
        organization = Organization.objects.create(
            name='Invitation Org',
            created_by=inviter,
        )
        Membership.objects.create(
            user=inviter,
            organization=organization,
            role='owner',
        )
        invitation_attrs = {
            'organization': organization,
            'email': email,
            'inviter': inviter,
            'role': 'admin',
            'expires_at': timezone.now() + timezone.timedelta(days=1),
        }
        invitation_attrs.update(overrides)
        invitation = Invitation.objects.create(**invitation_attrs)
        return invitation


class UserRegistrationFormTests(RegistrationFlowTestMixin, TestCase):
    def test_bootstrap_mode_saves_first_user_as_staff_not_superuser(self):
        form = UserRegistrationForm(
            data=self.registration_data(),
            registration_mode='bootstrap',
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertTrue(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_public_mode_saves_active_non_staff_user(self):
        form = UserRegistrationForm(
            data=self.registration_data(),
            registration_mode='public',
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    def test_invitation_mode_uses_invitation_email_and_ignores_posted_email(self):
        invitation = self.create_invitation(email='invited@example.test')
        form = UserRegistrationForm(
            data=self.registration_data(email='posted@example.test'),
            registration_mode='invitation',
            invitation=invitation,
        )

        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()

        self.assertEqual(user.email, 'invited@example.test')
        self.assertFalse(User.objects.filter(email='posted@example.test').exists())


class RegisterViewTests(RegistrationFlowTestMixin, TestCase):
    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_zero_users_get_renders_bootstrap_registration(self):
        response = self.client.get(reverse('register'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['registration_state'].mode, 'bootstrap')
        self.assertContains(response, 'Create the first account')
        self.assertContains(response, 'Bootstrap administrator')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_bootstrap_post_creates_first_staff_user(self):
        response = self.client.post(
            reverse('register'),
            self.registration_data(email='bootstrap@example.test'),
        )

        self.assertRedirects(response, reverse('dashboard:dashboard'))
        user = User.objects.get(email='bootstrap@example.test')
        self.assertTrue(user.is_active)
        self.assertTrue(user.is_staff)
        self.assertFalse(user.is_superuser)

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_existing_user_get_renders_closed_registration(self):
        self.create_user()

        response = self.client.get(reverse('register'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['registration_state'].mode, 'closed')
        self.assertIsNone(response.context['form'])
        self.assertContains(response, 'Registration is closed')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_existing_user_post_does_not_create_user_when_closed(self):
        self.create_user()

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='blocked@example.test'),
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(User.objects.count(), 1)
        self.assertFalse(User.objects.filter(email='blocked@example.test').exists())
        self.assertContains(response, 'Registration is closed')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=True,
    )
    def test_public_setting_allows_normal_signup(self):
        self.create_user()

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='public@example.test'),
        )

        self.assertRedirects(response, reverse('dashboard:dashboard'))
        user = User.objects.get(email='public@example.test')
        self.assertTrue(user.is_active)
        self.assertFalse(user.is_staff)
        self.assertFalse(user.is_superuser)

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=False,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_bootstrap_disabled_closes_zero_user_register(self):
        response = self.client.get(reverse('register'))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['registration_state'].mode, 'closed')
        self.assertIsNone(response.context['form'])
        self.assertContains(response, 'Registration is closed')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_invitation_get_renders_locked_email_field(self):
        invitation = self.create_invitation(email='invited@example.test')

        response = self.client.get(
            reverse('register'),
            {'invitation': invitation.token},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['registration_state'].mode, 'invitation')
        self.assertContains(response, 'value="invited@example.test"')
        self.assertContains(response, 'readonly')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_invitation_post_accepts_invitation_for_created_user(self):
        invitation = self.create_invitation(email='invited@example.test')

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='posted@example.test', invitation=invitation.token),
        )

        self.assertRedirects(response, reverse('dashboard:dashboard'))
        user = User.objects.get(email='invited@example.test')
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'accepted')
        self.assertTrue(
            Membership.objects.filter(
                organization=invitation.organization,
                user=user,
                role='admin',
            ).exists()
        )

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_expired_invitation_post_does_not_create_user(self):
        invitation = self.create_invitation(
            email='expired@example.test',
            expires_at=timezone.now() - timezone.timedelta(days=1),
        )

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='posted@example.test', invitation=invitation.token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email='expired@example.test').exists())
        self.assertFalse(User.objects.filter(email='posted@example.test').exists())
        self.assertContains(response, 'Registration is closed')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_revoked_invitation_post_does_not_create_user(self):
        invitation = self.create_invitation(
            email='revoked@example.test',
            status='revoked',
        )

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='posted@example.test', invitation=invitation.token),
        )

        self.assertEqual(response.status_code, 200)
        self.assertFalse(User.objects.filter(email='revoked@example.test').exists())
        self.assertFalse(User.objects.filter(email='posted@example.test').exists())
        self.assertContains(response, 'Registration is closed')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_exact_duplicate_invited_account_redirects_to_login(self):
        invitation = self.create_invitation(email='invited@example.test')
        self.create_user(email='invited@example.test')
        accept_path = reverse(
            'organizations:invitation_accept',
            kwargs={'token': invitation.token},
        )
        expected_redirect = f"{reverse('login')}?{urlencode({'next': accept_path})}"

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='posted@example.test', invitation=invitation.token),
        )

        self.assertRedirects(response, expected_redirect, fetch_redirect_response=False)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'pending')
        self.assertEqual(User.objects.filter(email__iexact='invited@example.test').count(), 1)

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_case_only_duplicate_invited_account_redirects_to_login(self):
        invitation = self.create_invitation(email='invited@example.test')
        self.create_user(email='INVITED@example.test')
        accept_path = reverse(
            'organizations:invitation_accept',
            kwargs={'token': invitation.token},
        )
        expected_redirect = f"{reverse('login')}?{urlencode({'next': accept_path})}"

        response = self.client.post(
            reverse('register'),
            self.registration_data(email='posted@example.test', invitation=invitation.token),
        )

        self.assertRedirects(response, expected_redirect, fetch_redirect_response=False)
        invitation.refresh_from_db()
        self.assertEqual(invitation.status, 'pending')
        self.assertEqual(User.objects.filter(email__iexact='invited@example.test').count(), 1)

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_invitation_accept_returning_none_rolls_back_user_creation(self):
        invitation = self.create_invitation(email='invited@example.test')

        with patch.object(Invitation, 'accept', return_value=None):
            response = self.client.post(
                reverse('register'),
                self.registration_data(email='posted@example.test', invitation=invitation.token),
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context['registration_state'].mode, 'closed')
        self.assertFalse(User.objects.filter(email='invited@example.test').exists())
        self.assertNotIn('_auth_user_id', self.client.session)


class LoginPromptTests(RegistrationFlowTestMixin, TestCase):
    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_login_shows_create_one_before_bootstrap(self):
        response = self.client.get(reverse('login'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create one')
        self.assertNotContains(response, 'Ask an organization owner for an invitation.')

    @override_settings(
        ALLOW_BOOTSTRAP_REGISTRATION=True,
        ALLOW_PUBLIC_REGISTRATION=False,
    )
    def test_login_hides_create_one_after_user_exists(self):
        self.create_user()

        response = self.client.get(reverse('login'))

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create one')
        self.assertContains(response, 'Need access? Ask an organization owner for an invitation.')


class LoginNextTests(RegistrationFlowTestMixin, TestCase):
    def test_internal_next_survives_post_and_redirects_after_login(self):
        self.create_user(email='user@example.test')

        get_response = self.client.get(reverse('login'), {'next': reverse('profile')})

        self.assertContains(get_response, f'name="next" value="{reverse("profile")}"')

        post_response = self.client.post(
            reverse('login'),
            {
                'email': 'user@example.test',
                'password': self.password,
                'next': reverse('profile'),
            },
        )

        self.assertRedirects(post_response, reverse('profile'))

    def test_external_next_falls_back_to_dashboard_after_login(self):
        self.create_user(email='user@example.test')

        response = self.client.post(
            reverse('login'),
            {
                'email': 'user@example.test',
                'password': self.password,
                'next': 'https://evil.example/phish',
            },
        )

        self.assertRedirects(response, reverse('dashboard:dashboard'))
