from dataclasses import dataclass

from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils import timezone

from organizations.models import Invitation


@dataclass
class RegistrationState:
    mode: str
    can_register: bool
    title: str
    subtitle: str
    submit_label: str = 'Create account'
    invitation: Invitation | None = None


def get_valid_registration_invitation(invitation_token):
    if not invitation_token:
        return None

    return (
        Invitation.objects.select_related('organization', 'inviter')
        .filter(
            token=invitation_token,
            status='pending',
            expires_at__gt=timezone.now(),
        )
        .first()
    )


def get_registration_state(invitation_token=None):
    invitation = get_valid_registration_invitation(invitation_token)
    if invitation:
        return RegistrationState(
            mode='invitation',
            can_register=True,
            title=f'Join {invitation.organization.name}',
            subtitle='Create an account to accept your invitation.',
            submit_label='Create account and join',
            invitation=invitation,
        )

    if settings.ALLOW_PUBLIC_REGISTRATION:
        return RegistrationState(
            mode='public',
            can_register=True,
            title='Create your account',
            subtitle='Registration is open for this server.',
        )

    User = get_user_model()
    if settings.ALLOW_BOOTSTRAP_REGISTRATION and not User.objects.exists():
        return RegistrationState(
            mode='bootstrap',
            can_register=True,
            title='Create the first account',
            subtitle='No users exist yet. Use this form to bootstrap access.',
        )

    return RegistrationState(
        mode='closed',
        can_register=False,
        title='Registration is closed',
        subtitle='Ask an administrator for an invitation.',
    )


def public_signup_link_available():
    return get_registration_state().mode in {'bootstrap', 'public'}
