from .models import SSOConfiguration


def get_enforced_sso_config(user):
    """Return the enforced SSO config that blocks password login for this user."""
    if not user or not user.is_authenticated:
        return None
    return (
        SSOConfiguration.objects.filter(
            is_enabled=True,
            enforce_sso=True,
            organization__memberships__user=user,
        )
        .select_related('organization')
        .first()
    )


def get_password_login_block_message(sso_config):
    org = sso_config.organization
    return (
        f'Your organization "{org.name}" requires SSO login. '
        f'Use the SSO login with organization slug "{org.slug}".'
    )
