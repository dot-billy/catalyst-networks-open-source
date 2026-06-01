from dataclasses import dataclass
import hashlib

from cryptography.fernet import Fernet
from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.exceptions import ImproperlyConfigured

from organizations.models import Membership


class SSOLoginRejected(Exception):
    pass


@dataclass(frozen=True)
class SSOLoginIdentity:
    email: str
    subject: str
    provider: str
    first_name: str = ''
    last_name: str = ''


def _get_field_fernet():
    key = getattr(settings, 'FIELD_ENCRYPTION_KEY', '')
    if not key:
        raise ImproperlyConfigured('FIELD_ENCRYPTION_KEY is required to encrypt SSO client secrets.')
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_secret(secret):
    if not secret:
        return ''
    return _get_field_fernet().encrypt(secret.encode()).decode()


def decrypt_secret(encrypted_secret):
    if not encrypted_secret:
        return ''
    return _get_field_fernet().decrypt(encrypted_secret.encode()).decode()


def oidc_scope_list(config):
    scopes = [scope for scope in (config.oidc_scopes or '').split() if scope]
    return scopes or ['openid', 'email', 'profile']


def oidc_provider_id_for_config(config):
    provider_id = f'org-{config.organization.slug}'
    if len(provider_id) <= 200:
        return provider_id
    digest = hashlib.sha256(provider_id.encode()).hexdigest()[:12]
    return f'{provider_id[:187]}-{digest}'


def complete_sso_login(config, identity):
    email = (identity.email or '').lower().strip()
    if not email:
        raise SSOLoginRejected('No email address received from identity provider.')

    if config.is_oidc and config.oidc_allowed_domain:
        domain = email.rsplit('@', 1)[-1]
        if domain.lower() != config.oidc_allowed_domain.lower().strip():
            raise SSOLoginRejected('Email domain is not allowed for this SSO provider.')

    User = get_user_model()
    org = config.organization
    user = User.objects.filter(email__iexact=email).first()
    created_user = False

    if user is None:
        if not config.auto_create_users:
            raise SSOLoginRejected('No account found for this email.')
        user = User.objects.create_user(
            email=email,
            first_name=identity.first_name or '',
            last_name=identity.last_name or '',
        )
        user.set_unusable_password()
        user.save(update_fields=['password'])
        created_user = True
    elif not Membership.objects.filter(user=user, organization=org).exists():
        raise SSOLoginRejected('Existing user is not a member of this organization.')

    if not user.is_active:
        raise SSOLoginRejected('User account is inactive.')

    updated_fields = []
    if identity.first_name and not user.first_name:
        user.first_name = identity.first_name
        updated_fields.append('first_name')
    if identity.last_name and not user.last_name:
        user.last_name = identity.last_name
        updated_fields.append('last_name')
    if updated_fields:
        user.save(update_fields=updated_fields)

    if created_user:
        Membership.objects.create(
            user=user,
            organization=org,
            role=config.default_role,
        )

    return user


def sync_allauth_app_for_config(config):
    if not config.is_oidc:
        raise ValueError('Only OIDC SSO configurations can sync allauth SocialApps.')

    from allauth.socialaccount.models import SocialApp
    from django.contrib.sites.models import Site

    if config.oidc_mode == config.OIDC_GOOGLE:
        provider = 'google'
        provider_id = ''
        app_settings = {
            'scope': oidc_scope_list(config),
        }
        name = config.oidc_display_name or f'{config.organization.name} Google Workspace'
    else:
        provider = 'openid_connect'
        provider_id = config.oidc_provider_id or oidc_provider_id_for_config(config)
        app_settings = {
            'server_url': config.oidc_issuer_url,
            'scope': oidc_scope_list(config),
            'fetch_userinfo': True,
            'oauth_pkce_enabled': True,
            'uid_field': config.oidc_subject_claim,
        }
        name = config.oidc_display_name or f'{config.organization.name} OIDC'

    app = None
    if config.allauth_app_id:
        app = SocialApp.objects.filter(pk=config.allauth_app_id).first()
    if app is None and provider_id:
        app = SocialApp.objects.filter(provider=provider, provider_id=provider_id).first()
    if app is None:
        app = SocialApp()

    app.provider = provider
    app.provider_id = provider_id
    app.name = name[:40]
    app.client_id = config.oidc_client_id
    app.secret = ''
    app.settings = app_settings
    app.save()
    app.sites.set([Site.objects.get_current()])

    config.allauth_app_id = app.id
    config.oidc_provider_id = provider_id
    config.save(update_fields=['allauth_app_id', 'oidc_provider_id'])
    return app
