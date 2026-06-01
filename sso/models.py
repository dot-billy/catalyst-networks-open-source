from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords


class SSOConfiguration(models.Model):
    """Per-organization SSO configuration."""

    PROVIDER_SAML = 'saml'
    PROVIDER_OIDC = 'oidc'
    PROVIDER_CHOICES = [
        (PROVIDER_SAML, 'SAML'),
        (PROVIDER_OIDC, 'OIDC / Google'),
    ]

    OIDC_GOOGLE = 'google'
    OIDC_GENERIC = 'generic'
    OIDC_MODE_CHOICES = [
        (OIDC_GOOGLE, 'Google Workspace'),
        (OIDC_GENERIC, 'Generic OIDC'),
    ]

    organization = models.OneToOneField(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='sso_config',
    )
    is_enabled = models.BooleanField(
        default=False,
        help_text='Enable SAML SSO for this organization',
    )
    enforce_sso = models.BooleanField(
        default=False,
        help_text='When enabled, members must use SSO (password login disabled)',
    )
    provider_type = models.CharField(
        max_length=20,
        choices=PROVIDER_CHOICES,
        default=PROVIDER_SAML,
    )

    # Identity Provider (IdP) settings
    idp_entity_id = models.CharField(
        max_length=512,
        blank=True,
        default='',
        help_text='IdP Entity ID (Issuer URL)',
    )
    idp_sso_url = models.URLField(
        max_length=512,
        blank=True,
        default='',
        help_text='IdP Single Sign-On URL',
    )
    idp_slo_url = models.URLField(
        max_length=512,
        blank=True,
        default='',
        help_text='IdP Single Logout URL (optional)',
    )
    idp_x509_cert = models.TextField(
        blank=True,
        default='',
        help_text='IdP X.509 certificate (PEM format, without header/footer)',
    )

    # OIDC / Google Workspace settings
    oidc_mode = models.CharField(
        max_length=20,
        choices=OIDC_MODE_CHOICES,
        blank=True,
        default='',
    )
    oidc_display_name = models.CharField(max_length=40, blank=True)
    oidc_issuer_url = models.URLField(blank=True)
    oidc_client_id = models.CharField(max_length=191, blank=True)
    oidc_client_secret_encrypted = models.TextField(blank=True)
    oidc_provider_id = models.SlugField(max_length=260, blank=True)
    oidc_allowed_domain = models.CharField(max_length=255, blank=True)
    oidc_scopes = models.CharField(max_length=255, default='openid email profile')
    oidc_email_claim = models.CharField(max_length=80, default='email')
    oidc_first_name_claim = models.CharField(max_length=80, default='given_name')
    oidc_last_name_claim = models.CharField(max_length=80, default='family_name')
    oidc_subject_claim = models.CharField(max_length=80, default='sub')
    allauth_app_id = models.PositiveIntegerField(null=True, blank=True)

    # Attribute mapping
    attribute_email = models.CharField(
        max_length=255,
        default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
        help_text='SAML attribute for user email',
    )
    attribute_first_name = models.CharField(
        max_length=255,
        default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
        blank=True,
        help_text='SAML attribute for first name',
    )
    attribute_last_name = models.CharField(
        max_length=255,
        default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
        blank=True,
        help_text='SAML attribute for last name',
    )

    # Auto-provisioning
    auto_create_users = models.BooleanField(
        default=True,
        help_text='Automatically create user accounts on first SSO login',
    )
    default_role = models.CharField(
        max_length=10,
        choices=[
            ('member', 'Member'),
            ('admin', 'Admin'),
        ],
        default='member',
        help_text='Default role for auto-provisioned users',
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'SSO Configuration'
        verbose_name_plural = 'SSO Configurations'

    def __str__(self):
        status = 'enabled' if self.is_enabled else 'disabled'
        return f"SSO for {self.organization.name} ({status})"

    @property
    def is_saml(self):
        return self.provider_type == self.PROVIDER_SAML

    @property
    def is_oidc(self):
        return self.provider_type == self.PROVIDER_OIDC

    def set_oidc_client_secret(self, secret):
        from .services import encrypt_secret

        self.oidc_client_secret_encrypted = encrypt_secret(secret)

    def get_oidc_client_secret(self):
        from .services import decrypt_secret

        return decrypt_secret(self.oidc_client_secret_encrypted)
