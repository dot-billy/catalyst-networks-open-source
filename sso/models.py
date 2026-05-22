from django.db import models
from django.utils import timezone
from simple_history.models import HistoricalRecords


class SSOConfiguration(models.Model):
    """Per-organization SAML SSO configuration."""

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

    # Identity Provider (IdP) settings
    idp_entity_id = models.CharField(
        max_length=512,
        help_text='IdP Entity ID (Issuer URL)',
    )
    idp_sso_url = models.URLField(
        max_length=512,
        help_text='IdP Single Sign-On URL',
    )
    idp_slo_url = models.URLField(
        max_length=512,
        blank=True,
        default='',
        help_text='IdP Single Logout URL (optional)',
    )
    idp_x509_cert = models.TextField(
        help_text='IdP X.509 certificate (PEM format, without header/footer)',
    )

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
