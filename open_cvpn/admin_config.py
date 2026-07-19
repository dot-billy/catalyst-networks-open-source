"""Conditional TOTP enforcement for the Django admin."""

from django.conf import settings
from django.contrib import admin
from django_otp.admin import OTPAdminSite


def configure_admin_site():
    """Switch the existing admin site to OTP enforcement when configured."""
    if settings.ADMIN_REQUIRE_OTP:
        admin.site.__class__ = OTPAdminSite
