"""Provision or reset a confirmed TOTP device for an admin user."""

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django_otp.plugins.otp_totp.models import TOTPDevice


class Command(BaseCommand):
    help = "Create (or --reset) a confirmed TOTP device and print its otpauth URL."

    def add_arguments(self, parser):
        parser.add_argument('email', help='Email (USERNAME_FIELD) of the user to enroll')
        parser.add_argument(
            '--reset',
            action='store_true',
            help='Delete any existing TOTP devices for the user first',
        )

    def handle(self, *args, **options):
        user_model = get_user_model()
        lookup = {user_model.USERNAME_FIELD: options['email']}
        try:
            user = user_model.objects.get(**lookup)
        except user_model.DoesNotExist as exc:
            raise CommandError(
                f"No user with {user_model.USERNAME_FIELD}={options['email']!r}"
            ) from exc

        existing = TOTPDevice.objects.filter(user=user)
        if existing.exists() and not options['reset']:
            raise CommandError(
                f"{options['email']} already has a TOTP device; pass --reset to replace it"
            )

        with transaction.atomic():
            existing.delete()
            device = TOTPDevice.objects.create(user=user, name='default', confirmed=True)

        self.stdout.write(self.style.SUCCESS(f"TOTP device created for {options['email']}"))
        self.stdout.write(device.config_url)
