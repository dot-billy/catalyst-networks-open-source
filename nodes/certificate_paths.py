import secrets

from django.utils import timezone


def unique_certificate_stem(name, *, now=None):
    timestamp = (now or timezone.now()).strftime("%Y%m%dT%H%M%SZ")
    return f"{name}-{timestamp}-{secrets.token_hex(4)}"
