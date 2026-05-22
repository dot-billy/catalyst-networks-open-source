from django.conf import settings
from django.db import models

from organizations.models import Organization


class EventType(models.TextChoices):
    NODE_REGISTERED = "node.registered", "Node Registered"
    NODE_CREATED = "node.created", "Node Created"
    NODE_REVOKED = "node.revoked", "Node Revoked"
    CERT_ISSUED = "cert.issued", "Certificate Issued"
    CERT_RENEWED = "cert.renewed", "Certificate Renewed"
    CERT_REVOKED = "cert.revoked", "Certificate Revoked"
    CERT_EXPIRING = "cert.expiring", "Certificate Expiring Soon"
    IP_ALLOCATED = "ip.allocated", "IP Allocated"


def default_notification_events():
    return [event.value for event in EventType]


class NotificationIntegration(models.Model):
    """Organization-wide notification delivery integration."""

    class Kind(models.TextChoices):
        SLACK = "slack", "Slack"

    Provider = Kind

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="notification_integrations",
    )
    kind = models.CharField(max_length=30, choices=Kind.choices)
    secret_url = models.TextField(blank=True)
    events = models.JSONField(default=default_notification_events)
    active = models.BooleanField(default=False)
    last_delivery_at = models.DateTimeField(null=True, blank=True)
    last_delivery_status = models.IntegerField(null=True, blank=True)
    last_delivery_error = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["kind"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "kind"],
                name="unique_org_notification_kind",
            ),
        ]

    def __str__(self):
        status = "active" if self.active else "inactive"
        return f"{self.organization.name} {self.get_kind_display()} ({status})"

    def set_secret_url(self, webhook_url):
        from .crypto import encrypt_value

        self.secret_url = encrypt_value((webhook_url or "").strip())

    def get_secret_url(self):
        from .crypto import decrypt_value

        return decrypt_value(self.secret_url)

    def set_webhook_url(self, webhook_url):
        self.set_secret_url(webhook_url)

    def get_webhook_url(self):
        return self.get_secret_url()

    @property
    def has_webhook_url(self):
        return bool(self.secret_url)


class NotificationPreference(models.Model):
    """Per-user, per-organization notification preferences."""

    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name="notification_preferences",
    )
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name="notification_preferences",
    )
    event_type = models.CharField(max_length=50, choices=EventType.choices)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["event_type"]
        constraints = [
            models.UniqueConstraint(
                fields=["user", "organization", "event_type"],
                name="unique_user_org_notification_preference",
            ),
        ]

    def __str__(self):
        status = "on" if self.enabled else "off"
        return f"{self.user} | {self.organization.name} | {self.event_type} ({status})"
