from django.db import models
from organizations.models import Organization
from simple_history.models import HistoricalRecords

class Webhook(models.Model):
    """
    Model for managing webhook subscriptions to system events.
    """
    EVENT_CHOICES = [
        ('node.created', 'Node Created'),
        ('node.revoked', 'Node Revoked'),
        ('cert.issued', 'Certificate Issued'),
        ('cert.revoked', 'Certificate Revoked'),
        ('cert.expiring', 'Certificate Expiring Soon'),
        ('ip.allocated', 'IP Allocated'),
    ]

    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='webhooks'
    )
    url = models.URLField()
    events = models.JSONField(
        help_text='List of events this webhook is subscribed to'
    )
    description = models.TextField(blank=True, help_text='Optional description of the webhook')
    secret = models.CharField(max_length=255, blank=True, help_text='Optional secret for webhook authentication')
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_delivery = models.DateTimeField(null=True, blank=True)
    last_delivery_status = models.IntegerField(null=True, blank=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Webhook'
        verbose_name_plural = 'Webhooks'
        ordering = ['-created_at']

    def __str__(self):
        return f"Webhook for {self.organization.name} - {self.url}"

    def get_events_display(self):
        """Return a human-readable list of subscribed events."""
        event_names = dict(self.EVENT_CHOICES)
        return [event_names.get(event, event) for event in self.events]

class WebhookDelivery(models.Model):
    """
    WebhookDelivery model for tracking webhook delivery attempts.
    """
    STATUS_PENDING = 'pending'
    STATUS_SUCCESS = 'success'
    STATUS_FAILED = 'failed'
    STATUS_RETRYING = 'retrying'

    STATUS_CHOICES = [
        (STATUS_PENDING, 'Pending'),
        (STATUS_SUCCESS, 'Success'),
        (STATUS_FAILED, 'Failed'),
        (STATUS_RETRYING, 'Retrying'),
    ]

    webhook = models.ForeignKey(
        Webhook,
        on_delete=models.CASCADE,
        related_name='deliveries'
    )
    event = models.CharField(max_length=50)
    payload = models.JSONField()
    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default=STATUS_PENDING
    )
    response_code = models.IntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    retry_count = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Webhook Delivery'
        verbose_name_plural = 'Webhook Deliveries'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.webhook.url} - {self.event} ({self.status})"
