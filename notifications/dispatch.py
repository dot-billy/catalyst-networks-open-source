import logging

import requests
from django.utils import timezone

from .models import NotificationIntegration

logger = logging.getLogger(__name__)


def format_slack_message(event_type, organization, payload):
    title = event_type.replace(".", " ").title()
    payload = payload or {}
    details = []
    labels = {
        "node": "Node",
        "node_name": "Node",
        "nebula_ip": "Nebula IP",
        "message": "Message",
        "certificate": "Certificate",
    }

    for key, value in payload.items():
        if value in (None, ""):
            continue
        label = labels.get(key, key.replace("_", " ").title())
        details.append(f"{label}: {value}")

    text = f"*{title}* (`{event_type}`) for organization `{organization.name}`"
    if details:
        text = f"{text}\n" + "\n".join(f"- {detail}" for detail in details[:8])
    return text


def dispatch_notification(organization, event_type, payload=None):
    """Synchronously deliver a notification to matching active organization integrations."""
    integrations = NotificationIntegration.objects.filter(
        organization=organization,
        kind=NotificationIntegration.Kind.SLACK,
        active=True,
    )

    for integration in integrations:
        if event_type not in (integration.events or []):
            continue
        if not integration.has_webhook_url:
            logger.warning("Slack integration %s has no webhook URL", integration.id)
            continue

        try:
            response = requests.post(
                integration.get_secret_url(),
                json={"text": format_slack_message(event_type, organization, payload)},
                timeout=10,
            )
            response.raise_for_status()
            integration.last_delivery_at = timezone.now()
            integration.last_delivery_status = response.status_code
            integration.last_delivery_error = ""
        except Exception as exc:
            integration.last_delivery_at = timezone.now()
            integration.last_delivery_status = getattr(getattr(exc, "response", None), "status_code", None)
            integration.last_delivery_error = str(exc)[:1000]
            logger.error("Failed to deliver Slack notification integration %s: %s", integration.id, exc)
        finally:
            integration.save(
                update_fields=[
                    "last_delivery_at",
                    "last_delivery_status",
                    "last_delivery_error",
                    "updated_at",
                ]
            )


def dispatch_event(event_type, organization_id, data):
    """Queue notification delivery for event-oriented callers."""
    from .tasks import deliver_slack_for_event

    deliver_slack_for_event.delay(event_type, organization_id, data)
