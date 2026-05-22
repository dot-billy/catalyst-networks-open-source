import logging
import re

import requests
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils import timezone

from .models import NotificationIntegration

logger = logging.getLogger(__name__)

SLACK_WEBHOOK_URL_RE = re.compile(r"https://hooks\.slack\.com/services/[^\s'\"<>]+")
URL_RE = re.compile(r"https?://[^\s'\"<>]+")
BODY_SNIPPET_LIMIT = 300


def _redact_urls(value):
    value = SLACK_WEBHOOK_URL_RE.sub("[redacted-slack-webhook]", value or "")
    return URL_RE.sub("[redacted-url]", value)


def _body_snippet(response):
    text = getattr(response, "text", "") or ""
    text = _redact_urls(text).replace("\n", " ").strip()
    return text[:BODY_SNIPPET_LIMIT]


def _delivery_error_summary(exc):
    response = getattr(exc, "response", None)
    if response is not None:
        status_code = getattr(response, "status_code", None)
        reason = getattr(response, "reason", "") or ""
        summary = f"HTTP {status_code}" if status_code else "HTTP error"
        if reason:
            summary = f"{summary} {reason}"
        snippet = _body_snippet(response)
        if snippet:
            summary = f"{summary}: {snippet}"
        return summary

    if isinstance(exc, (ImproperlyConfigured, ValidationError)):
        return "Notification integration secret is not configured correctly."

    return "Slack delivery failed before receiving a response."


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


def node_lifecycle_payload(node, **extra):
    """Build a non-secret payload for node lifecycle notification events."""
    payload = {
        "node_id": node.id,
        "node_name": node.name,
        "nebula_ip": node.nebula_ip,
        "is_lighthouse": node.is_lighthouse,
    }
    if getattr(node, "cert_expiration", None):
        payload["cert_expiration"] = node.cert_expiration.isoformat()
    payload.update({key: value for key, value in extra.items() if value not in (None, "")})
    return payload


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
            webhook_url = integration.get_secret_url()
            response = requests.post(
                webhook_url,
                json={"text": format_slack_message(event_type, organization, payload)},
                timeout=10,
            )
            response.raise_for_status()
            integration.last_delivery_at = timezone.now()
            integration.last_delivery_status = response.status_code
            integration.last_delivery_error = ""
        except Exception as exc:
            error_summary = _delivery_error_summary(exc)
            integration.last_delivery_at = timezone.now()
            integration.last_delivery_status = getattr(getattr(exc, "response", None), "status_code", None)
            integration.last_delivery_error = error_summary[:1000]
            logger.error("Failed to deliver Slack notification integration %s: %s", integration.id, error_summary)
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


def queue_notification_event(event_type, organization_id, data):
    """Queue a notification event without letting producer workflows fail."""
    try:
        dispatch_event(event_type, organization_id, data)
    except Exception:
        logger.error(
            "Failed to queue notification event %s for organization %s",
            event_type,
            organization_id,
        )


def queue_node_lifecycle_events(node, event_types, **extra):
    payload = node_lifecycle_payload(node, **extra)
    for event_type in event_types:
        queue_notification_event(event_type, node.organization_id, payload)
