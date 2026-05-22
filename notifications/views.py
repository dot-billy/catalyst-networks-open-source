from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.core.validators import URLValidator
from django.http import HttpResponseForbidden
from django.shortcuts import redirect, render

from organizations.access import get_org_role, is_org_manager, require_org_access

from .models import EventType, NotificationIntegration


SLACK_WEBHOOK_PREFIX = "https://hooks.slack.com/services/"

EVENT_CATEGORY_DEFINITIONS = [
    ("Nodes", ["node.registered", "node.created", "node.revoked"]),
    ("Certificates", ["cert.issued", "cert.renewed", "cert.expiring"]),
    ("Network", ["ip.allocated"]),
]


def _group_event_types():
    event_lookup = {event.value: event for event in EventType}
    return [
        {
            "name": category,
            "events": [
                event_lookup[event_value]
                for event_value in event_values
                if event_value in event_lookup
            ],
        }
        for category, event_values in EVENT_CATEGORY_DEFINITIONS
    ]


def _validate_slack_webhook_url(webhook_url):
    if not webhook_url:
        return
    URLValidator(schemes=["https"])(webhook_url)
    if not webhook_url.startswith(SLACK_WEBHOOK_PREFIX):
        raise ValidationError("Enter a valid Slack incoming webhook URL.")


@login_required
def org_notification_preferences(request, slug):
    org = require_org_access(request.user, slug=slug)
    org.role = get_org_role(request.user, org)

    context = {
        "organization": org,
        "slack_integration": NotificationIntegration.objects.filter(
            organization=org,
            kind=NotificationIntegration.Kind.SLACK,
        ).first(),
    }
    return render(request, "notifications/preferences.html", context)


@login_required
def org_slack_integration(request, slug):
    org = require_org_access(request.user, slug=slug)
    org.role = get_org_role(request.user, org)
    if not is_org_manager(request.user, org):
        return HttpResponseForbidden("You do not have permission to manage notification integrations.")

    integration, _ = NotificationIntegration.objects.get_or_create(
        organization=org,
        kind=NotificationIntegration.Kind.SLACK,
        defaults={
            "events": [event.value for event in EventType],
            "active": False,
        },
    )

    if request.method == "POST":
        selected_events = request.POST.getlist("events")
        webhook_url = request.POST.get("webhook_url", "").strip()
        active = request.POST.get("active") == "on"

        try:
            _validate_slack_webhook_url(webhook_url)
        except ValidationError as exc:
            messages.error(request, exc.messages[0])
            return redirect("notifications_org:slack", slug=slug)

        if active and not webhook_url and not integration.has_webhook_url:
            messages.error(request, "Enter a Slack webhook URL before enabling Slack notifications.")
            return redirect("notifications_org:slack", slug=slug)

        if webhook_url:
            try:
                integration.set_secret_url(webhook_url)
            except (ImproperlyConfigured, ValidationError) as exc:
                messages.error(request, f"Notification integration encryption is not configured: {exc}")
                return redirect("notifications_org:slack", slug=slug)
        integration.events = [event.value for event in EventType if event.value in selected_events]
        integration.active = active
        integration.save()

        if request.POST.get("action") == "test":
            if not integration.active or not integration.has_webhook_url:
                messages.error(request, "Enable Slack and save a webhook URL before sending a test.")
            else:
                from .tasks import deliver_slack_for_event

                deliver_slack_for_event.delay(
                    "node.registered",
                    org.id,
                    {
                        "message": "Slack test notification",
                    },
                )
                messages.success(request, "Slack test notification queued.")
        else:
            messages.success(request, "Slack notification settings updated.")

        return redirect("notifications_org:slack", slug=slug)

    return render(
        request,
        "notifications/slack.html",
        {
            "organization": org,
            "integration": integration,
            "event_categories": _group_event_types(),
        },
    )
