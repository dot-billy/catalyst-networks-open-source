from celery import shared_task


@shared_task
def deliver_slack_for_event(event_type, organization_id, data):
    from organizations.models import Organization

    from .dispatch import dispatch_notification

    organization = Organization.objects.filter(id=organization_id).first()
    if organization is None:
        return
    dispatch_notification(organization, event_type, data)
