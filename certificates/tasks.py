from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.db.models import Q
from nodes.models import Node
from webhooks.models import Webhook
import requests
import logging

logger = logging.getLogger(__name__)

@shared_task
def check_expiring_certificates():
    """
    Check for certificates that are about to expire within the next 30 days
    and notify via the webhook system.
    """
    logger.info("Running certificate expiration check task")
    
    # Find certificates expiring in the next 30 days
    thirty_days_from_now = timezone.now() + timedelta(days=30)
    expiring_nodes = Node.objects.filter(
        cert_expiration__lt=thirty_days_from_now,
        cert_expiration__gt=timezone.now()
    )
    
    if not expiring_nodes.exists():
        logger.info("No certificates found that will expire in the next 30 days")
        return
    
    logger.info(f"Found {expiring_nodes.count()} certificates expiring in the next 30 days")
    
    # Group expiring certificates by organization
    org_expiring_certs = {}
    for node in expiring_nodes:
        org_id = node.organization.id
        if org_id not in org_expiring_certs:
            org_expiring_certs[org_id] = []
        
        days_until_expiry = (node.cert_expiration - timezone.now()).days
        org_expiring_certs[org_id].append({
            'node_id': node.id,
            'node_name': node.name,
            'nebula_ip': node.nebula_ip,
            'expiration': node.cert_expiration.isoformat(),
            'days_until_expiry': days_until_expiry
        })
    
    # Send notifications to each organization.
    for org_id, expiring_certs in org_expiring_certs.items():
        notification_data = {
            'expiring_certificates': expiring_certs,
            'count': len(expiring_certs)
        }
        from notifications.dispatch import queue_notification_event

        queue_notification_event('cert.expiring', org_id, notification_data)

        # Get webhooks for this organization that subscribe to cert.expiring events
        webhooks = Webhook.objects.filter(
            organization_id=org_id,
            events__contains='cert.expiring',
            active=True
        )
        
        if not webhooks.exists():
            logger.info(f"No active webhooks found for organization {org_id} for cert.expiring events")
            continue
        
        # Create notification payload
        payload = {
            'event': 'cert.expiring',
            'organization_id': org_id,
            'timestamp': timezone.now().isoformat(),
            'data': notification_data
        }
        
        # Send to all webhooks
        for webhook in webhooks:
            try:
                send_webhook_notification.delay(webhook.id, payload)
            except Exception as e:
                logger.error(f"Failed to queue webhook notification to {webhook.url}: {str(e)}")

@shared_task(bind=True, max_retries=5)
def send_webhook_notification(self, webhook_id, payload):
    """
    Send a notification to a webhook with exponential backoff retry.
    """
    from webhooks.models import Webhook
    
    try:
        webhook = Webhook.objects.get(id=webhook_id)
        response = requests.post(webhook.url, json=payload, timeout=10)
        response.raise_for_status()
        logger.info(f"Successfully sent webhook notification to {webhook.url}")
        
        # Record successful delivery
        if hasattr(webhook, 'record_delivery'):
            webhook.record_delivery(True, payload, response.status_code, response.text)
        
        return True
    except Webhook.DoesNotExist:
        logger.error(f"Webhook with ID {webhook_id} not found")
        return False
    except requests.RequestException as exc:
        logger.warning(f"Failed to send webhook to {webhook_id}, attempt {self.request.retries + 1}")
        
        # Record failed delivery
        try:
            webhook = Webhook.objects.get(id=webhook_id)
            if hasattr(webhook, 'record_delivery'):
                webhook.record_delivery(False, payload, getattr(exc.response, 'status_code', None), str(exc))
        except Exception as e:
            logger.error(f"Failed to record webhook delivery: {str(e)}")
        
        # Retry with exponential backoff
        retry_delay = 2 ** self.request.retries
        raise self.retry(exc=exc, countdown=retry_delay)
