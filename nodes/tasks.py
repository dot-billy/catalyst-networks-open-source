from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.core.files import File
import os
import subprocess
import logging
import ipaddress
from .models import Node

logger = logging.getLogger(__name__)

# How many days before expiration to renew certificates
RENEWAL_WINDOW_DAYS = getattr(settings, 'CERTIFICATE_RENEWAL_WINDOW_DAYS', 14)

@shared_task
def renew_expiring_certificates():
    """
    Check for certificates that are about to expire within the renewal window
    and automatically renew them.
    """
    logger.info(f"Running certificate renewal task (renewal window: {RENEWAL_WINDOW_DAYS} days)")
    
    # Find certificates expiring within the renewal window
    renewal_date = timezone.now() + timedelta(days=RENEWAL_WINDOW_DAYS)
    expiring_nodes = Node.objects.filter(
        cert_expiration__lt=renewal_date,
        cert_expiration__gt=timezone.now()
    )
    
    if not expiring_nodes.exists():
        logger.info(f"No certificates found that will expire within {RENEWAL_WINDOW_DAYS} days")
        return
    
    logger.info(f"Found {expiring_nodes.count()} certificates to renew")
    
    # Process renewals in small batches to avoid overloading the system
    batch_size = getattr(settings, 'CERTIFICATE_RENEWAL_BATCH_SIZE', 10)
    
    renewal_results = {
        'succeeded': 0,
        'failed': 0,
        'nodes': []
    }
    
    # Process in batches
    for i in range(0, expiring_nodes.count(), batch_size):
        batch = expiring_nodes[i:i+batch_size]
        
        for node in batch:
            try:
                result = renew_node_certificate(node.id)
                renewal_results['nodes'].append({
                    'node_id': node.id,
                    'node_name': node.name,
                    'organization_id': node.organization_id,
                    'success': result['success'],
                    'old_expiration': result.get('old_expiration'),
                    'new_expiration': result.get('new_expiration'),
                    'error': result.get('error')
                })
                
                if result['success']:
                    renewal_results['succeeded'] += 1
                else:
                    renewal_results['failed'] += 1
                    
            except Exception as e:
                logger.error(f"Unexpected error renewing certificate for node {node.id} ({node.name}): {str(e)}")
                renewal_results['failed'] += 1
                renewal_results['nodes'].append({
                    'node_id': node.id,
                    'node_name': node.name,
                    'organization_id': node.organization_id,
                    'success': False,
                    'error': str(e)
                })
    
    logger.info(f"Certificate renewal complete: {renewal_results['succeeded']} succeeded, {renewal_results['failed']} failed")
    return renewal_results

@shared_task
def renew_node_certificate(node_id):
    """
    Renew the certificate for a specific node.
    """
    try:
        node = Node.objects.get(id=node_id)
        logger.info(f"Renewing certificate for node {node.name} (ID: {node.id})")
        
        # Store old expiration for reporting
        old_expiration = node.cert_expiration.isoformat() if node.cert_expiration else None
        
        # Get the necessary parameters for certificate generation
        ca = node.certificate_authority
        name = node.name
        ip = node.nebula_ip
        
        # Handle IP addresses with CIDR notation
        if ip and '/' in ip:
            ip = ip.split('/')[0]
            
        # Create cert directory if it doesn't exist (dedicated cert storage)
        cert_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'certs', f'org-{node.organization.id}')
        os.makedirs(cert_dir, exist_ok=True)
        
        # Generate new certificate file paths (use UTC datetime to ensure uniqueness)
        timestamp_str = timezone.now().strftime("%Y%m%dT%H%M%SZ")
        cert_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.crt')
        key_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.key')
        
        # Generate new certificate using nebula-cert
        subprocess.run([
            'nebula-cert', 'sign',
            '-name', name,
            '-ip', f'{ip}/24',
            '-ca-crt', ca.ca_cert.path,
            '-ca-key', ca.ca_key.path,
            '-out-crt', cert_path,
            '-out-key', key_path
        ], check=True)
        
        # Keep track of old paths to clean up
        old_cert_path = node.cert_path.path if node.cert_path else None
        old_key_path = node.key_path.path if node.key_path else None
        
        # Save the files to the node
        with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
            node.cert_path.save(f'{name}-{timestamp_str}.crt', File(cert_file), save=False)
            node.key_path.save(f'{name}-{timestamp_str}.key', File(key_file), save=False)
        
        # Get certificate expiration
        result = subprocess.run([
            'nebula-cert', 'print',
            '-path', cert_path
        ], capture_output=True, text=True, check=True)
        
        # Parse expiration from output
        new_expiration = None
        for line in result.stdout.split('\n'):
            if 'Not After' in line:
                exp_str = line.split(': ')[1].strip()
                # Convert the date format to Django-compatible format
                try:
                    # Parse the date format: "2025-05-03 11:54:04 +0000 UTC"
                    # Convert to YYYY-MM-DD HH:MM:SS format
                    exp_parts = exp_str.split()
                    if len(exp_parts) >= 3:
                        # Extract date and time, ignore timezone for now
                        date_part = exp_parts[0]
                        time_part = exp_parts[1]
                        new_expiration = f"{date_part}T{time_part}Z"
                        node.cert_expiration = new_expiration
                    else:
                        # Fallback: use current time + 1 year
                        node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                        new_expiration = node.cert_expiration.isoformat()
                except Exception as e:
                    logger.error(f"Error parsing certificate expiration: {e}")
                    # Fallback: use current time + 1 year
                    node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                    new_expiration = node.cert_expiration.isoformat()
                break
        
        node.save()
        
        # Clean up old certificate files if they exist
        try:
            if old_cert_path and os.path.exists(old_cert_path):
                os.remove(old_cert_path)
            if old_key_path and os.path.exists(old_key_path):
                os.remove(old_key_path)
        except OSError as e:
            # Log but don't fail if cleanup fails
            logger.warning(f"Could not remove old certificate files: {str(e)}")
        
        # Send webhook notification about certificate renewal
        try:
            from webhooks.models import Webhook
            
            # Get webhooks for this organization that subscribe to cert.issued events
            webhooks = Webhook.objects.filter(
                organization_id=node.organization.id,
                events__contains='cert.issued',
                active=True
            )
            
            if webhooks.exists():
                from certificates.tasks import send_webhook_notification
                
                payload = {
                    'event': 'cert.issued',
                    'organization_id': node.organization.id,
                    'timestamp': timezone.now().isoformat(),
                    'data': {
                        'node_id': node.id,
                        'node_name': node.name,
                        'nebula_ip': node.nebula_ip,
                        'old_expiration': old_expiration,
                        'new_expiration': new_expiration,
                        'renewal': True
                    }
                }
                
                for webhook in webhooks:
                    try:
                        send_webhook_notification.delay(webhook.id, payload)
                    except Exception as e:
                        logger.error(f"Failed to queue webhook notification to {webhook.url}: {str(e)}")
        except Exception as e:
            logger.error(f"Failed to send webhook notifications: {str(e)}")
        
        return {
            'success': True,
            'node_id': node.id,
            'old_expiration': old_expiration,
            'new_expiration': new_expiration
        }
    
    except Node.DoesNotExist:
        logger.error(f"Node with ID {node_id} not found")
        return {
            'success': False,
            'error': f"Node with ID {node_id} not found"
        }
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to generate certificate: {str(e)}")
        return {
            'success': False,
            'error': f"Failed to generate certificate: {str(e)}"
        }
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return {
            'success': False,
            'error': f"Unexpected error: {str(e)}"
        } 