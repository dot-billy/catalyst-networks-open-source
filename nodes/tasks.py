from celery import shared_task
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from datetime import timedelta, timezone as datetime_timezone
from django.conf import settings
from django.core.files import File
import json
import os
import subprocess
import logging
from .models import Node

logger = logging.getLogger(__name__)

# How many days before expiration to renew certificates
RENEWAL_WINDOW_DAYS = getattr(settings, 'CERTIFICATE_RENEWAL_WINDOW_DAYS', 14)


def _expected_certificate_groups(node):
    group_names = []
    if node.is_lighthouse:
        group_names.append('lighthouse')
    group_names.extend(list(node.security_groups.values_list('name', flat=True)))
    return sorted(set(group_names))


def parse_nebula_cert_expiration(output):
    """
    Parse nebula-cert print output from current JSON or legacy text formats.
    """
    output = (output or '').strip()
    if not output:
        raise ValueError("nebula-cert print output was empty")

    try:
        cert_info = json.loads(output)
    except json.JSONDecodeError:
        cert_info = None

    if cert_info is not None:
        details = cert_info.get('details', {}) if isinstance(cert_info, dict) else {}
        expiration_value = details.get('notAfter')
        if not expiration_value:
            raise ValueError("nebula-cert JSON output did not include details.notAfter")
        return _parse_nebula_expiration_value(expiration_value)

    for line in output.splitlines():
        if 'Not After' in line:
            try:
                expiration_value = line.split(': ', 1)[1].strip()
            except IndexError as exc:
                raise ValueError("legacy Not After line was not parseable") from exc
            return _parse_nebula_expiration_value(expiration_value)

    raise ValueError("nebula-cert output did not include an expiration")


def _parse_nebula_expiration_value(expiration_value):
    expiration_value = str(expiration_value).strip()
    parsed = parse_datetime(expiration_value)
    if parsed is None and expiration_value.endswith(' UTC'):
        parsed = parse_datetime(expiration_value[:-4])
    if parsed is None:
        raise ValueError(f"could not parse certificate expiration {expiration_value!r}")
    if timezone.is_naive(parsed):
        parsed = timezone.make_aware(parsed, timezone=datetime_timezone.utc)
    return parsed


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
        cmd = [
            'nebula-cert', 'sign',
            '-name', name,
            '-ip', f'{ip}/24',
            '-ca-crt', ca.ca_cert.path,
            '-ca-key', ca.ca_key.path,
            '-out-crt', cert_path,
            '-out-key', key_path,
        ]
        group_names = _expected_certificate_groups(node)
        if group_names:
            cmd.extend(['-groups', ','.join(group_names)])
        subprocess.run(cmd, check=True)
        
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
        
        try:
            node.cert_expiration = parse_nebula_cert_expiration(result.stdout)
        except ValueError as e:
            logger.error(f"Error parsing certificate expiration: {e}")
            node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
        new_expiration = node.cert_expiration.isoformat()
        
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
        
        renewal_notification_data = {
            'node_id': node.id,
            'node_name': node.name,
            'nebula_ip': node.nebula_ip,
            'old_expiration': old_expiration,
            'new_expiration': new_expiration,
            'renewal': True
        }

        # Send notifications about certificate renewal.
        from notifications.dispatch import queue_notification_event

        queue_notification_event('cert.renewed', node.organization.id, renewal_notification_data)

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
                    'data': renewal_notification_data
                }
                
                for webhook in webhooks:
                    try:
                        send_webhook_notification.delay(webhook.id, payload)
                    except Exception as e:
                        logger.error("Failed to queue webhook notification %s: %s", webhook.id, e)
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


@shared_task
def cleanup_stale_cert_files():
    """
    Remove delivered certificate/key files and orphaned files from storage.

    Nodes that have checked in and whose local certificate artifacts are older
    than CERT_FILE_RETENTION_DAYS no longer need server-side copies for normal
    operation. Missing files are regenerated on demand when a node downloads
    config again.
    """
    retention_days = getattr(settings, 'CERT_FILE_RETENTION_DAYS', 30)
    cutoff = timezone.now() - timedelta(days=retention_days)
    results = {'cleaned_nodes': 0, 'orphaned_files_removed': 0, 'errors': []}

    candidate_nodes = Node.objects.filter(last_checkin__isnull=False)

    for node in candidate_nodes:
        try:
            cleared_fields = []
            for field in (node.cert_path, node.key_path):
                if not field or not field.name:
                    continue
                modified_at = _certificate_file_modified_at(field)
                if modified_at is None or modified_at >= cutoff:
                    continue
                if _delete_storage_file(field):
                    cleared_fields.append(field.field.name)
                else:
                    results['errors'].append(f"Node {node.id}: could not delete {field.name}")
            if cleared_fields:
                update_values = {field_name: '' for field_name in cleared_fields}
                Node.objects.filter(pk=node.pk).update(**update_values)
                results['cleaned_nodes'] += 1
        except Exception as exc:
            results['errors'].append(f"Node {node.id}: {exc}")

    certs_root = os.path.join(settings.CERT_STORAGE_ROOT, 'certs')
    if os.path.isdir(certs_root):
        known_paths = set()
        for node in Node.objects.exclude(cert_path='').exclude(cert_path__isnull=True):
            try:
                known_paths.add(os.path.abspath(node.cert_path.path))
            except (ValueError, Exception):
                pass
        for node in Node.objects.exclude(key_path='').exclude(key_path__isnull=True):
            try:
                known_paths.add(os.path.abspath(node.key_path.path))
            except (ValueError, Exception):
                pass

        for dirpath, _dirnames, filenames in os.walk(certs_root):
            for filename in filenames:
                if not filename.endswith(('.crt', '.key')):
                    continue
                path = os.path.abspath(os.path.join(dirpath, filename))
                if path in known_paths:
                    continue
                try:
                    os.remove(path)
                    results['orphaned_files_removed'] += 1
                except OSError as exc:
                    results['errors'].append(f"Orphan {path}: {exc}")

    logger.info(
        "Cert cleanup: %s nodes cleaned, %s orphaned files removed, %s errors",
        results['cleaned_nodes'],
        results['orphaned_files_removed'],
        len(results['errors']),
    )
    return results


def _certificate_file_modified_at(field):
    try:
        if not field.storage.exists(field.name):
            return None
        modified_at = field.storage.get_modified_time(field.name)
    except Exception as exc:
        logger.warning("Could not inspect certificate file %s: %s", field.name, exc)
        return None
    if timezone.is_naive(modified_at):
        modified_at = timezone.make_aware(modified_at, timezone=datetime_timezone.utc)
    return modified_at


def _delete_storage_file(field):
    try:
        field.storage.delete(field.name)
        return not field.storage.exists(field.name)
    except Exception as exc:
        logger.warning("Could not remove certificate file %s: %s", field.name, exc)
        return False
