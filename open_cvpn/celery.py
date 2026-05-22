import os
import logging
from celery import Celery
from celery.schedules import crontab

logger = logging.getLogger(__name__)

# Set the default Django settings module for the 'celery' program.
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'open_cvpn.settings')

app = Celery('open_cvpn')

# Using a string here means the worker doesn't have to serialize
# the configuration object to child processes.
app.config_from_object('django.conf:settings', namespace='CELERY')

# Load task modules from all registered Django app configs.
app.autodiscover_tasks()

# Configure periodic tasks
app.conf.beat_schedule = {
    # Check for expiring certificates daily
    'check-expiring-certificates': {
        'task': 'certificates.tasks.check_expiring_certificates',
        'schedule': crontab(hour=0, minute=0),  # Run daily at midnight
    },
    
    # Automatically renew expiring certificates
    'renew-expiring-certificates': {
        'task': 'nodes.tasks.renew_expiring_certificates',
        'schedule': crontab(hour=1, minute=0),  # Run daily at 1 AM
    },

    # Clean up stale cert/key files from disk after delivery
    'cleanup-stale-cert-files': {
        'task': 'nodes.tasks.cleanup_stale_cert_files',
        'schedule': crontab(hour=3, minute=0),  # Run daily at 3 AM
    },
}

@app.task(bind=True, ignore_result=True)
def debug_task(self):
    logger.debug("Request: %r", self.request)
