"""
WSGI config for open_cvpn project.

It exposes the WSGI callable as a module-level variable named ``application``.

For more information on this file, see
https://docs.djangoproject.com/en/5.2/howto/deployment/wsgi/
"""

import os

from django.core.wsgi import get_wsgi_application

# Use the environment variable if set, otherwise default to base settings
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'open_cvpn.settings')

application = get_wsgi_application()
