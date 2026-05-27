"""
Production settings for the open_cvpn project.

This file is loaded in production environments. It inherits from the base
settings.py file and overrides settings for production use.
"""

from .settings import *
import os

# --- Database Configuration ---
# Parse DATABASE_URL for production database connection
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL:
    from urllib.parse import urlparse
    
    parsed_db = urlparse(DATABASE_URL)
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': parsed_db.path[1:],  # Remove leading slash
            'USER': parsed_db.username,
            'PASSWORD': parsed_db.password,
            'HOST': parsed_db.hostname,
            'PORT': parsed_db.port or 5432,
        }
    }
else:
    # Fallback to default empty config from base settings
    # This will cause an error if DATABASE_URL is not set
    pass

# --- Production Overrides ---

# DEBUG is always False in production.
DEBUG = False

# Allowed hosts for production. This MUST be set in the environment.
# Example: DJANGO_ALLOWED_HOSTS=your_domain.com,www.your_domain.com
ALLOWED_HOSTS_str = os.environ.get('DJANGO_ALLOWED_HOSTS')
if not ALLOWED_HOSTS_str:
    from django.core.exceptions import ImproperlyConfigured
    raise ImproperlyConfigured(
        "DJANGO_ALLOWED_HOSTS is not set. This is required in production. "
        "Example: DJANGO_ALLOWED_HOSTS=yourdomain.com,www.yourdomain.com"
    )
ALLOWED_HOSTS = [h.strip() for h in ALLOWED_HOSTS_str.split(',')]

# --- CSRF Configuration ---
# Handle CSRF trusted origins for production
CSRF_TRUSTED_ORIGINS_str = os.environ.get('CSRF_TRUSTED_ORIGINS', '')
if CSRF_TRUSTED_ORIGINS_str:
    # Split by comma to support multiple origins
    CSRF_TRUSTED_ORIGINS = [origin.strip() for origin in CSRF_TRUSTED_ORIGINS_str.split(',')]
else:
    # If not set, try to construct from ALLOWED_HOSTS
    CSRF_TRUSTED_ORIGINS = []
    for host in ALLOWED_HOSTS:
        if host not in ['localhost', '127.0.0.1', '*']:
            # Add both http and https versions
            CSRF_TRUSTED_ORIGINS.extend([
                f'http://{host}',
                f'https://{host}'
            ])

# --- Security Settings (from template) ---

# SSL/HTTPS settings
SECURE_SSL_REDIRECT = os.environ.get('SECURE_SSL_REDIRECT', 'True').lower() == 'true'
SESSION_COOKIE_SECURE = os.environ.get('SESSION_COOKIE_SECURE', 'True').lower() == 'true'
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = 'Lax'
CSRF_COOKIE_SECURE = os.environ.get('CSRF_COOKIE_SECURE', 'True').lower() == 'true'
CSRF_COOKIE_HTTPONLY = True
CSRF_COOKIE_SAMESITE = 'Lax'
USE_HTTPS_IN_ABSOLUTE_URLS = os.environ.get('USE_HTTPS_IN_ABSOLUTE_URLS', 'True').lower() == 'true'

# Handle SECURE_PROXY_SSL_HEADER for deployments behind a proxy
proxy_header = os.environ.get('SECURE_PROXY_SSL_HEADER', '')
if proxy_header and ',' in proxy_header:
    header, value = proxy_header.split(',', 1)
    SECURE_PROXY_SSL_HEADER = (header.strip(), value.strip())
else:
    SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")

USE_X_FORWARDED_HOST = os.environ.get('USE_X_FORWARDED_HOST', 'False').lower() == 'true'
USE_X_FORWARDED_PORT = os.environ.get('USE_X_FORWARDED_PORT', 'False').lower() == 'true'

# Now that USE_X_FORWARDED_HOST is defined, we can use it
# Handle X-Forwarded headers properly for CSRF
if USE_X_FORWARDED_HOST:
    # This ensures Django uses the forwarded host for CSRF checks
    CSRF_USE_SESSIONS = False  # Use cookies for CSRF tokens

# Handle SECURE_REDIRECT_EXEMPT for paths that should not be redirected to HTTPS
redirect_exempt = os.environ.get('SECURE_REDIRECT_EXEMPT', '')
if redirect_exempt:
    import re
    SECURE_REDIRECT_EXEMPT = [re.compile(redirect_exempt)]

# Additional security headers
SECURE_CONTENT_TYPE_NOSNIFF = True

# HTTP Strict Transport Security (HSTS) settings
SECURE_HSTS_SECONDS = int(os.environ.get('SECURE_HSTS_SECONDS', 31536000))  # Default to 1 year
SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get('SECURE_HSTS_INCLUDE_SUBDOMAINS', 'True').lower() == 'true'
SECURE_HSTS_PRELOAD = os.environ.get('SECURE_HSTS_PRELOAD', 'True').lower() == 'true'

# --- Admin and Logging ---

# Admin details for error reporting
_admin_name = os.environ.get('ADMIN_NAME', 'Admin')
_admin_email = os.environ.get('ADMIN_EMAIL', '')
ADMINS = [(_admin_name, _admin_email)] if _admin_email else []

# Production logging configuration - output to console for container environments
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
            'formatter': 'verbose',
        },
    },
    'root': {
        'handlers': ['console'],
        'level': 'INFO',
    },
    'loggers': {
        'django': {
            'handlers': ['console'],
            'level': 'INFO',
            'propagate': False,
        },
    },
}

# --- Storage Settings (S3/MinIO) ---
# Note: Static files are ALWAYS served by WhiteNoise (configured below)
# S3 is only used for media files if configured

if os.getenv('AWS_STORAGE_BUCKET_NAME'):
    # Configure storage for media files only (static files use WhiteNoise)
    # STATICFILES_STORAGE is NOT set here - WhiteNoise handles static files

    # Get S3 credentials from environment
    AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
    AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
    AWS_STORAGE_BUCKET_NAME = os.getenv('AWS_STORAGE_BUCKET_NAME')
    AWS_S3_ENDPOINT_URL = os.getenv('AWS_S3_ENDPOINT_URL')

    # S3 settings
    _s3_default_acl = None
    _s3_object_parameters = {'CacheControl': 'max-age=86400'}
    AWS_DEFAULT_ACL = _s3_default_acl
    AWS_S3_OBJECT_PARAMETERS = _s3_object_parameters

    # Construct the domain for media files
    if AWS_S3_ENDPOINT_URL:  # For MinIO or other S3-compatible services
        domain = AWS_S3_ENDPOINT_URL.split('//')[-1]
        _s3_custom_domain = f'{domain}/{AWS_STORAGE_BUCKET_NAME}'
    else:  # For AWS S3
        _s3_custom_domain = f'{AWS_STORAGE_BUCKET_NAME}.s3.amazonaws.com'
    AWS_S3_CUSTOM_DOMAIN = _s3_custom_domain

    # Update media URL only (STATIC_URL stays as '/static/' for WhiteNoise)
    MEDIA_URL = f'https://{AWS_S3_CUSTOM_DOMAIN}/media/'

# --- Gunicorn Configuration ---

# These settings are used when running with Gunicorn
# They can be overridden by environment variables or Gunicorn command line args

# Number of worker processes
GUNICORN_WORKERS = int(os.environ.get('GUNICORN_WORKERS', 4))

# Number of threads per worker
GUNICORN_THREADS = int(os.environ.get('GUNICORN_THREADS', 4))

# Worker class (gthread for multi-threaded workers)
GUNICORN_WORKER_CLASS = os.environ.get('GUNICORN_WORKER_CLASS', 'gthread')

# Timeout for workers
GUNICORN_TIMEOUT = int(os.environ.get('GUNICORN_TIMEOUT', 120))

# Max requests per worker before restart (helps prevent memory leaks)
GUNICORN_MAX_REQUESTS = int(os.environ.get('GUNICORN_MAX_REQUESTS', 1000))
GUNICORN_MAX_REQUESTS_JITTER = int(os.environ.get('GUNICORN_MAX_REQUESTS_JITTER', 100))

# Gunicorn logging
GUNICORN_ACCESSLOG = os.environ.get('GUNICORN_ACCESSLOG', '-')  # '-' means stdout
GUNICORN_ERRORLOG = os.environ.get('GUNICORN_ERRORLOG', '-')    # '-' means stderr
GUNICORN_LOGLEVEL = os.environ.get('GUNICORN_LOGLEVEL', 'info')

# --- Additional Production Settings ---

# Force HTTPS for all URLs in production
if USE_HTTPS_IN_ABSOLUTE_URLS:
    SECURE_SSL_REDIRECT = True

# Ensure static files are collected to the right place
STATIC_ROOT = os.path.join(BASE_DIR, 'staticfiles')

# STATIC_URL must always be '/static/' for WhiteNoise to work correctly
# This is set in base settings.py, but we explicitly ensure it here
STATIC_URL = '/static/'

# --- WhiteNoise Configuration ---
# WhiteNoise is ALWAYS used for serving static files in production

# Insert WhiteNoise middleware after SecurityMiddleware
MIDDLEWARE = MIDDLEWARE.copy()
if 'whitenoise.middleware.WhiteNoiseMiddleware' not in MIDDLEWARE:
    security_index = MIDDLEWARE.index('django.middleware.security.SecurityMiddleware')
    MIDDLEWARE.insert(security_index + 1, 'whitenoise.middleware.WhiteNoiseMiddleware')

# Configure WhiteNoise
STORAGES = {
    "default": {
        "BACKEND": "storages.backends.s3boto3.S3Boto3Storage"
        if os.getenv('AWS_STORAGE_BUCKET_NAME')
        else "django.core.files.storage.FileSystemStorage",
    },
    "staticfiles": {
        # Using CompressedStaticFilesStorage instead of CompressedManifestStaticFilesStorage
        # to avoid 500 errors when static files are missing from manifest
        "BACKEND": "whitenoise.storage.CompressedStaticFilesStorage",
    },
}

# WhiteNoise settings
# The deployed app may serve static files from a mounted volume that can be
# refreshed independently of the Gunicorn process. Auto-refresh keeps
# WhiteNoise from serving stale Content-Length / ETag metadata after those
# on-disk files change.
WHITENOISE_AUTOREFRESH = os.environ.get('WHITENOISE_AUTOREFRESH', 'True').lower() == 'true'
WHITENOISE_COMPRESS_OFFLINE = True  # Pre-compress files
WHITENOISE_SKIP_COMPRESS_EXTENSIONS = ['jpg', 'jpeg', 'png', 'gif', 'webp', 'zip', 'gz', 'tgz', 'bz2', 'tbz', 'xz', 'br']
WHITENOISE_MIMETYPES = {
    '.webmanifest': 'application/manifest+json',
}

# Cache static files for 1 year (versioned files)
WHITENOISE_MAX_AGE = 31536000

# Allow WhiteNoise to serve index files at directory roots
WHITENOISE_INDEX_FILE = True

# Use WhiteNoise in production even during development (for testing)
WHITENOISE_USE_FINDERS = False

# --- Redis Configuration for JWT Blacklisting ---
CACHES = {
    'default': {
        'BACKEND': 'django_redis.cache.RedisCache',
        'LOCATION': 'redis://redis:6379/1',
        'OPTIONS': {
            'CLIENT_CLASS': 'django_redis.client.DefaultClient',
        }
    }
}

SESSION_ENGINE = 'django.contrib.sessions.backends.cache'
SESSION_CACHE_ALIAS = 'default'
