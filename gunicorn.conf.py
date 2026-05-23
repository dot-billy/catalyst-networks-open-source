"""
Gunicorn configuration file for production deployment.

This file can be used with: gunicorn -c gunicorn.conf.py open_cvpn.wsgi:application
"""

import os

# Server socket
bind = os.environ.get('GUNICORN_BIND', '0.0.0.0:8000')
backlog = int(os.environ.get('GUNICORN_BACKLOG', 2048))

# Worker processes
# Default to the same conservative worker count used by docker-entrypoint.sh
# before the image started delegating Gunicorn startup to this config file.
workers = int(os.environ.get('GUNICORN_WORKERS', 1))
worker_class = os.environ.get('GUNICORN_WORKER_CLASS', 'gthread')
threads = int(os.environ.get('GUNICORN_THREADS', 4))
worker_connections = int(os.environ.get('GUNICORN_WORKER_CONNECTIONS', 1000))
max_requests = int(os.environ.get('GUNICORN_MAX_REQUESTS', 1000))
max_requests_jitter = int(os.environ.get('GUNICORN_MAX_REQUESTS_JITTER', 100))
timeout = int(os.environ.get('GUNICORN_TIMEOUT', 120))
graceful_timeout = int(os.environ.get('GUNICORN_GRACEFUL_TIMEOUT', 30))
keepalive = int(os.environ.get('GUNICORN_KEEPALIVE', 5))

# Logging
accesslog = os.environ.get('GUNICORN_ACCESSLOG', '-')
errorlog = os.environ.get('GUNICORN_ERRORLOG', '-')
loglevel = os.environ.get('GUNICORN_LOGLEVEL', os.environ.get('GUNICORN_LOG_LEVEL', 'info'))
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Process naming
proc_name = 'catalyst_networks'

# Server mechanics
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL (if needed)
keyfile = os.environ.get('GUNICORN_KEYFILE', None)
certfile = os.environ.get('GUNICORN_CERTFILE', None)

# StatsD integration (optional)
statsd_host = os.environ.get('GUNICORN_STATSD_HOST', None)
if statsd_host:
    statsd_prefix = os.environ.get('GUNICORN_STATSD_PREFIX', 'catalyst_networks')

# Server hooks
def pre_fork(server, worker):
    """Called just before a worker is forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_exec(server):
    """Called just before a new master process is forked."""
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("Server is ready. Spawning workers")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT."""
    worker.log.info("Worker received INT or QUIT signal")

def on_exit(server):
    """Called just before exiting."""
    server.log.info("Shutting down: Master")
