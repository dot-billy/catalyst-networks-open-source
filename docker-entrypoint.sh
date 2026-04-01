#!/bin/bash
set -e

echo "Starting Django application..."
echo "Current directory: $(pwd)"
echo "Directory contents:"
ls -la

echo -e "\nPython path inspection:"
python -c "import sys; print('sys.path:', sys.path)"

# Run healthcheck
echo -e "\nRunning healthcheck..."
python healthcheck.py

# Run migrations if requested
if [ "$RUN_MIGRATIONS" = "true" ]; then
    echo -e "\nRunning database migrations..."
    if ! python manage.py migrate --noinput; then
        echo "WARNING: migrate command exited non-zero. Checking migration state..."
        if python manage.py showmigrations --plan | grep -q "\[ \]"; then
            echo "ERROR: Unapplied migrations remain after failure. Exiting."
            exit 1
        fi
        echo "All migrations applied (likely handled by another replica). Continuing."
    fi
fi

# Create superuser if requested
if [ "$CREATE_SUPERUSER" = "true" ] && [ -n "$DJANGO_SUPERUSER_USERNAME" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ]; then
    echo -e "\nCreating superuser..."
    python manage.py createsuperuser --noinput || echo "Superuser creation failed (may already exist)"
fi

# If healthcheck passes, start Gunicorn
echo -e "\nStarting Gunicorn..."
exec gunicorn --bind 0.0.0.0:8000 \
    --workers ${GUNICORN_WORKERS:-1} \
    --threads ${GUNICORN_THREADS:-4} \
    --worker-class ${GUNICORN_WORKER_CLASS:-gthread} \
    --timeout ${GUNICORN_TIMEOUT:-120} \
    --access-logfile - \
    --error-logfile - \
    --log-level ${GUNICORN_LOG_LEVEL:-info} \
    --preload \
    open_cvpn.wsgi:application 