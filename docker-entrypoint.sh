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

# If no command is supplied, fall back to the production WSGI server.
if [ "$#" -eq 0 ]; then
    set -- gunicorn -c gunicorn.conf.py open_cvpn.wsgi:application
fi

echo -e "\nStarting command: $*"
exec "$@"
