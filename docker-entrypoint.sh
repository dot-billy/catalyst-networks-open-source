#!/bin/bash
set -e

echo "Starting Django application..."
echo "Current directory: $(pwd)"
echo "Directory contents:"
ls -la

echo -e "\nPython path inspection:"
python -c "import sys; print('sys.path:', sys.path)"

# If no command is supplied, fall back to the production WSGI server.
if [ "$#" -eq 0 ]; then
    set -- gunicorn -c gunicorn.conf.py open_cvpn.wsgi:application
fi

if [ -n "$DJANGO_STATIC_ROOT" ]; then
    mkdir -p "$DJANGO_STATIC_ROOT"
fi

if [ -n "$DJANGO_GENERATED_STATIC_DIR" ]; then
    mkdir -p "$DJANGO_GENERATED_STATIC_DIR"
fi

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
if [ "$CREATE_SUPERUSER" = "true" ] && [ -n "$DJANGO_SUPERUSER_EMAIL" ] && [ -n "$DJANGO_SUPERUSER_PASSWORD" ]; then
    echo -e "\nCreating superuser..."
    python manage.py createsuperuser --noinput || echo "Superuser creation failed (may already exist)"
fi

if [ "$1" = "gunicorn" ]; then
    if [ "$RUN_BUILD_STATIC" = "true" ]; then
        echo -e "\nBuilding generated static assets..."
        static_build_dir="${DJANGO_GENERATED_STATIC_DIR:-static}"
        mkdir -p "$static_build_dir/css"
        tailwind_output="$static_build_dir/css/tailwind-output.css"
        tailwindcss -i static/css/tailwind-input.css -o "$tailwind_output" --minify
    fi

    if [ "$RUN_COLLECTSTATIC" = "true" ]; then
        echo -e "\nCollecting static assets..."
        python manage.py collectstatic --noinput --clear
    fi
fi

echo -e "\nStarting command: $*"
exec "$@"
