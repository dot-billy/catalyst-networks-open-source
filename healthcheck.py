#!/usr/bin/env python
"""
Simple healthcheck script to verify Django can load properly.
This helps debug startup issues.
"""
import os
import sys
import django


def main():
    print("=== Django Healthcheck ===")
    print(f"Python: {sys.version}")
    print(f"Django: {django.__version__}")
    print(f"DJANGO_SETTINGS_MODULE: {os.environ.get('DJANGO_SETTINGS_MODULE', 'NOT SET')}")
    print(f"PYTHONPATH: {os.environ.get('PYTHONPATH', 'NOT SET')}")
    print(f"Working Directory: {os.getcwd()}")

    # Check required environment variables
    print("\n=== Environment Variables ===")
    required_vars = ['POSTGRES_DB', 'POSTGRES_USER', 'POSTGRES_PASSWORD', 'POSTGRES_HOST']
    optional_vars = ['POSTGRES_PORT', 'REDIS_HOST', 'REDIS_PORT', 'DJANGO_SECRET_KEY']

    missing_vars = []
    for var in required_vars:
        value = os.environ.get(var)
        if value:
            print(f"  {var}: [SET]")
        else:
            print(f"  {var}: NOT SET")
            missing_vars.append(var)

    print("\nOptional variables:")
    for var in optional_vars:
        value = os.environ.get(var)
        if value:
            print(f"  {var}: [SET]")
        else:
            print(f"  {var}: NOT SET")

    try:
        django.setup()
        print("\n  Django setup successful")

        # Try to import the WSGI application
        from open_cvpn.wsgi import application
        print("  WSGI application imported successfully")

        # Check database connection only if vars are set
        if not missing_vars:
            try:
                from django.db import connection
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                print("  Database connection successful")
            except Exception as db_error:
                print(f"  Database connection failed: {db_error}")
                print("  (This may be expected if the database is not yet available)")
        else:
            print("  Skipping database check - missing environment variables")

    except Exception as e:
        print(f"\n  Error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

    print("\n=== Healthcheck completed ===")

if __name__ == "__main__":
    main()
