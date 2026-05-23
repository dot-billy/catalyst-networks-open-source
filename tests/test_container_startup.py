import pathlib
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


class ContainerStartupConfigTests(unittest.TestCase):
    def read_file(self, relative_path):
        return (ROOT / relative_path).read_text()

    def test_dockerfile_uses_existing_entrypoint_with_gunicorn_default(self):
        dockerfile = self.read_file("Dockerfile")

        self.assertIn("COPY healthcheck.py .", dockerfile)
        self.assertIn("COPY docker-entrypoint.sh .", dockerfile)
        self.assertIn("COPY gunicorn.conf.py .", dockerfile)
        self.assertIn("RUN chmod +x docker-entrypoint.sh", dockerfile)
        self.assertIn('ENTRYPOINT ["./docker-entrypoint.sh"]', dockerfile)
        self.assertIn('CMD ["gunicorn", "-c", "gunicorn.conf.py", "open_cvpn.wsgi:application"]', dockerfile)
        self.assertNotIn('CMD ["python", "manage.py", "runserver"', dockerfile)

    def test_entrypoint_runs_setup_then_executes_configured_command(self):
        entrypoint = self.read_file("docker-entrypoint.sh")

        self.assertIn('python healthcheck.py', entrypoint)
        self.assertIn('if [ "$RUN_MIGRATIONS" = "true" ]; then', entrypoint)
        self.assertIn('python manage.py migrate --noinput', entrypoint)
        self.assertIn('exec "$@"', entrypoint)
        self.assertNotIn('exec gunicorn --bind 0.0.0.0:8000', entrypoint)

    def test_entrypoint_superuser_creation_uses_email_user_contract(self):
        entrypoint = self.read_file("docker-entrypoint.sh")

        self.assertIn('if [ "$CREATE_SUPERUSER" = "true" ]', entrypoint)
        self.assertIn('[ -n "$DJANGO_SUPERUSER_EMAIL" ]', entrypoint)
        self.assertIn('[ -n "$DJANGO_SUPERUSER_PASSWORD" ]', entrypoint)
        self.assertNotIn("DJANGO_SUPERUSER_USERNAME", entrypoint)

    def test_compose_uses_image_startup_for_web_and_list_commands_for_workers(self):
        compose = self.read_file("docker-compose.yml")

        self.assertNotIn("command: python manage.py runserver", compose)
        self.assertIn("RUN_MIGRATIONS=${RUN_MIGRATIONS:-true}", compose)
        self.assertIn('command: ["celery", "-A", "open_cvpn", "worker", "-l", "INFO"]', compose)
        self.assertIn(
            'command: ["celery", "-A", "open_cvpn", "beat", "-l", "INFO", "--schedule", "/tmp/celerybeat-schedule"]',
            compose,
        )

    def test_jwt_signing_key_falls_back_when_env_is_empty(self):
        settings = self.read_file("open_cvpn/settings.py")

        self.assertIn("'SIGNING_KEY': os.getenv('JWT_SECRET_KEY') or SECRET_KEY", settings)


    def test_gunicorn_config_keeps_entrypoint_defaults(self):
        config = self.read_file("gunicorn.conf.py")

        self.assertIn("workers = int(os.environ.get('GUNICORN_WORKERS', 1))", config)
        self.assertIn("threads = int(os.environ.get('GUNICORN_THREADS', 4))", config)
        self.assertIn("timeout = int(os.environ.get('GUNICORN_TIMEOUT', 120))", config)
        self.assertIn(
            "loglevel = os.environ.get('GUNICORN_LOGLEVEL', os.environ.get('GUNICORN_LOG_LEVEL', 'info'))",
            config,
        )


if __name__ == "__main__":
    unittest.main()
