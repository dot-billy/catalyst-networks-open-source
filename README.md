# Catalyst Networks

An open-source platform for managing [Nebula](https://github.com/slackhq/nebula) mesh VPN networks. Built with Django, it provides a web UI and REST API for multi-tenant network management including certificate authorities, node provisioning, IP address management, and security groups.

## Features

- **Multi-tenant organizations** with role-based access control (Owner/Admin/Member)
- **Certificate Authority management** — create CAs, issue and rotate Nebula certificates
- **Node provisioning** — register and manage Nebula endpoints (lighthouses and nodes)
- **IP address management** — automatic IP allocation from organization-scoped CIDR ranges
- **Security groups** — logical firewall groupings for nodes
- **SAML SSO** — organization-managed SAML login enforcement
- **Webhook notifications** — event-driven webhooks for node and certificate lifecycle events
- **Slack notifications** — optional incoming webhook delivery for organization events
- **Audit logging** — full change history via django-simple-history
- **Bulk operations** — CSV import/export, batch deletion, and batch certificate renewal
- **REST API** with OpenAPI/Swagger documentation
- **Web dashboard** built with Django templates and HTMX
- **Built-in documentation** — in-app guides for setup, networking, certificates, API, and troubleshooting

## Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/your-org/catalyst-networks-open-source.git
cd catalyst-networks-open-source

# Copy the example environment file
cp .env.example .env
```

Edit `.env` and set the required values:

```bash
# Generate a Django secret key
python3 -c "import secrets; print(secrets.token_urlsafe(50))"

# Generate a node registration token
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set `DJANGO_SECRET_KEY` and `REGISTRATION_MASTER_TOKEN` in your `.env` file with the generated values. `REGISTRATION_MASTER_TOKEN` is for node registration API access, not human account registration.

```bash
# Start all services
docker compose up --build -d

# Create the first admin account on a fresh database
open http://localhost:8000/register/

# Visit the app
open http://localhost:8000
```

The Docker Compose web service runs database migrations on startup by default,
then starts the Django app with Gunicorn. Set `RUN_MIGRATIONS=false` in the
shell before running Compose if you need to manage migrations manually. Do not
run the entrypoint migrations and a separate `docker compose exec web python
manage.py migrate` at the same time against a fresh database.

On a fresh database, the first human account can be created from `/register/`.
After any user exists, human registration is invitation-only by default.

There are two supported first-admin deployment paths:

- Default interactive bootstrap: set `ALLOW_BOOTSTRAP_REGISTRATION=True` and
  `ALLOW_PUBLIC_REGISTRATION=False`, start the stack, then create the first
  admin at `/register/`.
- Non-interactive seeded superuser: set `CREATE_SUPERUSER=true`,
  `DJANGO_SUPERUSER_EMAIL`, and `DJANGO_SUPERUSER_PASSWORD`. This is usually
  paired with `ALLOW_BOOTSTRAP_REGISTRATION=False`.

## Configuration

All configuration is done via environment variables. See `.env.example` for the full list.

| Variable | Description | Default |
|----------|-------------|---------|
| `DJANGO_SECRET_KEY` | **Required.** Django secret key | — |
| `DJANGO_DEBUG` | Enable debug mode | `False` in settings; `.env.example` enables it for local use |
| `DJANGO_ALLOWED_HOSTS` | Comma-separated allowed hostnames | `localhost,127.0.0.1` |
| `WEB_PORT` | Host port used by Docker Compose for the web service | `8000` |
| `DJANGO_LOG_FILE` | Optional writable file path for Django logs | Empty; logs go to console |
| `ALLOW_BOOTSTRAP_REGISTRATION` | Allow `/register/` to create the first human admin account when no users exist | `True` in `.env.example`; `False` in `.env.prod.example` |
| `ALLOW_PUBLIC_REGISTRATION` | Allow public human account registration after users exist | `False` |
| `CREATE_SUPERUSER` | Optionally seed the first superuser during container startup when email and password are also set | Empty |
| `DJANGO_SUPERUSER_EMAIL` | Email address for optional non-interactive superuser creation | Empty |
| `DJANGO_SUPERUSER_PASSWORD` | Password for optional non-interactive superuser creation; inject as a secret | Empty |
| `POSTGRES_DB` | Database name | `open_cvpn` |
| `POSTGRES_USER` | Database user | `postgres` |
| `POSTGRES_PASSWORD` | Database password | `postgres` |
| `REDIS_HOST` | Redis hostname | `redis` |
| `JWT_SECRET_KEY` | JWT signing key | Falls back to `DJANGO_SECRET_KEY` |
| `REGISTRATION_MASTER_TOKEN` | **Required.** Token for node registration API; unrelated to human account registration | — |
| `FIELD_ENCRYPTION_KEY` | Fernet key for Slack webhook storage | Empty; required before saving Slack webhooks |
| `DEFAULT_FROM_EMAIL` | Sender email address | `noreply@example.com` |
| `BASE_URL` | Public URL of the application | `http://localhost:8000` |
| `STATIC_ASSET_VERSION` | Optional cache-busting version for static URLs | Project version |
| `CERT_STORAGE_ROOT` | Path for certificate storage | `/data/certs` |
| `RUN_MIGRATIONS` | Run migrations when the Compose web service starts | `true` |

The default Docker Compose stack publishes only the Django web service on `8000`.
PostgreSQL and Redis stay on the internal Compose network.
If another local project already uses port `8000`, set `WEB_PORT=18000` before
running Compose and visit `http://localhost:18000`.

### DigitalOcean Smoke Test

For a temporary remote smoke test, create a small Ubuntu droplet, copy this
repository to it, generate a fresh `.env`, and run:

```bash
sudo apt-get update
sudo apt-get install -y docker.io docker-compose-v2

docker compose up --build -d
curl -fsS http://DROPLET_IP:8000/health/
curl -fsSI http://DROPLET_IP:8000/login/
python3 tools/smoke_bootstrap_registration.py --base-url http://DROPLET_IP:8000
```

Set `DJANGO_ALLOWED_HOSTS` to include the droplet IP and delete the droplet when
the smoke test is complete. The smoke script creates the first account through
the default interactive bootstrap path, verifies `/register/` closes afterward,
and never prints the password. To use a known password for the smoke, set
`SMOKE_BOOTSTRAP_PASSWORD` in the shell before running it.

There are two supported first-user deployment choices:

- Interactive bootstrap, the OSS default: keep `ALLOW_BOOTSTRAP_REGISTRATION=True`
  and `ALLOW_PUBLIC_REGISTRATION=False`, then create the first admin at
  `/register/`. After that account exists, public registration closes.
- Non-interactive seeding: set `ALLOW_BOOTSTRAP_REGISTRATION=False`,
  `CREATE_SUPERUSER=true`, `DJANGO_SUPERUSER_EMAIL`, and
  `DJANGO_SUPERUSER_PASSWORD` for the first startup. Inject the password as a
  secret and remove or disable the seeding variables after the account exists.

For an explicit migration smoke on a fresh database, disable entrypoint
migrations first and run exactly one migration command before starting the full
stack:

```bash
RUN_MIGRATIONS=false docker compose up --build -d db redis
RUN_MIGRATIONS=false docker compose run --rm -T web python manage.py migrate --noinput </dev/null
RUN_MIGRATIONS=false docker compose up -d
```

## Architecture

| Component | Technology |
|-----------|-----------|
| Framework | Django 5.2 LTS + Django REST Framework |
| Database | PostgreSQL 15 |
| Task Queue | Celery + Redis 7 |
| Frontend | Django templates + HTMX |
| Auth | JWT (simplejwt), SAML SSO, custom User model |
| API Docs | OpenAPI/Swagger (drf-spectacular) |
| Audit | django-simple-history |
| Security | django-axes (brute-force protection) |

## API Documentation

Once running, API docs are available at:

- **Swagger UI:** http://localhost:8000/api/docs/
- **ReDoc:** http://localhost:8000/api/redoc/

## Development

### Running without Docker

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env with your local Postgres and Redis connection details
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```

### Running Tests

```bash
docker compose exec web python manage.py test
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

Built on [Nebula](https://github.com/slackhq/nebula) by Slack/Netflix — a scalable overlay networking tool.
