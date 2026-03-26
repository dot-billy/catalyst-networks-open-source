# Catalyst Networks

An open-source platform for managing [Nebula](https://github.com/slackhq/nebula) mesh VPN networks. Built with Django, it provides a web UI and REST API for multi-tenant network management including certificate authorities, node provisioning, IP address management, and security groups.

## Features

- **Multi-tenant organizations** with role-based access control (Owner/Admin/Member)
- **Certificate Authority management** — create CAs, issue and rotate Nebula certificates
- **Node provisioning** — register and manage Nebula endpoints (lighthouses and nodes)
- **IP address management** — automatic IP allocation from organization-scoped CIDR ranges
- **Security groups** — logical firewall groupings for nodes
- **Webhook notifications** — event-driven webhooks for node and certificate lifecycle events
- **Audit logging** — full change history via django-simple-history
- **REST API** with OpenAPI/Swagger documentation
- **Web dashboard** built with Django templates and HTMX

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
python3 -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())"

# Generate a registration token
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Set `DJANGO_SECRET_KEY` and `REGISTRATION_MASTER_TOKEN` in your `.env` file with the generated values.

```bash
# Start all services
docker compose up --build -d

# Run database migrations
docker compose exec web python manage.py migrate

# Create an admin user
docker compose exec web python manage.py createsuperuser

# Visit the app
open http://localhost:8000
```

## Configuration

All configuration is done via environment variables. See `.env.example` for the full list.

| Variable | Description | Default |
|----------|-------------|---------|
| `DJANGO_SECRET_KEY` | **Required.** Django secret key | — |
| `DJANGO_DEBUG` | Enable debug mode | `True` |
| `POSTGRES_DB` | Database name | `open_cvpn` |
| `POSTGRES_USER` | Database user | `postgres` |
| `POSTGRES_PASSWORD` | Database password | `postgres` |
| `REDIS_HOST` | Redis hostname | `redis` |
| `JWT_SECRET_KEY` | JWT signing key | Falls back to `DJANGO_SECRET_KEY` |
| `REGISTRATION_MASTER_TOKEN` | **Required.** Token for node registration API | — |
| `DEFAULT_FROM_EMAIL` | Sender email address | `noreply@example.com` |
| `BASE_URL` | Public URL of the application | `http://localhost:8000` |
| `CERT_STORAGE_ROOT` | Path for certificate storage | `/data/certs` |

## Architecture

| Component | Technology |
|-----------|-----------|
| Framework | Django 5.2 LTS + Django REST Framework |
| Database | PostgreSQL 15 |
| Task Queue | Celery + Redis 7 |
| Frontend | Django templates + HTMX |
| Auth | JWT (simplejwt) + custom User model |
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
