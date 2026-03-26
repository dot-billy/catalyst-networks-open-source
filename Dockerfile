FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install nebula-cert with checksum verification
RUN wget -q https://github.com/slackhq/nebula/releases/download/v1.7.2/nebula-linux-amd64.tar.gz && \
    echo "4600c23344a07c9eda7da4b844730d2e5eb6c36b806eb0e54e4833971f336f70  nebula-linux-amd64.tar.gz" | sha256sum -c - && \
    tar -xzf nebula-linux-amd64.tar.gz && \
    mv nebula-cert /usr/local/bin/ && \
    chmod +x /usr/local/bin/nebula-cert && \
    rm nebula-linux-amd64.tar.gz nebula

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy only necessary application files
COPY manage.py .
COPY open_cvpn/ open_cvpn/
COPY certificates/ certificates/
COPY dashboard/ dashboard/
COPY docs/ docs/
COPY health/ health/
COPY nodes/ nodes/
COPY organizations/ organizations/
COPY security_groups/ security_groups/
COPY templates/ templates/
COPY users/ users/
COPY webhooks/ webhooks/
COPY static/ static/

# Create necessary directories
RUN mkdir -p /app/media/ca /app/media/certs /app/staticfiles

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV DJANGO_SETTINGS_MODULE=open_cvpn.settings

# Create a non-root user
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Default command (can be overridden)
CMD ["python", "manage.py", "runserver", "0.0.0.0:8000"] 