import logging

from certificates.models import CertificateAuthority

logger = logging.getLogger(__name__)

def _get_latest_org_ca(org):
    """Return the most recently created CA for the organization."""
    return CertificateAuthority.objects.filter(organization=org).order_by('-created_at').first()

# Node registration serializer
