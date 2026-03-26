from django.db import models
from django.conf import settings
from organizations.models import Organization
from simple_history.models import HistoricalRecords
import os
import subprocess
from django.utils import timezone
from dateutil import parser as dateutil_parser
from datetime import timezone as dt_timezone
from django.core.files.base import ContentFile
from io import BytesIO
import qrcode

def ca_cert_path(instance, filename):
    """Generate path for CA certificate storage"""
    return f'ca/{instance.organization.id}/{filename}'

def ca_key_path(instance, filename):
    """Generate path for CA private key storage"""
    return f'ca/{instance.organization.id}/{filename}'

class CertificateAuthority(models.Model):
    """Model for managing Nebula Certificate Authorities"""
    name = models.CharField(max_length=255)
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='certificate_authorities')
    ca_cert = models.FileField(upload_to=ca_cert_path, storage=settings.CERT_STORAGE)
    ca_key = models.FileField(upload_to=ca_key_path, storage=settings.CERT_STORAGE)
    created_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Certificate Authority'
        verbose_name_plural = 'Certificate Authorities'
        constraints = [
            models.UniqueConstraint(fields=['name', 'organization'], name='unique_ca_name_org'),
        ]

    def __str__(self):
        return f"{self.name} ({self.organization.name})"

    @property
    def is_valid(self):
        """Return True if the CA certificate has not expired."""
        try:
            result = subprocess.run([
                'nebula-cert', 'print',
                '-path', self.ca_cert.path
            ], capture_output=True, text=True, check=True)
            for line in result.stdout.split('\n'):
                if 'Not After' in line:
                    exp_str = line.split(': ', 1)[1].strip()
                    if exp_str.endswith(" UTC"):
                        exp_str = exp_str[:-4]
                    parts = exp_str.split()
                    date_part = parts[0]
                    time_part = parts[1]
                    exp_dt = timezone.datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
                    exp_dt = exp_dt.replace(tzinfo=dt_timezone.utc)
                    return exp_dt > timezone.now()
            return False
        except Exception as e:
            print("CA is_valid error:", e)
            return False

    def delete(self, *args, **kwargs):
        """Delete associated files when CA is deleted"""
        if self.ca_cert:
            if os.path.isfile(self.ca_cert.path):
                os.remove(self.ca_cert.path)
        if self.ca_key:
            if os.path.isfile(self.ca_key.path):
                os.remove(self.ca_key.path)
        super().delete(*args, **kwargs)


def ca_qr_path(instance, filename):
    """Generate path for CA QR storage."""
    return f'ca_qr/{instance.certificate_authority.organization.id}/{instance.certificate_authority.id}/{filename}'


class CertificateAuthorityQRCode(models.Model):
    """QR code artifact for a certificate authority."""
    certificate_authority = models.OneToOneField(
        CertificateAuthority,
        on_delete=models.CASCADE,
        related_name='qr_code',
    )
    qr_image = models.ImageField(
        upload_to=ca_qr_path,
        help_text='Generated CA QR code image file',
    )
    source = models.CharField(
        max_length=32,
        default='nebula_print',
        help_text='How this QR was generated',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-updated_at']

    def __str__(self):
        return f"CA QR for {self.certificate_authority.name}"

    @classmethod
    def create_or_update_for_ca_image(cls, certificate_authority, qr_bytes, source='nebula_out_qr'):
        """Persist a CA QR image produced externally (e.g., nebula-cert -out-qr)."""
        filename = f"ca_qr_{certificate_authority.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.png"
        qr_record, _ = cls.objects.get_or_create(certificate_authority=certificate_authority)
        qr_record.qr_image.save(filename, ContentFile(qr_bytes), save=False)
        qr_record.source = source
        qr_record.save()
        return qr_record

    @classmethod
    def create_or_update_for_ca(cls, certificate_authority):
        """Generate and store a CA QR code using nebula cert data."""
        payload = None
        source = 'nebula_print'
        try:
            result = subprocess.run(
                ['nebula-cert', 'print', '-path', certificate_authority.ca_cert.path],
                capture_output=True,
                text=True,
                check=True,
            )
            payload = result.stdout.strip()
        except Exception:
            # Fallback to raw cert content if nebula print isn't available.
            source = 'cert_pem_fallback'
            with open(certificate_authority.ca_cert.path, 'r', encoding='utf-8') as cert_file:
                payload = cert_file.read().strip()

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')

        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        filename = f"ca_qr_{certificate_authority.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.png"

        qr_record, _ = cls.objects.get_or_create(certificate_authority=certificate_authority)
        qr_record.qr_image.save(filename, ContentFile(buffer.getvalue()), save=False)
        qr_record.source = source
        qr_record.save()
        return qr_record
