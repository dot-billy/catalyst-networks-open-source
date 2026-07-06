from django.db import models
from django.conf import settings
from organizations.models import Organization
from certificates.models import CertificateAuthority
from security_groups.models import Tag
from simple_history.models import HistoricalRecords
from django.core.exceptions import ValidationError
from django.utils import timezone
import os
import ipaddress
from django.contrib.auth import get_user_model
import uuid
from datetime import timedelta

def node_cert_path(instance, filename):
    """Generate path for node certificate storage"""
    return f'certs/{instance.organization.id}/{instance.name}/{filename}'

def node_key_path(instance, filename):
    """Generate path for node private key storage"""
    return f'certs/{instance.organization.id}/{instance.name}/{filename}'

class Node(models.Model):
    """
    Node model for managing Nebula endpoints.
    """
    name = models.CharField(max_length=255, help_text='Hostname or description of the node')
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='nodes'
    )
    certificate_authority = models.ForeignKey(
        CertificateAuthority,
        on_delete=models.CASCADE,
        related_name='nodes'
    )
    nebula_ip = models.GenericIPAddressField(
        help_text='IP address in the organization\'s network range'
    )
    tags = models.ManyToManyField(
        'security_groups.Tag',
        related_name='nodes',
        blank=True,
        # Explicit through model pins the existing join table AND its existing
        # columns (node_id, securitygroup_id). Renaming the target model to Tag
        # would otherwise make Django expect a tag_id column; the explicit
        # through with db_column keeps the rename byte-for-byte / DDL-free.
        through='nodes.NodeTag',
        help_text='Tags applied to this node (become Nebula cert groups).'
    )
    cert_path = models.FileField(
        upload_to=node_cert_path,
        storage=settings.CERT_STORAGE,
        null=True,
        blank=True,
        help_text='Path to the node\'s certificate'
    )
    key_path = models.FileField(
        upload_to=node_key_path,
        storage=settings.CERT_STORAGE,
        null=True,
        blank=True,
        help_text='Path to the node\'s private key'
    )
    cert_expiration = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Certificate expiration date'
    )
    is_lighthouse = models.BooleanField(
        default=False,
        help_text='Whether this node is a lighthouse'
    )
    public_ip = models.GenericIPAddressField(
        null=True,
        blank=True,
        help_text='Public IP address for lighthouse nodes'
    )
    fqdn = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        help_text='Fully Qualified Domain Name for lighthouse nodes'
    )
    external_port = models.IntegerField(
        default=4242,
        help_text='External port for lighthouse nodes'
    )
    created_by = models.ForeignKey(
        get_user_model(),
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_nodes',
        help_text='The user who created this node'
    )
    assigned_user = models.ForeignKey(
        get_user_model(),
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_mobile_nodes',
        help_text='The user this mobile node is assigned to'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    api_token = models.CharField(
        max_length=64,
        unique=True,
        blank=True,
        null=True,
        help_text='Unique API token for authenticating this node''s API requests'
    )
    last_checkin = models.DateTimeField(
        null=True,
        blank=True,
        help_text='Last time this node checked in via API'
    )
    config_overrides = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            'Custom Nebula config keys deep-merged into this node\'s generated '
            'config, on top of any org-level overrides. The "pki" key is '
            'protected and ignored.'
        )
    )
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Node'
        verbose_name_plural = 'Nodes'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.name} ({self.nebula_ip})"

    def clean(self):
        """
        Validate that the IP address is within the organization's network range.
        """
        if self.nebula_ip and self.organization:
            try:
                node_ip = ipaddress.ip_address(self.nebula_ip)
                network_ranges = self.organization.network_ranges.all()
                
                if not any(node_ip in ipaddress.ip_network(net_range.cidr) for net_range in network_ranges):
                    raise ValidationError({
                        'nebula_ip': 'IP address must be within one of the organization\'s network ranges.'
                    })
            except ValueError:
                raise ValidationError({
                    'nebula_ip': 'Invalid IP address format.'
                })

    def delete(self, *args, **kwargs):
        """Delete associated files when node is deleted"""
        if self.cert_path:
            if os.path.isfile(self.cert_path.path):
                os.remove(self.cert_path.path)
        if self.key_path:
            if os.path.isfile(self.key_path.path):
                os.remove(self.key_path.path)
        super().delete(*args, **kwargs)

    def get_cert_path(self):
        """Returns the absolute path to the node certificate file."""
        return self.cert_path.path if self.cert_path else None

    def get_key_path(self):
        """Returns the absolute path to the node private key file."""
        return self.key_path.path if self.key_path else None

    def get_next_available_ip(self):
        """
        Find the next available IP address in the organization's network range.
        """
        if not self.organization:
            return None
        
        network_ranges = self.organization.network_ranges.all()
        if not network_ranges:
            return None
        
        # For now, just use the first network range
        network_range = network_ranges.first()
        network = ipaddress.ip_network(network_range.cidr)
        
        # Get all used IPs in this organization
        used_ips = set()
        for node in Node.objects.filter(organization=self.organization):
            try:
                # Handle IP strings that might have CIDR notation
                ip_str = node.nebula_ip
                if ip_str and '/' in ip_str:
                    ip_str = ip_str.split('/')[0]
                used_ips.add(ipaddress.ip_address(ip_str))
            except ValueError:
                continue
        
        # Find the first available IP
        for ip in network.hosts():
            if ip not in used_ips:
                return str(ip)
        
        return None

    def save(self, *args, **kwargs):
        """
        Validate the node before saving and assign an IP if none is provided.
        """
        if not self.nebula_ip:
            self.nebula_ip = self.get_next_available_ip()
            if not self.nebula_ip:
                raise ValidationError({
                    'nebula_ip': 'No available IP addresses in the organization\'s network range.'
                })
        
        # Allow created_by to be None
        if getattr(self, 'created_by', None) is None:
            # For nodes created through registration, created_by can be null
            pass
        
        self.full_clean()
        super().save(*args, **kwargs)

    def get_all_applicable_firewall_rules(self):
        """
        Get all firewall rules applicable to this node, including:
        1. Rules directly attached to this node
        2. Legacy rules attached to tags through security_group
        3. Rules targeting tags through target_groups
        
        Returns a QuerySet of FirewallRule objects.
        """
        from django.db.models import Q
        from security_groups.models import FirewallRule
        
        # Get rules directly attached to this node
        direct_rules = FirewallRule.objects.filter(node=self)

        # Support both the legacy FK and the new target_groups path during the
        # Tag/Rule transition.
        tag_ids = self.tags.values_list('id', flat=True)
        group_rules = FirewallRule.objects.filter(
            Q(security_group_id__in=tag_ids) | Q(target_groups__in=tag_ids)
        )

        # Combine and return unique rules
        return (direct_rules | group_rules).distinct()

    @property
    def security_groups(self):
        """Backward-compatible name for callers that still treat tags as groups."""
        return self.tags


class NodeTag(models.Model):
    """
    Explicit through model for the Node.tags M2M.

    It reproduces the pre-existing auto-generated join table exactly: same table
    name (nodes_node_security_groups) and same columns (node_id,
    securitygroup_id). This lets us rename the target model SecurityGroup -> Tag
    with ZERO schema change — the column stays ``securitygroup_id`` via db_column
    rather than becoming the model-derived ``tag_id``.
    """
    node = models.ForeignKey(
        'nodes.Node',
        on_delete=models.CASCADE,
        db_column='node_id',
    )
    tag = models.ForeignKey(
        'security_groups.Tag',
        on_delete=models.CASCADE,
        db_column='securitygroup_id',
    )

    class Meta:
        db_table = 'nodes_node_security_groups'
        unique_together = (('node', 'tag'),)

def generate_token():
    """Generate a unique registration token"""
    return str(uuid.uuid4())

class NodeRegistrationToken(models.Model):
    """
    Model for managing node registration tokens.
    Each token is linked to an organization and can be used to securely register nodes.
    """
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='registration_tokens'
    )
    token = models.CharField(
        max_length=255,
        default=generate_token,
        unique=True,
        help_text='Unique token for node registration'
    )
    description = models.CharField(
        max_length=255,
        help_text='Description or purpose of this token'
    )
    created_by = models.ForeignKey(
        get_user_model(),
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_tokens',
        help_text='The user who created this token'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text='Expiration date of the token'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this token is currently active'
    )
    uses_allowed = models.IntegerField(
        default=-1,  # -1 means unlimited
        help_text='Number of times this token can be used (-1 for unlimited)'
    )
    uses_count = models.IntegerField(
        default=0,
        help_text='Number of times this token has been used'
    )
    can_register_regular = models.BooleanField(
        default=True,
        help_text='Whether this token can register regular nodes'
    )
    can_register_lighthouse = models.BooleanField(
        default=False,
        help_text='Whether this token can register lighthouse nodes'
    )
    
    class Meta:
        verbose_name = 'Node Registration Token'
        verbose_name_plural = 'Node Registration Tokens'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Token for {self.organization.name} - {self.description}"
    
    def is_valid(self):
        """Check if the token is valid for use"""
        now = timezone.now()
        if not self.is_active:
            return False
        if now > self.expires_at:
            return False
        if self.uses_allowed != -1 and self.uses_count >= self.uses_allowed:
            return False
        return True
    
    @property
    def is_revoked(self):
        """Check if the token has been manually revoked"""
        return not self.is_active
    
    @property
    def is_expired(self):
        """Check if the token has expired"""
        return timezone.now() > self.expires_at
    
    @property
    def is_used_up(self):
        """Check if all allowed uses have been consumed"""
        return self.uses_allowed != -1 and self.uses_count >= self.uses_allowed
    
    def use_token(self):
        """Mark token as used once"""
        if not self.is_valid():
            return False
        
        self.uses_count += 1
        if self.uses_allowed != -1 and self.uses_count >= self.uses_allowed:
            self.is_active = False
        
        self.save()
        return True
    
    @classmethod
    def create_for_organization(cls, organization, description, created_by,
                               days_valid=30, uses_allowed=-1):
        """Create a new registration token for an organization"""
        expires_at = timezone.now() + timedelta(days=days_valid)

        return cls.objects.create(
            organization=organization,
            description=description,
            created_by=created_by,
            expires_at=expires_at,
            uses_allowed=uses_allowed
        )


def node_qr_path(instance, filename):
    """Generate path for node QR code storage"""
    return f'qr_codes/{instance.node.organization.id}/{instance.node.id}/{filename}'


class NodeQRCode(models.Model):
    """
    QR code for mobile device enrollment of a node.
    Stores the generated QR code image and enrollment data.
    """
    node = models.OneToOneField(
        Node,
        on_delete=models.CASCADE,
        related_name='qr_code'
    )
    qr_image = models.ImageField(
        upload_to=node_qr_path,
        help_text='Generated QR code image file'
    )
    enrollment_token = models.CharField(
        max_length=255,
        unique=True,
        help_text='Secure token for enrollment URL'
    )
    enrollment_url = models.URLField(
        help_text='Full enrollment URL encoded in QR code'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField(
        help_text='When this QR code expires and should be regenerated'
    )
    is_active = models.BooleanField(
        default=True,
        help_text='Whether this QR code is still valid for use'
    )

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"QR Code for {self.node.name}"

    @property
    def is_expired(self):
        """Check if the QR code has expired"""
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        """Check if the QR code is still valid for use"""
        return self.is_active and not self.is_expired

    def deactivate(self):
        """Mark this QR code as inactive"""
        self.is_active = False
        self.save()

    @classmethod
    def create_or_update_for_node_image(cls, node, qr_bytes, days_valid=7):
        """Create or update QR record using already-generated PNG bytes."""
        import secrets
        from django.core.files.base import ContentFile

        enrollment_token = secrets.token_urlsafe(32)
        enrollment_url = f"{settings.BASE_URL}/api/org/{node.organization.slug}/nodes/{node.id}/enroll?token={enrollment_token}"
        filename = f"qr_{node.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.png"

        qr_code, _ = cls.objects.get_or_create(
            node=node,
            defaults={
                'enrollment_token': enrollment_token,
                'enrollment_url': enrollment_url,
                'expires_at': timezone.now() + timedelta(days=days_valid),
                'is_active': True,
            }
        )
        qr_code.qr_image.save(filename, ContentFile(qr_bytes), save=False)
        qr_code.enrollment_token = enrollment_token
        qr_code.enrollment_url = enrollment_url
        qr_code.expires_at = timezone.now() + timedelta(days=days_valid)
        qr_code.is_active = True
        qr_code.save()
        return qr_code

    @classmethod
    def create_for_node(cls, node, days_valid=7):
        """Create a new QR code for a node"""
        import secrets
        import qrcode
        from io import BytesIO
        from django.core.files.base import ContentFile

        # Generate secure enrollment token
        enrollment_token = secrets.token_urlsafe(32)

        # Build enrollment URL
        enrollment_url = f"{settings.BASE_URL}/api/org/{node.organization.slug}/nodes/{node.id}/enroll?token={enrollment_token}"

        # Generate QR code
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(enrollment_url)
        qr.make(fit=True)

        # Create QR code image
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)

        qr_code, _ = cls.objects.get_or_create(
            node=node,
            defaults={
                'enrollment_token': enrollment_token,
                'enrollment_url': enrollment_url,
                'expires_at': timezone.now() + timedelta(days=days_valid),
                'is_active': True,
            }
        )
        filename = f"qr_{node.id}_{timezone.now().strftime('%Y%m%d_%H%M%S')}.png"
        qr_code.qr_image.save(filename, ContentFile(buffer.getvalue()), save=False)
        qr_code.enrollment_token = enrollment_token
        qr_code.enrollment_url = enrollment_url
        qr_code.expires_at = timezone.now() + timedelta(days=days_valid)
        qr_code.is_active = True
        qr_code.save()
        return qr_code
