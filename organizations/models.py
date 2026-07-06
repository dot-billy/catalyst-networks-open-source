from django.db import models
from django.conf import settings
from simple_history.models import HistoricalRecords
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.text import slugify
import ipaddress
import secrets
from django.db import transaction

User = get_user_model()

class Organization(models.Model):
    """
    Organization model for grouping users and resources.
    """
    name = models.CharField(max_length=255, unique=True)
    slug = models.SlugField(max_length=255, unique=True, blank=True, null=True, default="")
    created_by = models.ForeignKey(
        User,
        on_delete=models.PROTECT,
        related_name='created_organizations'
    )
    created_at = models.DateTimeField(default=timezone.now)
    members = models.ManyToManyField(
        User,
        through='Membership',
        related_name='organizations'
    )
    config_overrides = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            'Custom Nebula config keys deep-merged into every generated node '
            'config for this org (e.g. {"punchy": {"respond": true}}). '
            'The "pki" key is protected and ignored.'
        )
    )
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Organization'
        verbose_name_plural = 'Organizations'
        ordering = ['name']

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        """
        Ensure organization has a unique slug before saving.
        """
        if not self.slug:
            base_slug = slugify(self.name)
            slug = base_slug
            counter = 1
            
            # Ensure uniqueness of slugs
            while Organization.objects.filter(slug=slug).exists():
                slug = f"{base_slug}-{counter}"
                counter += 1
                
            self.slug = slug
            
        super().save(*args, **kwargs)

class NetworkRange(models.Model):
    """
    NetworkRange model for managing IP address ranges for organizations.
    """
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='network_ranges'
    )
    cidr = models.CharField(max_length=32, help_text='CIDR notation (e.g., 192.168.100.0/24)')
    description = models.TextField(blank=True, help_text='Optional description of the network range')
    created_at = models.DateTimeField(default=timezone.now)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Network Range'
        verbose_name_plural = 'Network Ranges'
        constraints = [
            models.UniqueConstraint(fields=['organization', 'cidr'], name='unique_org_cidr'),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.cidr} ({self.organization.name})"

    def clean(self):
        """
        Validate the CIDR notation.
        """
        try:
            network = ipaddress.ip_network(self.cidr)
            # Allow private IP ranges and CGNAT (100.64.0.0/10) range
            cgnat_network = ipaddress.ip_network('100.64.0.0/10')
            
            if not network.is_private and not network.overlaps(cgnat_network):
                raise models.ValidationError("Only private IP ranges and CGNAT (100.64.0.0/10) ranges are allowed")
        except ValueError:
            raise models.ValidationError("Invalid CIDR notation")

    def save(self, *args, **kwargs):
        """
        Validate CIDR before saving.
        """
        self.clean()
        super().save(*args, **kwargs)

class Membership(models.Model):
    """
    Through model for Organization-User relationship with role information.
    """
    ROLE_CHOICES = [
        ('owner', 'Owner'),
        ('admin', 'Admin'),
        ('member', 'Member'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='memberships')
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name='memberships')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='member')
    created_at = models.DateTimeField(default=timezone.now)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Membership'
        verbose_name_plural = 'Memberships'
        constraints = [
            models.UniqueConstraint(fields=['user', 'organization'], name='unique_user_org'),
        ]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} - {self.organization.name} ({self.role})"

def generate_invitation_token():
    return secrets.token_urlsafe(32)

class Invitation(models.Model):
    """
    Model for managing organization membership invitations.
    """
    organization = models.ForeignKey(
        Organization,
        on_delete=models.CASCADE,
        related_name='invitations'
    )
    email = models.EmailField()
    inviter = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='sent_invitations'
    )
    token = models.CharField(
        max_length=255,
        unique=True,
        default=generate_invitation_token
    )
    role = models.CharField(
        max_length=10,
        choices=Membership.ROLE_CHOICES,
        default='member'
    )
    status = models.CharField(
        max_length=20,
        choices=[
            ('pending', 'Pending'),
            ('accepted', 'Accepted'),
            ('revoked', 'Revoked'),
            ('expired', 'Expired'),
        ],
        default='pending'
    )
    created_at = models.DateTimeField(default=timezone.now)
    accepted_at = models.DateTimeField(null=True, blank=True)
    revoked_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Invitation'
        verbose_name_plural = 'Invitations'
        ordering = ['-created_at']
        constraints = [
            models.UniqueConstraint(fields=['organization', 'email', 'status'], name='unique_org_email_status'),
        ]

    def __str__(self):
        return f"Invitation for {self.email} to {self.organization.name}"

    def save(self, *args, **kwargs):
        # Set expiration date if not set
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(days=7)
        super().save(*args, **kwargs)

    def accept(self, user):
        """
        Accept the invitation and create membership for the user.
        Returns the created membership if successful, None otherwise.
        """
        if self.status != 'pending':
            return None
        
        if user.email.lower() != self.email.lower():
            return None

        with transaction.atomic():
            membership, _ = Membership.objects.get_or_create(
                organization=self.organization,
                user=user,
                defaults={'role': self.role}
            )
            self.status = 'accepted'
            self.accepted_at = timezone.now()
            self.save()
            return membership

    def revoke(self):
        """
        Revoke the invitation if it's still pending.
        """
        if self.status == 'pending':
            self.status = 'revoked'
            self.revoked_at = timezone.now()
            self.save()
            return True
        return False

    @property
    def is_expired(self):
        """Check if the invitation has expired."""
        return timezone.now() > self.expires_at

    @property
    def is_valid(self):
        """Check if the invitation can still be accepted."""
        return (
            self.status == 'pending' and
            not self.is_expired
        )
