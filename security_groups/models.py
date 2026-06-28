from django.db import models
from simple_history.models import HistoricalRecords

class Tag(models.Model):
    """A membership label on nodes. A tag on a node becomes a Nebula cert `groups:` entry."""
    name = models.CharField(max_length=255)
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='tags'
    )
    description = models.TextField(blank=True)
    color = models.CharField(max_length=7, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True)
    # Keep the existing history table — the model rename is state-only, no data move.
    history = HistoricalRecords(table_name='security_groups_historicalsecuritygroup')

    class Meta:
        db_table = 'security_groups_securitygroup'   # keep existing table — no data move
        verbose_name = 'Tag'
        verbose_name_plural = 'Tags'
        constraints = [
            models.UniqueConstraint(fields=['name', 'organization'], name='unique_sg_name_org'),
        ]

    def __str__(self):
        return f"{self.name} ({self.organization.name})"

class FirewallRule(models.Model):
    """
    FirewallRule model - rules can be attached to either nodes or security groups.
    """
    PROTOCOL_CHOICES = [
        ('tcp', 'TCP'),
        ('udp', 'UDP'),
        ('icmp', 'ICMP'),
        ('any', 'Any Protocol'),
    ]
    
    # Rule can be attached to a node or a security group (but not both)
    node = models.ForeignKey(
        'nodes.Node',
        on_delete=models.CASCADE,
        related_name='firewall_rules',
        null=True,
        blank=True,
        help_text='Node this rule applies to (if not attached to a security group)'
    )
    security_group = models.ForeignKey(
        Tag,
        on_delete=models.CASCADE,
        related_name='firewall_rules',
        null=True,
        blank=True,
        help_text='Security group this rule applies to (if not attached to a specific node)'
    )
    DIRECTION_CHOICES = [('in', 'Inbound'), ('out', 'Outbound')]
    MATCH_TYPE_CHOICES = [('groups', 'Tags'), ('host', 'Host/Node'), ('cidr', 'CIDR'), ('any', 'Any')]

    protocol = models.CharField(
        max_length=10,
        choices=PROTOCOL_CHOICES,
        default='tcp',
        help_text='Network protocol this rule applies to'
    )
    direction = models.CharField(max_length=3, choices=DIRECTION_CHOICES, default='in',
                                 help_text='Inbound rules gate traffic INTO the target; outbound gates traffic OUT.')
    match_type = models.CharField(max_length=6, choices=MATCH_TYPE_CHOICES, default='any',
                                  help_text='Which source/destination field is authoritative.')
    target_groups = models.ManyToManyField(
        'security_groups.Tag', blank=True, related_name='rules_targeting',
        help_text='Tags whose nodes this rule applies TO (replaces the single security_group FK).')
    port_min = models.IntegerField(
        null=True,
        blank=True,
        help_text='Starting port (inclusive)'
    )
    port_max = models.IntegerField(
        null=True,
        blank=True,
        help_text='Ending port (inclusive)'
    )
    source_cidr = models.CharField(
        max_length=50,
        blank=True,
        default='',
        help_text='Source CIDR block (optional)'
    )
    source_groups = models.ManyToManyField(
        'security_groups.Tag',
        blank=True,
        related_name='rules_as_source',
        # Explicit through model pins the existing join table and its existing
        # columns. Renaming SecurityGroup -> Tag would otherwise make Django
        # expect a tag_id column; db_column='securitygroup_id' keeps it DDL-free.
        through='security_groups.FirewallRuleSourceGroup',
        help_text='Source security groups allowed by this rule'
    )
    source_nodes = models.ManyToManyField(
        'nodes.Node',
        blank=True,
        related_name='rules_as_source',
        help_text='Source nodes allowed by this rule'
    )
    description = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Firewall Rule'
        verbose_name_plural = 'Firewall Rules'

    def __str__(self):
        target = self.node.name if self.node else f"Group: {self.security_group.name}"
        
        if self.protocol in ['tcp', 'udp'] and self.port_min and self.port_max:
            if self.port_min == self.port_max:
                return f"{target}: {self.protocol.upper()} port {self.port_min} from {self.source_cidr}"
            else:
                return f"{target}: {self.protocol.upper()} ports {self.port_min}-{self.port_max} from {self.source_cidr}"
        else:
            return f"{target}: {self.protocol.upper()} from {self.source_cidr}"

    def clean(self):
        """
        Validate the rule's configuration.
        """
        from django.core.exceptions import ValidationError
        
        # Rule must target at least one of: a node, the legacy security_group FK, or target_groups.
        has_target = bool(self.node_id) or bool(self.security_group_id) or (self.pk and self.target_groups.exists())
        if not has_target:
            raise ValidationError("Rule must target a node, a tag, or one or more target groups")

        if self.node_id and self.security_group_id:
            raise ValidationError("Rule cannot be attached to both a node and a security group")
        
        # ICMP doesn't use ports
        if self.protocol == 'icmp' and (self.port_min is not None or self.port_max is not None):
            self.port_min = None
            self.port_max = None
            
        # For 'any' protocol, ports should be None
        if self.protocol == 'any':
            self.port_min = None
            self.port_max = None
            
        # For TCP/UDP, validate port range if provided
        if self.protocol in ['tcp', 'udp']:
            if (self.port_min is not None and self.port_max is not None):
                if self.port_min > self.port_max:
                    raise ValidationError("Starting port must be less than or equal to ending port")
                if self.port_min < 1 or self.port_max > 65535:
                    raise ValidationError("Ports must be between 1 and 65535")
    
    def save(self, *args, **kwargs):
        self.clean()
        super().save(*args, **kwargs)

    @staticmethod
    def get_common_rule_templates():
        """
        Return templates for common firewall rules that can be easily applied.
        """
        return {
            'ssh': {
                'protocol': 'tcp',
                'port_min': 22, 
                'port_max': 22,
                'source_cidr': '10.0.0.0/8',
                'description': 'SSH access'
            },
            'http': {
                'protocol': 'tcp',
                'port_min': 80,
                'port_max': 80,
                'source_cidr': '0.0.0.0/0',
                'description': 'HTTP access'
            },
            'https': {
                'protocol': 'tcp',
                'port_min': 443,
                'port_max': 443,
                'source_cidr': '0.0.0.0/0',
                'description': 'HTTPS access'
            },
            'mysql': {
                'protocol': 'tcp',
                'port_min': 3306,
                'port_max': 3306,
                'source_cidr': '10.0.0.0/8',
                'description': 'MySQL access'
            },
            'postgres': {
                'protocol': 'tcp',
                'port_min': 5432,
                'port_max': 5432,
                'source_cidr': '10.0.0.0/8',
                'description': 'PostgreSQL access'
            }
        }


class FirewallRuleSourceGroup(models.Model):
    """
    Explicit through model for FirewallRule.source_groups.

    Reproduces the pre-existing auto-generated join table exactly: same table
    (security_groups_firewallrule_source_groups) and columns (firewallrule_id,
    securitygroup_id). Keeps the SecurityGroup -> Tag rename DDL-free by pinning
    ``securitygroup_id`` via db_column instead of the model-derived ``tag_id``.
    """
    firewallrule = models.ForeignKey(
        'security_groups.FirewallRule',
        on_delete=models.CASCADE,
        db_column='firewallrule_id',
    )
    tag = models.ForeignKey(
        'security_groups.Tag',
        on_delete=models.CASCADE,
        db_column='securitygroup_id',
    )

    class Meta:
        db_table = 'security_groups_firewallrule_source_groups'
        unique_together = (('firewallrule', 'tag'),)


# Temporary backward-compatibility alias (Phase 0 rename). Any import that still
# references ``SecurityGroup`` keeps working through this alias. Remove in Phase 4 cleanup.
SecurityGroup = Tag
