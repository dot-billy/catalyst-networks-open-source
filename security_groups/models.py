from django.db import models
from simple_history.models import HistoricalRecords

class SecurityGroup(models.Model):
    """
    SecurityGroup model - simple collections of nodes for easier management.
    """
    name = models.CharField(max_length=255)
    organization = models.ForeignKey(
        'organizations.Organization',
        on_delete=models.CASCADE,
        related_name='security_groups'
    )
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    history = HistoricalRecords()

    class Meta:
        verbose_name = 'Security Group'
        verbose_name_plural = 'Security Groups'
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
        SecurityGroup,
        on_delete=models.CASCADE,
        related_name='firewall_rules',
        null=True,
        blank=True,
        help_text='Security group this rule applies to (if not attached to a specific node)'
    )
    protocol = models.CharField(
        max_length=10,
        choices=PROTOCOL_CHOICES,
        default='tcp',
        help_text='Network protocol this rule applies to'
    )
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
        'security_groups.SecurityGroup',
        blank=True,
        related_name='rules_as_source',
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
        
        # Rule must be attached to either a node or a security group (but not both)
        if not self.node and not self.security_group:
            raise ValidationError("Rule must be attached to either a node or a security group")
        
        if self.node and self.security_group:
            raise ValidationError("Rule cannot be attached to both a node and a security group")
        
        # Validate target belongs to same organization for consistency
        if self.node and self.security_group and self.node.organization != self.security_group.organization:
            raise ValidationError("Node and security group must belong to the same organization")
        
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
