from rest_framework import serializers
from .models import Node
from organizations.models import Organization
from certificates.models import CertificateAuthority
from security_groups.models import Tag, SecurityGroup
import ipaddress
import subprocess
import os
from django.conf import settings
from django.core.files import File
from django.utils import timezone
from .models import NodeRegistrationToken

class NodeSerializer(serializers.ModelSerializer):
    """
    Serializer for Node model.
    
    Handles creation, retrieval, update, and deletion of Nebula network nodes.
    Each node represents a device or service in the Nebula VPN network.
    """
    # Make nebula_ip optional
    nebula_ip = serializers.IPAddressField(
        required=False, 
        allow_null=True,
        help_text="IP address assigned to this node in the Nebula network"
    )
    
    organization = serializers.SerializerMethodField(
        help_text="Organization this node belongs to"
    )
    
    certificate_authority = serializers.SerializerMethodField(
        help_text="Certificate authority used to sign this node's certificate"
    )
    
    is_lighthouse = serializers.BooleanField(
        default=False,
        help_text="Whether this node is a lighthouse (coordination server) in the Nebula network"
    )
    
    security_groups = serializers.SerializerMethodField(
        help_text="Security groups assigned to this node"
    )
    
    class Meta:
        model = Node
        fields = [
            'id', 'name', 'organization', 'certificate_authority',
            'nebula_ip', 'is_lighthouse', 'security_groups', 'public_ip',
            'fqdn', 'external_port', 'cert_expiration', 'created_at'
        ]
        read_only_fields = ['cert_expiration', 'created_at']
        
    def get_organization(self, obj):
        return obj.organization.name
        
    def get_certificate_authority(self, obj):
        return obj.certificate_authority.name
        
    def get_security_groups(self, obj):
        return [sg.name for sg in obj.tags.all()]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Set the queryset for security_groups based on the organization
        if 'context' in kwargs and 'request' in kwargs['context']:
            user = kwargs['context']['request'].user
            if self.fields.get('security_groups'):
                self.fields['security_groups'].queryset = Tag.objects.filter(
                    organization__memberships__user=user
                )

    def validate_nebula_ip(self, value):
        """
        Validate that the IP address is valid and not already in use.
        Only validate if a value is provided.
        """
        if not value:
            return value
            
        try:
            ipaddress.ip_address(value)
        except ValueError:
            raise serializers.ValidationError("Invalid IP address format")

        if Node.objects.filter(nebula_ip=value).exists():
            raise serializers.ValidationError("IP address is already in use")

        return value

    def validate(self, data):
        """
        Validate that the organization has a network range and the IP is within it.
        Only validate IP if it's provided.
        """
        organization = data['organization']
        nebula_ip = data.get('nebula_ip')
        
        # If no IP is provided, skip IP validation
        if not nebula_ip:
            return data
            
        # Check if organization has network ranges
        if not organization.network_ranges.exists():
            raise serializers.ValidationError("Organization has no network ranges defined")

        # Check if IP is in any of the ranges
        node_ip = ipaddress.ip_address(nebula_ip)
        in_range = False
        for network_range in organization.network_ranges.all():
            network = ipaddress.ip_network(network_range.cidr)
            if node_ip in network:
                in_range = True
                break

        if not in_range:
            raise serializers.ValidationError(
                f"IP address {nebula_ip} is not in any of the organization's network ranges"
            )

        return data

    def create(self, validated_data):
        """
        Create a new node and generate its certificate.
        """
        # Extract security groups before creating the node
        security_groups = validated_data.pop('security_groups', [])

        # Create the node
        node = Node.objects.create(**validated_data)

        # Add security groups
        node.tags.set(security_groups)

        # Generate certificate
        ca = validated_data['certificate_authority']
        name = validated_data['name']
        ip = validated_data['nebula_ip']
        
        # Create cert directory if it doesn't exist (dedicated cert storage)
        cert_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'certs', f'org-{node.organization.id}')
        os.makedirs(cert_dir, exist_ok=True)

        # Generate certificate using nebula-cert (filename with UTC datetime suffix)
        timestamp_str = timezone.now().strftime("%Y%m%dT%H%M%SZ")
        cert_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.crt')
        key_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.key')
        
        try:
            subprocess.run([
                'nebula-cert', 'sign',
                '-name', name,
                '-ip', f'{ip}/24',
                '-ca-crt', ca.ca_cert.path,
                '-ca-key', ca.ca_key.path,
                '-out-crt', cert_path,
                '-out-key', key_path
            ], check=True)

            # Save the files to the node
            with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
                node.cert_path.save(f'{name}-{timestamp_str}.crt', File(cert_file))
                node.key_path.save(f'{name}-{timestamp_str}.key', File(key_file))

            # Get certificate expiration
            result = subprocess.run([
                'nebula-cert', 'print',
                '-path', cert_path
            ], capture_output=True, text=True, check=True)
            
            # Parse expiration from output
            for line in result.stdout.split('\n'):
                if 'Not After' in line:
                    expiration_str = line.split(': ')[1].strip()
                    # Format: "2025-05-03 12:56:48 +0000 UTC"
                    # Convert to Django-compatible format: "2025-05-03T12:56:48Z"
                    try:
                        parts = expiration_str.split()
                        if len(parts) >= 2:
                            date_part = parts[0]
                            time_part = parts[1]
                            # Create ISO format date
                            node.cert_expiration = f"{date_part}T{time_part}Z"
                        else:
                            # If parsing fails, use a default expiration
                            from django.utils import timezone
                            node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                    except Exception as e:
                        print(f"Error parsing certificate expiration: {e}")
                        # If parsing fails, use a default expiration
                        from django.utils import timezone
                        node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                    break

            node.save()
            return node

        except subprocess.CalledProcessError as e:
            # Clean up if certificate generation fails
            node.delete()
            raise serializers.ValidationError(f"Failed to generate certificate: {str(e)}")

class NodeRegistrationTokenSerializer(serializers.ModelSerializer):
    """
    Serializer for NodeRegistrationToken model.
    
    Node registration tokens are used for securely registering new nodes without requiring user authentication.
    Each token can be configured with usage limits and expiration dates.
    """
    created_by_username = serializers.SerializerMethodField(
        help_text="Username of the user who created this token"
    )
    organization_name = serializers.SerializerMethodField(
        help_text="Name of the organization this token belongs to"
    )
    is_valid = serializers.SerializerMethodField(
        help_text="Whether this token is currently valid for use"
    )
    
    organization = serializers.PrimaryKeyRelatedField(
        queryset=Organization.objects.all(),
        help_text="Organization this token belongs to"
    )
    
    description = serializers.CharField(
        help_text="Description of the token's purpose"
    )
    
    expires_at = serializers.DateTimeField(
        required=False,
        help_text="Date and time when this token expires"
    )
    
    uses_allowed = serializers.IntegerField(
        default=-1,
        help_text="Number of times this token can be used, -1 for unlimited"
    )
    
    class Meta:
        model = NodeRegistrationToken
        fields = [
            'id', 'organization', 'organization_name', 'token', 'description',
            'created_by', 'created_by_username', 'created_at', 'expires_at',
            'is_active', 'uses_allowed', 'uses_count', 'is_valid'
        ]
        read_only_fields = ['token', 'created_by', 'created_at', 'uses_count', 'is_valid']
    
    def get_created_by_username(self, obj):
        if obj.created_by:
            return obj.created_by.username
        return None
    
    def get_organization_name(self, obj):
        return obj.organization.name
    
    def get_is_valid(self, obj):
        return obj.is_valid()
    
    def create(self, validated_data):
        """
        Create a new token with the user from the context.
        """
        user = self.context['request'].user
        
        # Use the class method to create the token
        days_valid = 30  # Default expiration
        if 'expires_at' in validated_data:
            # Keep the provided expiration
            days_valid = None
            
        uses_allowed = validated_data.get('uses_allowed', -1)
        
        if days_valid is not None:
            # Create with default expiration
            token = NodeRegistrationToken.create_for_organization(
                organization=validated_data['organization'],
                description=validated_data['description'],
                created_by=user,
                days_valid=days_valid,
                uses_allowed=uses_allowed
            )
        else:
            # Create with provided expiration
            token = NodeRegistrationToken.objects.create(
                organization=validated_data['organization'],
                description=validated_data['description'],
                created_by=user,
                expires_at=validated_data['expires_at'],
                uses_allowed=uses_allowed,
                is_active=validated_data.get('is_active', True)
            )
            
        return token 

class NodeRegistrationSerializer(serializers.Serializer):
    organization_slug = serializers.CharField(
        max_length=255,
        min_length=1,
        help_text="Slug of the organization to register the node with"
    )
    node_name = serializers.CharField(
        max_length=255,
        min_length=1,
        help_text="Name or hostname for the node"
    )
    registration_token = serializers.CharField(
        max_length=255,
        min_length=1,
        help_text="Registration token for the organization"
    )
    is_lighthouse = serializers.BooleanField(
        default=False,
        help_text="Whether this node should be a lighthouse (coordination server)"
    )
    public_ip = serializers.IPAddressField(
        required=False, 
        allow_null=True,
        help_text="Public IP address for lighthouse nodes (required for lighthouse nodes)"
    )
    fqdn = serializers.CharField(
        max_length=255, 
        required=False, 
        allow_blank=True,
        help_text="Fully Qualified Domain Name for lighthouse nodes"
    )
    external_port = serializers.IntegerField(
        required=False, 
        allow_null=True,
        min_value=1,
        max_value=65535,
        help_text="External port for lighthouse nodes (1-65535)"
    )
    
    def validate_node_name(self, value):
        """Validate node name format and content."""
        if not value or not value.strip():
            raise serializers.ValidationError("Node name cannot be empty or whitespace only.")
        
        # Check for valid characters (alphanumeric, hyphens, underscores, dots)
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', value):
            raise serializers.ValidationError(
                "Node name can only contain letters, numbers, dots, hyphens, and underscores."
            )
        
        # Check length after stripping
        if len(value.strip()) < 1:
            raise serializers.ValidationError("Node name must be at least 1 character long.")
        
        if len(value.strip()) > 255:
            raise serializers.ValidationError("Node name cannot exceed 255 characters.")
        
        return value.strip()
    
    def validate_organization_slug(self, value):
        """Validate organization slug format."""
        if not value or not value.strip():
            raise serializers.ValidationError("Organization slug cannot be empty.")
        
        # Check for valid slug format
        import re
        if not re.match(r'^[a-z0-9-]+$', value):
            raise serializers.ValidationError(
                "Organization slug can only contain lowercase letters, numbers, and hyphens."
            )
        
        return value.strip()
    
    def validate_registration_token(self, value):
        """Validate registration token format."""
        if not value or not value.strip():
            raise serializers.ValidationError("Registration token cannot be empty.")
        
        # Check for reasonable token format (UUID-like or custom format)
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', value):
            raise serializers.ValidationError(
                "Registration token contains invalid characters."
            )
        
        return value.strip()
    
    def validate_fqdn(self, value):
        """Validate FQDN format if provided."""
        if not value or not value.strip():
            return value
        
        import re
        # Basic FQDN validation
        fqdn_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(fqdn_pattern, value.strip()):
            raise serializers.ValidationError(
                "Invalid FQDN format. Please provide a valid domain name."
            )
        
        return value.strip()
    
    def validate(self, data):
        """Cross-field validation."""
        is_lighthouse = data.get('is_lighthouse', False)
        public_ip = data.get('public_ip')
        fqdn = data.get('fqdn')
        external_port = data.get('external_port')
        
        # Lighthouse-specific validations
        if is_lighthouse:
            if not public_ip and not fqdn:
                raise serializers.ValidationError({
                    'public_ip': 'Lighthouse nodes must have either a public IP or FQDN configured.',
                    'fqdn': 'Lighthouse nodes must have either a public IP or FQDN configured.'
                })
            
            if external_port is not None and (external_port < 1 or external_port > 65535):
                raise serializers.ValidationError({
                    'external_port': 'External port must be between 1 and 65535.'
                })
        
        # Regular node validations
        else:
            if public_ip:
                raise serializers.ValidationError({
                    'public_ip': 'Public IP is only allowed for lighthouse nodes.'
                })
            
            if fqdn:
                raise serializers.ValidationError({
                    'fqdn': 'FQDN is only allowed for lighthouse nodes.'
                })
            
            if external_port is not None:
                raise serializers.ValidationError({
                    'external_port': 'External port is only allowed for lighthouse nodes.'
                })
        
        return data

class AuthenticatedNodeRegistrationSerializer(serializers.Serializer):
    """
    Serializer for authenticated node registration (desktop app flow).
    
    This serializer is used when a user is already authenticated and wants to
    register their device without needing a registration token.
    """
    node_name = serializers.CharField(
        max_length=255,
        min_length=1,
        help_text="Name or hostname for the node"
    )
    is_lighthouse = serializers.BooleanField(
        default=False,
        help_text="Whether this node should be a lighthouse (coordination server)"
    )
    public_ip = serializers.IPAddressField(
        required=False, 
        allow_null=True,
        help_text="Public IP address for lighthouse nodes (required for lighthouse nodes)"
    )
    fqdn = serializers.CharField(
        max_length=255, 
        required=False, 
        allow_blank=True,
        help_text="Fully Qualified Domain Name for lighthouse nodes"
    )
    external_port = serializers.IntegerField(
        required=False, 
        allow_null=True,
        min_value=1,
        max_value=65535,
        help_text="External port for lighthouse nodes (1-65535)"
    )
    
    def validate_node_name(self, value):
        """Validate node name format and content."""
        if not value or not value.strip():
            raise serializers.ValidationError("Node name cannot be empty or whitespace only.")
        
        # Check for valid characters (alphanumeric, hyphens, underscores, dots)
        import re
        if not re.match(r'^[a-zA-Z0-9._-]+$', value):
            raise serializers.ValidationError(
                "Node name can only contain letters, numbers, dots, hyphens, and underscores."
            )
        
        # Check length after stripping
        if len(value.strip()) < 1:
            raise serializers.ValidationError("Node name must be at least 1 character long.")
        
        if len(value.strip()) > 255:
            raise serializers.ValidationError("Node name cannot exceed 255 characters.")
        
        return value.strip()
    
    def validate_fqdn(self, value):
        """Validate FQDN format if provided."""
        if not value or not value.strip():
            return value
        
        import re
        # Basic FQDN validation
        fqdn_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        if not re.match(fqdn_pattern, value.strip()):
            raise serializers.ValidationError(
                "Invalid FQDN format. Please provide a valid domain name."
            )
        
        return value.strip()
    
    def validate(self, data):
        """Cross-field validation."""
        is_lighthouse = data.get('is_lighthouse', False)
        public_ip = data.get('public_ip')
        fqdn = data.get('fqdn')
        external_port = data.get('external_port')
        
        # Lighthouse-specific validations
        if is_lighthouse:
            if not public_ip and not fqdn:
                raise serializers.ValidationError({
                    'public_ip': 'Lighthouse nodes must have either a public IP or FQDN configured.',
                    'fqdn': 'Lighthouse nodes must have either a public IP or FQDN configured.'
                })
            
            if external_port is not None and (external_port < 1 or external_port > 65535):
                raise serializers.ValidationError({
                    'external_port': 'External port must be between 1 and 65535.'
                })
        
        # Regular node validations
        else:
            if public_ip:
                raise serializers.ValidationError({
                    'public_ip': 'Public IP is only allowed for lighthouse nodes.'
                })
            
            if fqdn:
                raise serializers.ValidationError({
                    'fqdn': 'FQDN is only allowed for lighthouse nodes.'
                })
            
            if external_port is not None:
                raise serializers.ValidationError({
                    'external_port': 'External port is only allowed for lighthouse nodes.'
                })
        
        return data
