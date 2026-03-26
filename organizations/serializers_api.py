from rest_framework import serializers
from .models import Organization, Membership, NetworkRange
import ipaddress

class MembershipSerializer(serializers.ModelSerializer):
    user = serializers.SlugRelatedField(
        slug_field='email',
        read_only=True
    )

    class Meta:
        model = Membership
        fields = ['id', 'user', 'role', 'created_at']
        read_only_fields = ['id', 'user', 'created_at']

class OrganizationSerializer(serializers.ModelSerializer):
    memberships = MembershipSerializer(many=True, read_only=True)
    created_by = serializers.SlugRelatedField(
        slug_field='email',
        read_only=True
    )

    class Meta:
        model = Organization
        fields = ['id', 'name', 'slug', 'created_by', 'created_at', 'memberships']
        read_only_fields = ['id', 'slug', 'created_by', 'created_at']

class OrganizationCreateSerializer(OrganizationSerializer):
    cidr = serializers.CharField(
        write_only=True,
        help_text='CIDR notation for the organization\'s network (e.g., 192.168.100.0/24)'
    )

    class Meta:
        model = Organization
        fields = ['id', 'name', 'created_by', 'created_at', 'memberships', 'cidr']
        read_only_fields = ['id', 'created_at']

    def validate_cidr(self, value):
        """
        Validate the CIDR notation.
        """
        try:
            network = ipaddress.ip_network(value)
            # Allow private IP ranges and CGNAT (100.64.0.0/10) range
            cgnat_network = ipaddress.ip_network('100.64.0.0/10')
            
            if not network.is_private and not network.overlaps(cgnat_network):
                raise serializers.ValidationError("Only private IP ranges and CGNAT (100.64.0.0/10) ranges are allowed")
            return value
        except ValueError:
            raise serializers.ValidationError("Invalid CIDR notation")

    def create(self, validated_data):
        """
        Create organization, set created_by to the authenticated user,
        and create the network range.
        """
        cidr = validated_data.pop('cidr')
        validated_data['created_by'] = self.context['request'].user
        organization = super().create(validated_data)
        
        # Create the network range
        NetworkRange.objects.create(
            organization=organization,
            cidr=cidr,
            description=f"Default network range for {organization.name}"
        )
        
        return organization

class MembershipCreateSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(write_only=True)

    class Meta:
        model = Membership
        fields = ['email', 'role']

    def create(self, validated_data):
        email = validated_data.pop('email')
        organization = validated_data.pop('organization')
        user = self.context['request'].user

        # Check if user has permission to add members
        if not organization.memberships.filter(user=user, role__in=['owner', 'admin']).exists():
            raise serializers.ValidationError("You don't have permission to add members to this organization.")

        # Get or create the target user
        from django.contrib.auth import get_user_model
        User = get_user_model()
        try:
            target_user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError("User not found.")

        # Create the membership
        return Membership.objects.create(
            user=target_user,
            organization=organization,
            **validated_data
        ) 