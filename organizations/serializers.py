from rest_framework import serializers
from .models import Organization, Membership, Invitation
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model, used in nested serializations."""
    class Meta:
        model = User
        fields = ['id', 'email']
        read_only_fields = ['email']

class OrganizationSerializer(serializers.ModelSerializer):
    """Serializer for Organization model."""
    members_count = serializers.SerializerMethodField()
    user_role = serializers.SerializerMethodField()
    created_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Organization
        fields = [
            'id', 'name', 'slug', 'created_at', 'created_by',
            'members_count', 'user_role', 'config_overrides'
        ]
        read_only_fields = ['slug', 'created_at', 'created_by']
    
    def get_members_count(self, obj):
        """Get the total number of members in the organization."""
        return obj.members.count()
    
    def get_user_role(self, obj):
        """Get the requesting user's role in the organization."""
        request = self.context.get('request')
        if request and request.user.is_authenticated:
            try:
                membership = obj.memberships.get(user=request.user)
                return membership.role
            except Membership.DoesNotExist:
                return None
        return None

class MembershipSerializer(serializers.ModelSerializer):
    """Serializer for Organization Membership model."""
    user = UserSerializer(read_only=True)
    organization = OrganizationSerializer(read_only=True)
    
    class Meta:
        model = Membership
        fields = ['id', 'user', 'organization', 'role', 'created_at']
        read_only_fields = ['created_at']

class InvitationSerializer(serializers.ModelSerializer):
    """Serializer for Organization Invitation model."""
    organization_name = serializers.CharField(source='organization.name', read_only=True)
    inviter_email = serializers.EmailField(source='inviter.email', read_only=True)
    expires_in_days = serializers.IntegerField(write_only=True, required=False, default=7)
    
    class Meta:
        model = Invitation
        fields = [
            'id', 'organization', 'organization_name', 'email',
            'inviter', 'inviter_email', 'role', 'status',
            'created_at', 'accepted_at', 'revoked_at', 'expires_at',
            'expires_in_days', 'is_expired', 'is_valid'
        ]
        read_only_fields = [
            'id', 'organization_name', 'inviter', 'inviter_email',
            'status', 'created_at', 'accepted_at', 'revoked_at',
            'expires_at', 'is_expired', 'is_valid'
        ]

    def validate_email(self, value):
        """
        Validate that the email is not already a member of the organization
        and doesn't have a pending invitation.
        """
        organization = self.context['organization']
        email = value.lower()  # Normalize email to lowercase
        
        # Check if user is already a member
        if User.objects.filter(email=email, organizations=organization).exists():
            raise serializers.ValidationError(
                f"The user with email {email} is already a member of {organization.name}."
            )
        
        # Check for existing invitations
        existing_invitation = Invitation.objects.filter(
            organization=organization,
            email=email
        ).order_by('-created_at').first()
        
        if existing_invitation:
            if existing_invitation.status == 'pending':
                raise serializers.ValidationError(
                    f"An invitation has already been sent to {email} and is waiting for their response. "
                    f"You can wait for them to respond or revoke the existing invitation before sending a new one."
                )
            elif existing_invitation.status == 'expired':
                # Delete expired invitation to allow new one
                existing_invitation.delete()
            elif existing_invitation.status == 'revoked':
                # Delete revoked invitation to allow new one
                existing_invitation.delete()
            elif existing_invitation.status == 'accepted':
                raise serializers.ValidationError(
                    f"The user with email {email} has previously accepted an invitation to {organization.name}. "
                    f"If they are no longer a member, they can request a new invitation."
                )
        
        return email
    
    def create(self, validated_data):
        """Create a new invitation."""
        expires_in_days = validated_data.pop('expires_in_days', 7)
        organization = self.context['organization']
        inviter = self.context['request'].user
        
        try:
            invitation = Invitation.objects.create(
                organization=organization,
                inviter=inviter,
                expires_at=timezone.now() + timezone.timedelta(days=expires_in_days),
                **validated_data
            )
            return invitation
        except Exception as e:
            raise serializers.ValidationError(
                "Could not create invitation. Please try again or contact support if the problem persists."
            )
