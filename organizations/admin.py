from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.utils import timezone
import secrets
from .models import Organization, Membership, Invitation

class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 1
    fields = ['user', 'role', 'created_at']
    readonly_fields = ['created_at']


class InvitationInline(admin.TabularInline):
    model = Invitation
    extra = 0
    fields = ['email', 'role', 'status', 'inviter', 'created_at', 'expires_at']
    readonly_fields = ['created_at']

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_by', 'created_at', 'member_count']
    list_filter = ['created_at']
    search_fields = ['name', 'created_by__username']
    readonly_fields = ['created_at']
    inlines = [MembershipInline, InvitationInline]
    
    def member_count(self, obj):
        return obj.members.count()
    member_count.short_description = 'Members'


@admin.register(Invitation)
class InvitationAdmin(admin.ModelAdmin):
    list_display = ['email', 'organization', 'status', 'role', 'inviter', 'created_at', 'expires_at']
    list_filter = ['status', 'role', 'organization', 'created_at', 'expires_at']
    search_fields = ['email', 'organization__name', 'inviter__email', 'token']
    readonly_fields = ['token', 'created_at', 'accepted_at', 'revoked_at']

    def save_model(self, request, obj, form, change):
        User = get_user_model()
        previous_status = None
        if change:
            previous_status = Invitation.objects.get(pk=obj.pk).status

        if obj.status == 'accepted' and previous_status != 'accepted':
            user = User.objects.filter(email__iexact=obj.email).first()
            if not user:
                # Admin override path: create a local user account so acceptance can proceed.
                user = User.objects.create_user(
                    email=obj.email,
                    password=secrets.token_urlsafe(24),
                    is_active=True,
                )
                self.message_user(
                    request,
                    (
                        f"Created user account for {obj.email} automatically. "
                        "Set a password in Users admin if this person needs to log in."
                    ),
                    level=messages.WARNING,
                )

            Membership.objects.get_or_create(
                organization=obj.organization,
                user=user,
                defaults={'role': obj.role},
            )
            if not obj.accepted_at:
                obj.accepted_at = timezone.now()

        super().save_model(request, obj, form, change)
