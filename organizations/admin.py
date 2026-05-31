from django.contrib import admin, messages
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.translation import ngettext
import secrets
from .emails import resend_invitation_email
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
    actions = ['resend_selected_invitations']

    @admin.action(description="Resend selected pending invitations")
    def resend_selected_invitations(self, request, queryset):
        pending_invitations = queryset.filter(status='pending').select_related('organization', 'inviter')
        sent_count = 0
        for invitation in pending_invitations:
            try:
                resend_invitation_email(invitation)
                sent_count += 1
            except Exception as exc:
                self.message_user(
                    request,
                    f"Could not resend invitation to {invitation.email}: {exc}",
                    level=messages.ERROR,
                )

        skipped_count = queryset.exclude(status='pending').count()
        if sent_count:
            self.message_user(
                request,
                ngettext(
                    "Resent %(count)d invitation email.",
                    "Resent %(count)d invitation emails.",
                    sent_count,
                ) % {'count': sent_count},
                level=messages.SUCCESS,
            )
        if skipped_count:
            self.message_user(
                request,
                ngettext(
                    "Skipped %(count)d non-pending invitation.",
                    "Skipped %(count)d non-pending invitations.",
                    skipped_count,
                ) % {'count': skipped_count},
                level=messages.WARNING,
            )

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
