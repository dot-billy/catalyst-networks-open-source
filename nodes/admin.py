from django.contrib import admin, messages
from .models import Node, NodeRegistrationToken, NodeQRCode
from .views import regenerate_certificate

@admin.register(Node)
class NodeAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization', 'assigned_user', 'nebula_ip', 'is_lighthouse', 'public_ip', 'cert_expiration', 'api_token_short', 'last_checkin')
    list_filter = ('organization', 'is_lighthouse', 'cert_expiration')
    search_fields = ('name', 'nebula_ip', 'organization__name', 'public_ip', 'fqdn')
    readonly_fields = ('cert_path', 'key_path', 'created_at', 'api_token', 'last_checkin')
    
    def api_token_short(self, obj):
        if obj.api_token:
            return obj.api_token[:6] + '...' + obj.api_token[-4:]
        return ''
    api_token_short.short_description = 'API Token'
    
    def get_fieldsets(self, request, obj=None):
        fieldsets = [
            (None, {
                'fields': ('name', 'organization', 'assigned_user', 'certificate_authority', 'nebula_ip', 'is_lighthouse', 'api_token', 'last_checkin')
            }),
            ('Certificate Files', {
                'fields': ('cert_path', 'key_path', 'cert_expiration'),
                'classes': ('collapse',)
            }),
        ]
        
        # Always include lighthouse fieldset, but we'll show/hide it with JavaScript
        fieldsets.insert(1, ('Lighthouse Configuration', {
            'fields': ('public_ip', 'fqdn', 'external_port'),
            'description': 'Configuration for lighthouse nodes',
            'classes': ('lighthouse-config',)
        }))
            
        return fieldsets
    
    class Media:
        js = ('js/admin/node_admin.js',)

    def save_model(self, request, obj, form, change):
        """Override save_model to regenerate certificates when necessary."""
        # Save the object first
        super().save_model(request, obj, form, change)
        # Determine if we need to regenerate the certificate
        if not change:
            # New object creation: always generate certificate
            success = regenerate_certificate(obj)
            if success:
                self.message_user(request, f"Certificate generated for new node {obj.name}.", messages.SUCCESS)
            else:
                self.message_user(request, f"Failed to generate certificate for new node {obj.name}.", messages.ERROR)
        else:
            # On update: regenerate only if certificate-impacting fields changed
            old = self.model.objects.get(pk=obj.pk)
            regenerate = False
            if old.certificate_authority_id != obj.certificate_authority_id:
                regenerate = True
            if old.fqdn != obj.fqdn:
                regenerate = True
            if old.is_lighthouse != obj.is_lighthouse:
                regenerate = True
            if obj.is_lighthouse and old.public_ip != obj.public_ip:
                regenerate = True
            if obj.is_lighthouse and old.external_port != obj.external_port:
                regenerate = True
            if regenerate:
                success = regenerate_certificate(obj)
                if success:
                    self.message_user(request, f"Certificate regenerated for node {obj.name}.", messages.SUCCESS)
                else:
                    self.message_user(request, f"Failed to regenerate certificate for node {obj.name}.", messages.ERROR)

@admin.register(NodeRegistrationToken)
class NodeRegistrationTokenAdmin(admin.ModelAdmin):
    list_display = ('description', 'organization', 'token', 'created_by', 'expires_at', 'is_active', 'uses_count', 'uses_allowed')
    list_filter = ('organization', 'is_active', 'created_at', 'expires_at')
    search_fields = ('description', 'token', 'organization__name')
    readonly_fields = ('token', 'created_at', 'uses_count')
    fieldsets = (
        (None, {
            'fields': ('organization', 'description', 'token', 'created_by')
        }),
        ('Validity Settings', {
            'fields': ('is_active', 'expires_at', 'uses_allowed', 'uses_count')
        }),
    )
    
    def save_model(self, request, obj, form, change):
        if not change:  # Only for new objects
            obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(NodeQRCode)
class NodeQRCodeAdmin(admin.ModelAdmin):
    list_display = ('node', 'enrollment_token_short', 'created_at', 'expires_at', 'is_active', 'is_expired')
    list_filter = ('is_active', 'created_at', 'expires_at')
    search_fields = ('node__name', 'enrollment_token', 'node__organization__name')
    readonly_fields = ('qr_image', 'enrollment_token', 'enrollment_url', 'created_at', 'expires_at')

    fieldsets = (
        (None, {
            'fields': ('node', 'qr_image', 'enrollment_url')
        }),
        ('Security', {
            'fields': ('enrollment_token', 'is_active', 'created_at', 'expires_at'),
            'classes': ('collapse',)
        }),
    )

    def enrollment_token_short(self, obj):
        if obj.enrollment_token:
            return obj.enrollment_token[:8] + '...' + obj.enrollment_token[-4:]
        return ''
    enrollment_token_short.short_description = 'Token'

    def get_queryset(self, request):
        return super().get_queryset(request).select_related('node', 'node__organization')
