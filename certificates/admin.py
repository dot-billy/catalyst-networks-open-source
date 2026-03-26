from django.contrib import admin
from .models import CertificateAuthority, CertificateAuthorityQRCode
from django.utils.html import format_html
import os
from django.conf import settings


class CertificateAuthorityQRCodeInline(admin.StackedInline):
    model = CertificateAuthorityQRCode
    extra = 0
    fields = ('qr_image', 'source', 'created_at', 'updated_at')
    readonly_fields = ('source', 'created_at', 'updated_at')


@admin.register(CertificateAuthority)
class CertificateAuthorityAdmin(admin.ModelAdmin):
    list_display = ('name', 'organization_link', 'created_by', 'created_at', 'is_active', 'certificate_info')
    list_filter = ('organization', 'created_at', 'created_by')
    search_fields = ('name', 'organization__name', 'created_by__email')
    readonly_fields = ('ca_cert', 'ca_key', 'created_by', 'created_at', 'certificate_info')
    inlines = (CertificateAuthorityQRCodeInline,)
    fieldsets = (
        (None, {
            'fields': ('name', 'organization', 'created_by')
        }),
        ('Certificate Files', {
            'fields': ('ca_cert', 'ca_key'),
            'classes': ('collapse',)
        }),
        ('Certificate Information', {
            'fields': ('certificate_info',),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )

    def organization_link(self, obj):
        return format_html(
            '<a href="/admin/organizations/organization/{}/change/">{}</a>',
            obj.organization.id,
            obj.organization.name
        )
    organization_link.short_description = 'Organization'
    organization_link.admin_order_field = 'organization__name'

    def is_active(self, obj):
        cert_path = obj.ca_cert.path if obj.ca_cert else None
        key_path = obj.ca_key.path if obj.ca_key else None
        cert_exists = os.path.exists(cert_path) if cert_path else False
        key_exists = os.path.exists(key_path) if key_path else False
        
        if cert_exists and key_exists:
            return format_html(
                '<span style="color: green;">✓ Active</span>'
            )
        else:
            return format_html(
                '<span style="color: red;">✗ Inactive</span>'
            )
    is_active.short_description = 'Status'

    def certificate_info(self, obj):
        cert_path = obj.ca_cert.path if obj.ca_cert else None
        key_path = obj.ca_key.path if obj.ca_key else None
        
        info = []
        if cert_path and os.path.exists(cert_path):
            cert_size = os.path.getsize(cert_path)
            info.append(f"Certificate: {cert_size} bytes")
        else:
            info.append("Certificate: Missing")
            
        if key_path and os.path.exists(key_path):
            key_size = os.path.getsize(key_path)
            info.append(f"Private Key: {key_size} bytes")
        else:
            info.append("Private Key: Missing")
            
        return format_html('<br>'.join(info))
    certificate_info.short_description = 'Certificate Details'


@admin.register(CertificateAuthorityQRCode)
class CertificateAuthorityQRCodeAdmin(admin.ModelAdmin):
    list_display = ('certificate_authority', 'source', 'updated_at')
    list_filter = ('source', 'updated_at')
    search_fields = ('certificate_authority__name', 'certificate_authority__organization__name')
    readonly_fields = ('created_at', 'updated_at')
