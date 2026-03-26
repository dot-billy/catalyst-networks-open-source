from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import User
from organizations.models import Membership

class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 0
    fields = ['organization', 'role', 'created_at']
    readonly_fields = ['created_at']
    can_delete = False

@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('email', 'first_name', 'last_name', 'is_active', 'is_staff', 'is_superuser', 'date_joined', 'organization_count')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'date_joined')
    search_fields = ('email', 'first_name', 'last_name')
    ordering = ('email',)
    readonly_fields = ('date_joined', 'last_login')
    
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('first_name', 'last_name')}),
        ('Permissions', {
            'fields': ('is_active', 'is_staff', 'is_superuser', 'groups', 'user_permissions'),
        }),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )
    
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'first_name', 'last_name', 'is_staff', 'is_superuser'),
        }),
    )
    
    inlines = [MembershipInline]
    
    def organization_count(self, obj):
        count = obj.organizations.count()
        return format_html(
            '<a href="/admin/organizations/organization/?members={}">{}</a>',
            obj.id,
            count
        )
    organization_count.short_description = 'Organizations'
