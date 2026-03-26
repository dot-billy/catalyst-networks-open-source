from django.contrib import admin
from .models import Organization, Membership, NetworkRange

class MembershipInline(admin.TabularInline):
    model = Membership
    extra = 1
    fields = ['user', 'role', 'created_at']
    readonly_fields = ['created_at']

class NetworkRangeInline(admin.TabularInline):
    model = NetworkRange
    extra = 1
    fields = ['cidr', 'description', 'created_at']
    readonly_fields = ['created_at']

@admin.register(Organization)
class OrganizationAdmin(admin.ModelAdmin):
    list_display = ['name', 'created_by', 'created_at', 'member_count']
    list_filter = ['created_at']
    search_fields = ['name', 'created_by__username']
    readonly_fields = ['created_at']
    inlines = [MembershipInline, NetworkRangeInline]
    
    def member_count(self, obj):
        return obj.members.count()
    member_count.short_description = 'Members'

@admin.register(Membership)
class MembershipAdmin(admin.ModelAdmin):
    list_display = ['user', 'organization', 'role', 'created_at']
    list_filter = ['role', 'created_at']
    search_fields = ['user__username', 'organization__name']
    readonly_fields = ['created_at']

@admin.register(NetworkRange)
class NetworkRangeAdmin(admin.ModelAdmin):
    list_display = ['organization', 'cidr', 'description', 'created_at']
    list_filter = ['created_at']
    search_fields = ['organization__name', 'cidr']
    readonly_fields = ['created_at'] 