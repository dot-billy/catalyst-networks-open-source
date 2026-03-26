from django.contrib import admin
from .models import Webhook

@admin.register(Webhook)
class WebhookAdmin(admin.ModelAdmin):
    list_display = ['url', 'organization', 'get_events', 'active', 'created_at']
    list_filter = ['created_at', 'organization', 'active']
    search_fields = ['url', 'organization__name']
    readonly_fields = ['created_at']
    fieldsets = (
        (None, {
            'fields': ('url', 'organization', 'events', 'active')
        }),
        ('Timestamps', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        })
    )

    def get_events(self, obj):
        return ", ".join(obj.events)
    get_events.short_description = 'Events'
