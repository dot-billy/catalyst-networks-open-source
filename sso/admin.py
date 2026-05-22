from django.contrib import admin
from .models import SSOConfiguration


@admin.register(SSOConfiguration)
class SSOConfigurationAdmin(admin.ModelAdmin):
    list_display = ('organization', 'is_enabled', 'enforce_sso', 'idp_entity_id', 'updated_at')
    list_filter = ('is_enabled', 'enforce_sso')
    search_fields = ('organization__name', 'idp_entity_id')
