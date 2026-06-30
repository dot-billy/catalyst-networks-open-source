from django.contrib import admin
from .models import Tag, FirewallRule

class FirewallRuleInline(admin.TabularInline):
    model = FirewallRule
    extra = 1
    fields = ['protocol', 'port_min', 'port_max', 'source_cidr', 'description']
    fk_name = 'security_group'
    verbose_name = "Firewall Rule"
    verbose_name_plural = "Firewall Rules"

@admin.register(Tag)
class SecurityGroupAdmin(admin.ModelAdmin):
    list_display = ['name', 'organization', 'node_count', 'rule_count', 'created_at']
    list_filter = ['created_at', 'organization']
    search_fields = ['name', 'organization__name']
    readonly_fields = ['created_at']
    inlines = [FirewallRuleInline]
    
    def node_count(self, obj):
        return obj.nodes.count()
    node_count.short_description = 'Nodes'
    
    def rule_count(self, obj):
        return obj.firewall_rules.count()
    rule_count.short_description = 'Rules'

@admin.register(FirewallRule)
class FirewallRuleAdmin(admin.ModelAdmin):
    list_display = ['target_display', 'protocol', 'port_range', 'source_cidr', 'created_at']
    list_filter = ['protocol', 'created_at']
    search_fields = ['description', 'source_cidr']
    readonly_fields = ['created_at']
    
    def target_display(self, obj):
        """Display either the node or the security group this rule is attached to"""
        if obj.node:
            return f"Node: {obj.node.name}"
        elif obj.security_group:
            return f"Group: {obj.security_group.name}"
        return "Unattached"
    target_display.short_description = 'Target'
    
    def port_range(self, obj):
        """Format the port range for display"""
        if obj.protocol in ['tcp', 'udp']:
            if obj.port_min is not None and obj.port_max is not None:
                if obj.port_min == obj.port_max:
                    return str(obj.port_min)
                else:
                    return f"{obj.port_min}-{obj.port_max}"
        return "N/A"
    port_range.short_description = 'Ports'
