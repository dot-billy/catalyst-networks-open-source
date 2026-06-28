"""
Backfill helper for FirewallRule legacy fields.

This module is model-agnostic: it only touches instance attributes and the
M2M managers exposed by both real Django model instances and historical model
instances produced by apps.get_model() inside data migrations.
"""


def backfill_rule(rule):
    """Set target_groups, match_type, and direction from legacy fields. Idempotent."""
    if rule.security_group_id:
        rule.target_groups.add(rule.security_group_id)

    if rule.source_groups.exists():
        rule.match_type = 'groups'
    elif rule.source_nodes.exists():
        rule.match_type = 'host'
    elif rule.source_cidr:
        rule.match_type = 'cidr'
    else:
        rule.match_type = 'any'

    rule.direction = 'in'  # every existing rule is inbound
    rule.save(update_fields=['match_type', 'direction'])
