"""Plain-English summaries of what a Tag's firewall rules allow."""

from django.db.models import Prefetch, Q

from .models import FirewallRule, Tag

WELL_KNOWN_PORTS = {
    22: 'SSH', 53: 'DNS', 80: 'HTTP', 443: 'HTTPS', 3306: 'MySQL',
    5432: 'PostgreSQL', 6379: 'Redis', 8080: 'HTTP-alt', 4242: 'Nebula',
}


def _service_label(rule):
    """Short label for a rule's protocol+port: 'SSH', 'TCP/8000-8100', 'ICMP', 'all traffic'."""
    if rule.protocol == 'any':
        return 'all traffic'
    if rule.protocol == 'icmp':
        return 'ICMP'
    if rule.port_min == rule.port_max:
        return WELL_KNOWN_PORTS.get(rule.port_min) or f'{rule.protocol.upper()}/{rule.port_min}'
    return f'{rule.protocol.upper()}/{rule.port_min}-{rule.port_max}'


def target_rules_queryset(organization):
    """Rules that can target tags in an organization, with org-scoped sources."""
    from nodes.models import Node

    return (
        FirewallRule.objects
        .filter(Q(security_group__organization=organization) | Q(target_groups__organization=organization))
        .select_related('security_group', 'security_group__organization', 'node', 'node__organization')
        .prefetch_related(
            Prefetch(
                'source_groups',
                queryset=Tag.objects.filter(organization=organization).order_by('name'),
                to_attr='org_source_groups',
            ),
            Prefetch(
                'source_nodes',
                queryset=Node.objects.filter(organization=organization).order_by('name'),
                to_attr='org_source_nodes',
            ),
        )
        .distinct()
    )


def target_rules_for_tag(tag):
    """Return legacy-FK and target_groups rules for a tag exactly once."""
    legacy_rules = getattr(tag, 'legacy_target_rules', None)
    m2m_rules = getattr(tag, 'm2m_target_rules', None)
    if legacy_rules is not None and m2m_rules is not None:
        return _dedupe_rules((legacy_rules, m2m_rules))

    return list(
        target_rules_queryset(tag.organization)
        .filter(Q(security_group=tag) | Q(target_groups=tag))
        .distinct()
    )


def _dedupe_rules(rule_sets):
    rule_map = {}
    for rules in rule_sets:
        for rule in rules:
            rule_map[rule.pk] = rule
    return list(rule_map.values())


def _scoped_names(rule, relation_name, prefetched_attr, organization):
    items = getattr(rule, prefetched_attr, None)
    if items is None:
        items = getattr(rule, relation_name).filter(organization=organization)
    return sorted(item.name for item in items)


def _peer_label(rule, organization):
    """Who the rule's source is: 'tag web', 'anywhere', '10.0.0.0/8', 'node db1'."""
    if rule.match_type == 'groups':
        names = _scoped_names(rule, 'source_groups', 'org_source_groups', organization)
        return 'tag ' + ', '.join(names) if names else 'a tag'
    if rule.match_type == 'cidr':
        return rule.source_cidr or 'a network'
    if rule.match_type == 'host':
        names = _scoped_names(rule, 'source_nodes', 'org_source_nodes', organization)
        return 'node ' + ', '.join(names) if names else 'a node'
    return 'anywhere'


def summarize_tag(tag, rules=None):
    """One-line plain-English summary of the rules targeting `tag`.

    'Accepts …' for inbound rules, 'Sends …' for outbound; 'No rules yet.' if none.
    """
    targeting = list(rules if rules is not None else target_rules_for_tag(tag))
    inbound = sorted((r for r in targeting if r.direction == 'in'), key=lambda r: (r.port_min or 0))
    outbound = sorted((r for r in targeting if r.direction == 'out'), key=lambda r: (r.port_min or 0))
    if not inbound and not outbound:
        return 'No rules yet.'
    parts = []
    if inbound:
        parts.append('Accepts ' + '; '.join(f'{_service_label(r)} from {_peer_label(r, tag.organization)}' for r in inbound))
    if outbound:
        parts.append('Sends ' + '; '.join(f'{_service_label(r)} to {_peer_label(r, tag.organization)}' for r in outbound))
    return '. '.join(parts) + '.'
