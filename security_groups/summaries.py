"""Plain-English summaries of what a Tag's firewall rules allow."""

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


def _peer_label(rule):
    """Who the rule's source is: 'tag web', 'anywhere', '10.0.0.0/8', 'node db1'."""
    if rule.match_type == 'groups':
        names = sorted(rule.source_groups.values_list('name', flat=True))
        return 'tag ' + ', '.join(names) if names else 'a tag'
    if rule.match_type == 'cidr':
        return rule.source_cidr or 'a network'
    if rule.match_type == 'host':
        names = sorted(rule.source_nodes.values_list('name', flat=True))
        return 'node ' + ', '.join(names) if names else 'a node'
    return 'anywhere'


def summarize_tag(tag):
    """One-line plain-English summary of the rules targeting `tag`.

    'Accepts …' for inbound rules, 'Sends …' for outbound; 'No rules yet.' if none.
    """
    targeting = list(tag.rules_targeting.all())
    inbound = sorted((r for r in targeting if r.direction == 'in'), key=lambda r: (r.port_min or 0))
    outbound = sorted((r for r in targeting if r.direction == 'out'), key=lambda r: (r.port_min or 0))
    if not inbound and not outbound:
        return 'No rules yet.'
    parts = []
    if inbound:
        parts.append('Accepts ' + '; '.join(f'{_service_label(r)} from {_peer_label(r)}' for r in inbound))
    if outbound:
        parts.append('Sends ' + '; '.join(f'{_service_label(r)} to {_peer_label(r)}' for r in outbound))
    return '. '.join(parts) + '.'
