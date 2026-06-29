"""What firewall rules effectively apply to a node, and why (provenance)."""

from nodes.api_registration import render_proto_port


def effective_rules(node):
    """Resolve the rules applying to `node` into display rows with provenance.

    Returns {'inbound': [...], 'outbound': [...], 'inbound_default_allow': bool,
    'outbound_default_allow': bool}; each row is {'entry': <render dict>, 'via': str}.
    'via' is 'direct' (node-targeted) or 'via tag <names>' (the node's tags in the
    rule's target_groups).
    """
    node_tag_ids = set(node.tags.values_list('id', flat=True))
    inbound, outbound = [], []
    for rule in node.get_all_applicable_firewall_rules():
        if rule.node_id == node.id:
            via = 'direct'
        else:
            matched = sorted(t.name for t in rule.target_groups.all() if t.id in node_tag_ids)
            if not matched and rule.security_group_id in node_tag_ids:
                matched = [rule.security_group.name]
            via = ('via tag ' + ', '.join(matched)) if matched else 'via tag'
        bucket = inbound if rule.direction == 'in' else outbound
        for entry in render_rule_entries_for_node(rule, node):
            bucket.append({'entry': entry, 'via': via})
    return {
        'inbound': inbound,
        'outbound': outbound,
        'inbound_default_allow': not inbound,
        'outbound_default_allow': not outbound,
    }


def render_rule_entries_for_node(rule, node):
    """Render entries for display using the node's organization as source scope."""
    base = {}
    render_proto_port(rule, base)
    return [{**base, **src} for src in render_sources_for_node(rule, node)]


def render_sources_for_node(rule, node):
    match_type = getattr(rule, 'match_type', 'any') or 'any'
    organization = node.organization

    if match_type == 'any':
        return [{'host': 'any'}]
    if match_type == 'groups':
        src_groups = list(
            rule.source_groups.filter(organization=organization).values_list('name', flat=True)
        )
        if src_groups:
            return [{'groups': src_groups}]
    elif match_type == 'host':
        node_ips = list(
            rule.source_nodes.filter(organization=organization).values_list('nebula_ip', flat=True)
        )
        if node_ips:
            return [{'cidr': f"{ip.split('/')[0]}/32"} for ip in node_ips]
    elif match_type == 'cidr' and rule.source_cidr:
        return [{'cidr': rule.source_cidr}]
    return []
