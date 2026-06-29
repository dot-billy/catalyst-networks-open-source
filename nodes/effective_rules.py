"""What firewall rules effectively apply to a node, and why (provenance)."""

from nodes.api_registration import render_rule_entries


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
            via = ('via tag ' + ', '.join(matched)) if matched else 'via tag'
        bucket = inbound if rule.direction == 'in' else outbound
        for entry in render_rule_entries(rule):
            bucket.append({'entry': entry, 'via': via})
    return {
        'inbound': inbound,
        'outbound': outbound,
        'inbound_default_allow': not inbound,
        'outbound_default_allow': not outbound,
    }
