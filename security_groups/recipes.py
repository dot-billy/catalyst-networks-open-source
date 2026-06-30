"""Preset firewall-rule recipes that materialize onto a Tag, idempotently."""

from django.db import transaction

RECIPES = {
    'web': {
        'label': 'Web tier',
        'description': 'Accept HTTP and HTTPS from anywhere.',
        'rules': [
            {'direction': 'in', 'protocol': 'tcp', 'port': 80, 'source': 'any'},
            {'direction': 'in', 'protocol': 'tcp', 'port': 443, 'source': 'any'},
        ],
    },
    'db': {
        'label': 'Database tier',
        'description': 'Accept PostgreSQL from the web tier.',
        'rules': [
            {'direction': 'in', 'protocol': 'tcp', 'port': 5432, 'source': 'tag:web'},
        ],
    },
    'admin': {
        'label': 'Admin-only',
        'description': 'Accept SSH from the admin tag.',
        'rules': [
            {'direction': 'in', 'protocol': 'tcp', 'port': 22, 'source': 'tag:admin'},
        ],
    },
    'jump': {
        'label': 'Jump host',
        'description': 'Accept SSH from anywhere.',
        'rules': [
            {'direction': 'in', 'protocol': 'tcp', 'port': 22, 'source': 'any'},
        ],
    },
}


def apply_recipe(tag, key, org):
    """(Re)apply recipe `key` to `tag`, idempotently. Returns the created rules.

    Deletes the tag's existing recipe-owned rules, regenerates from the recipe
    (temp-target save pattern), and records the recipe on the tag. Hand-added
    (non-recipe) rules are untouched.
    """
    from .models import FirewallRule, Tag
    if key not in RECIPES:
        raise ValueError(f"Unknown recipe: {key}")
    with transaction.atomic():
        tag = Tag.objects.select_for_update().get(pk=tag.pk)
        FirewallRule.objects.filter(target_groups=tag, managed_by_recipe=True).delete()
        created = []
        for spec in RECIPES[key]['rules']:
            is_tag_source = spec['source'].startswith('tag:')
            rule = FirewallRule(
                direction=spec['direction'], protocol=spec['protocol'],
                port_min=spec.get('port'), port_max=spec.get('port'),
                match_type='groups' if is_tag_source else 'any',
                managed_by_recipe=True,
            )
            rule.security_group = tag  # temp target so first save() passes clean()
            rule.save()
            rule.target_groups.add(tag)
            rule.security_group = None
            if is_tag_source:
                src = Tag.objects.get_or_create(name=spec['source'].split(':', 1)[1], organization=org)[0]
                rule.source_groups.add(src)
            rule.save()
            created.append(rule)
        tag.recipe = key
        tag.save(update_fields=['recipe'])
        return created
