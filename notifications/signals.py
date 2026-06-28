"""Connect notification events to security and model lifecycle signals."""
import logging

from django.db.models.signals import m2m_changed, post_save, pre_delete, pre_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)


def _dispatch_event(event_type, organization_id, data):
    try:
        from notifications.dispatch import dispatch_event

        dispatch_event(event_type, organization_id, data)
    except Exception:
        logger.exception("Failed to dispatch notification event %s", event_type)


def _node_payload(node):
    return {
        'node_name': node.name,
        'nebula_ip': node.nebula_ip,
        'is_lighthouse': node.is_lighthouse,
    }


def _group_payload(group):
    return {
        'group_name': group.name,
        'description': group.description,
    }


def _policy_organization_id(policy):
    if policy.security_group_id:
        return policy.security_group.organization_id
    if policy.node_id:
        return policy.node.organization_id
    return None


def _policy_payload(policy):
    if policy.security_group_id:
        target = policy.security_group.name
        target_type = 'group'
    elif policy.node_id:
        target = policy.node.name
        target_type = 'node'
    else:
        target = ''
        target_type = ''

    payload = {
        'policy': str(policy),
        'description': policy.description,
        'target': target,
        'target_type': target_type,
        'protocol': policy.protocol,
        'port_min': policy.port_min,
        'port_max': policy.port_max,
        'source_cidr': policy.source_cidr,
    }
    changes = getattr(policy, '_notification_changes', None)
    if changes:
        payload['changes'] = changes
    return payload


def _policy_change_value(field_name, value):
    if field_name == 'security_group_id' and value:
        from security_groups.models import Tag

        group = Tag.objects.filter(id=value).first()
        return group.name if group else value
    if field_name == 'node_id' and value:
        from nodes.models import Node

        node = Node.objects.filter(id=value).first()
        return node.name if node else value
    return value


def _policy_changed_fields(policy):
    original = getattr(policy, '_notification_original', None)
    if not original:
        return {}

    changes = {}
    for field_name in [
        'description',
        'protocol',
        'port_min',
        'port_max',
        'source_cidr',
        'security_group_id',
        'node_id',
    ]:
        old_value = original[field_name]
        new_value = getattr(policy, field_name)
        if old_value != new_value:
            display_name = {
                'security_group_id': 'target_group',
                'node_id': 'target_node',
            }.get(field_name, field_name)
            changes[display_name] = {
                'old': _policy_change_value(field_name, old_value),
                'new': _policy_change_value(field_name, new_value),
            }
    return changes


def _member_payload(membership):
    return {
        'email': membership.user.email,
        'role': membership.role,
    }


def _node_names(node_ids):
    from nodes.models import Node

    return list(Node.objects.filter(id__in=node_ids).order_by('name').values_list('name', flat=True))


def _group_names(group_ids):
    from security_groups.models import Tag

    return list(Tag.objects.filter(id__in=group_ids).order_by('name').values_list('name', flat=True))


@receiver(post_save, sender='nodes.Node')
def handle_node_saved(sender, instance, created, **kwargs):
    if created:
        _dispatch_event('node.added', instance.organization_id, _node_payload(instance))


@receiver(pre_delete, sender='nodes.Node')
def handle_node_deleted(sender, instance, **kwargs):
    _dispatch_event('node.removed', instance.organization_id, _node_payload(instance))


@receiver(post_save, sender='security_groups.Tag')
def handle_group_saved(sender, instance, created, **kwargs):
    event_type = 'group.created' if created else 'group.updated'
    _dispatch_event(event_type, instance.organization_id, _group_payload(instance))


@receiver(pre_delete, sender='security_groups.Tag')
def handle_group_deleted(sender, instance, **kwargs):
    _dispatch_event('group.deleted', instance.organization_id, _group_payload(instance))


@receiver(pre_save, sender='security_groups.FirewallRule')
def capture_policy_changes(sender, instance, **kwargs):
    if not instance.pk:
        return

    original = sender.objects.filter(pk=instance.pk).first()
    if not original:
        return

    instance._notification_original = {
        'description': original.description,
        'protocol': original.protocol,
        'port_min': original.port_min,
        'port_max': original.port_max,
        'source_cidr': original.source_cidr,
        'security_group_id': original.security_group_id,
        'node_id': original.node_id,
    }


@receiver(post_save, sender='security_groups.FirewallRule')
def handle_policy_saved(sender, instance, created, **kwargs):
    organization_id = _policy_organization_id(instance)
    if not organization_id:
        return
    event_type = 'policy.created' if created else 'policy.updated'
    if not created:
        instance._notification_changes = _policy_changed_fields(instance)
    _dispatch_event(event_type, organization_id, _policy_payload(instance))


@receiver(pre_delete, sender='security_groups.FirewallRule')
def handle_policy_deleted(sender, instance, **kwargs):
    organization_id = _policy_organization_id(instance)
    if organization_id:
        _dispatch_event('policy.deleted', organization_id, _policy_payload(instance))


@receiver(post_save, sender='organizations.Membership')
def handle_membership_saved(sender, instance, created, **kwargs):
    event_type = 'member.created' if created else 'member.updated'
    _dispatch_event(event_type, instance.organization_id, _member_payload(instance))


@receiver(pre_delete, sender='organizations.Membership')
def handle_membership_deleted(sender, instance, **kwargs):
    _dispatch_event('member.deleted', instance.organization_id, _member_payload(instance))


def _handle_group_node_membership_change(action, instance, reverse, model, pk_set):
    if action not in {'post_add', 'post_remove', 'pre_clear'}:
        return

    if reverse:
        groups = [instance]
        if action == 'pre_clear':
            node_ids = list(instance.nodes.values_list('id', flat=True))
        else:
            node_ids = list(pk_set or [])
    else:
        node_ids = [instance.id]
        if action == 'pre_clear':
            groups = list(instance.tags.all())
        else:
            groups = list(model.objects.filter(id__in=pk_set or []))

    if not node_ids:
        return

    change_key = 'nodes_added' if action == 'post_add' else 'nodes_removed'
    changes = {change_key: _node_names(node_ids)}
    for group in groups:
        payload = _group_payload(group)
        payload['changes'] = changes
        _dispatch_event('group.updated', group.organization_id, payload)


def _handle_policy_source_membership_change(source_type, action, instance, reverse, model, pk_set):
    if action not in {'post_add', 'post_remove', 'pre_clear'}:
        return

    if reverse:
        source_ids = [instance.id]
        if action == 'pre_clear':
            policies = list(instance.rules_as_source.all())
        else:
            policies = list(model.objects.filter(id__in=pk_set or []))
    else:
        policies = [instance]
        if action == 'pre_clear':
            source_manager = instance.source_nodes if source_type == 'nodes' else instance.source_groups
            source_ids = list(source_manager.values_list('id', flat=True))
        else:
            source_ids = list(pk_set or [])

    if not source_ids:
        return

    source_names = _node_names(source_ids) if source_type == 'nodes' else _group_names(source_ids)
    change_key = f"source_{source_type}_{'added' if action == 'post_add' else 'removed'}"
    for policy in policies:
        organization_id = _policy_organization_id(policy)
        if not organization_id:
            continue
        policy._notification_changes = {change_key: source_names}
        _dispatch_event('policy.updated', organization_id, _policy_payload(policy))


from nodes.models import Node
from security_groups.models import FirewallRule


@receiver(m2m_changed, sender=Node.tags.through)
def handle_group_node_membership_changed(sender, instance, action, reverse, model, pk_set, **kwargs):
    _handle_group_node_membership_change(action, instance, reverse, model, pk_set)


@receiver(m2m_changed, sender=FirewallRule.source_nodes.through)
def handle_policy_source_nodes_changed(sender, instance, action, reverse, model, pk_set, **kwargs):
    _handle_policy_source_membership_change('nodes', action, instance, reverse, model, pk_set)


@receiver(m2m_changed, sender=FirewallRule.source_groups.through)
def handle_policy_source_groups_changed(sender, instance, action, reverse, model, pk_set, **kwargs):
    _handle_policy_source_membership_change('groups', action, instance, reverse, model, pk_set)

try:
    from axes.signals import user_locked_out

    def handle_lockout(sender, request, credentials, **kwargs):
        """Fired by django-axes when a user is locked out."""
        from notifications.dispatch import dispatch_event
        from organizations.models import Membership

        email = credentials.get('username', '') or credentials.get('email', '')
        ip = request.META.get('REMOTE_ADDR', 'unknown')

        memberships = Membership.objects.filter(
            user__email=email,
            role__in=['owner', 'admin'],
        )
        for m in memberships:
            dispatch_event('security.brute_force', m.organization_id, {
                'target_email': email,
                'ip_address': ip,
            })

    user_locked_out.connect(handle_lockout)
except ImportError:
    logger.debug("django-axes not available, skipping brute-force signal")
