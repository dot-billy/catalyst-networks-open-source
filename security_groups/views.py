import json

import ipaddress

from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import FirewallRule, SecurityGroup, Tag
from .summaries import summarize_tag, target_rules_for_tag, target_rules_queryset
from nodes.models import Node
from nodes.tasks import renew_node_certificate
from django.views.decorators.http import require_POST
from organizations.permissions import IsOrganizationOwnerOrAdmin
from organizations.access import get_org_role, require_org_access
from django.http import JsonResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from rest_framework.views import APIView
from django.contrib.auth.decorators import login_required
from organizations.models import Membership, Organization
from django.core.exceptions import PermissionDenied
from django.contrib import messages
from django.urls import reverse
from django.utils.translation import gettext as _
from django.db import transaction
from django.db.models import Prefetch, Q
from organizations.mixins import OrganizationFilterMixin

@login_required
def security_group_list(request):
    """List security groups that the user has access to."""
    # Get organizations the user is a member of
    user_orgs = request.user.memberships.values_list('organization_id', flat=True)
    
    # Get security groups in those organizations
    security_groups = Tag.objects.filter(organization_id__in=user_orgs)
    
    # Handle organization filter
    selected_org = request.GET.get('organization', None)
    if selected_org:
        security_groups = security_groups.filter(organization_id=selected_org)
        selected_org_name = Tag.objects.filter(organization_id=selected_org).first().organization.name if security_groups.exists() else None
    else:
        selected_org_name = None
    
    # Handle search
    search_query = request.GET.get('search', '')
    if search_query:
        security_groups = security_groups.filter(name__icontains=search_query)
    
    # Get organizations for the filter dropdown
    organizations = request.user.organizations.all()
    # User can create if owner/admin in any org
    can_create = Membership.objects.filter(
        user=request.user,
        role__in=['owner', 'admin']
    ).exists()
    
    context = {
        'security_groups': security_groups,
        'organizations': organizations,
        'selected_org': selected_org,
        'selected_org_name': selected_org_name,
        'search_query': search_query,
        'can_create': can_create,
    }
    
    return render(request, 'security_groups/list.html', context)

@login_required
def security_group_create(request):
    """Create a new security group."""
    if request.method == 'POST':
        # Handle form submission for creating a security group
        name = request.POST.get('name')
        organization_id = request.POST.get('organization')
        description = request.POST.get('description', '')
        
        if name and organization_id:
            org = check_org_access(request.user, org_id=organization_id, required_roles=['owner', 'admin'])
            ok, initial_rule_data, organization_error = _validate_flat_initial_rule(request.POST)
            if ok:
                with transaction.atomic():
                    security_group = Tag.objects.create(
                        name=name,
                        organization=org,
                        description=description
                    )

                    if initial_rule_data:
                        rule = FirewallRule.objects.create(
                            security_group=security_group,
                            **initial_rule_data,
                        )
                        rule.target_groups.set([security_group])

                return redirect('security_groups:detail', pk=security_group.id)
            return render(
                request,
                'security_groups/create.html',
                {
                    'organizations': request.user.organizations.filter(id=organization_id),
                    'form': {},
                    'organization_error': organization_error,
                },
                status=400,
            )
    
    # Get organizations the user is an admin of - FIXED QUERY
    # Get organizations where the user has owner or admin role using the Membership model
    org_ids = Membership.objects.filter(
        user=request.user,
        role__in=['owner', 'admin']
    ).values_list('organization_id', flat=True)
    
    organizations = request.user.organizations.filter(id__in=org_ids)
    
    # Print for debugging
    print(f"Found {organizations.count()} organizations for user {request.user.email}")
    for org in organizations:
        print(f"- {org.name} (ID: {org.id})")
    
    context = {
        'organizations': organizations,
        'form': {}, # For handling form errors if needed
    }
    
    return render(request, 'security_groups/create.html', context)


def _validate_flat_initial_rule(post):
    """Validate optional legacy initial CIDR rule fields for the flat create route."""
    protocol = post.get('protocol')
    port_min_raw = post.get('port_min')
    port_max_raw = post.get('port_max')
    source_cidr = (post.get('source_cidr') or '').strip()
    rule_description = post.get('rule_description') or ''

    has_rule_input = any([protocol, port_min_raw, port_max_raw, source_cidr, rule_description])
    if not has_rule_input:
        return True, None, None

    if protocol not in {choice[0] for choice in FirewallRule.PROTOCOL_CHOICES}:
        return False, None, 'Choose a valid protocol.'
    if not source_cidr:
        return False, None, 'Source CIDR is required for the initial rule.'
    try:
        ipaddress.ip_network(source_cidr, strict=False)
    except ValueError:
        return False, None, 'Source CIDR must be a valid network.'

    if protocol in ('tcp', 'udp'):
        try:
            port_min = int(port_min_raw) if port_min_raw else None
            port_max = int(port_max_raw) if port_max_raw else port_min
        except (TypeError, ValueError):
            return False, None, 'Ports must be numeric.'
        if port_min is None:
            return False, None, 'A port is required for TCP and UDP rules.'
        if port_min < 1 or port_max > 65535 or port_min > port_max:
            return False, None, 'Ports must be between 1 and 65535, with the minimum no greater than the maximum.'
    else:
        port_min = None
        port_max = None

    return True, {
        'protocol': protocol,
        'port_min': port_min,
        'port_max': port_max,
        'source_cidr': source_cidr,
        'match_type': 'cidr',
        'description': rule_description,
    }, None

@login_required
def security_group_detail(request, pk):
    """View security group details."""
    security_group = get_object_or_404(Tag, id=pk)
    
    # Check if user has access to this security group
    if not request.user.memberships.filter(
        organization=security_group.organization
    ).exists():
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("You don't have permission to view this security group")
    
    # Get rules and nodes for this security group
    from nodes.models import Node
    rules = security_group.firewall_rules.prefetch_related(
        Prefetch(
            'source_groups',
            queryset=Tag.objects.filter(organization=security_group.organization).order_by('name'),
            to_attr='org_source_groups',
        ),
        Prefetch(
            'source_nodes',
            queryset=Node.objects.filter(organization=security_group.organization).order_by('name'),
            to_attr='org_source_nodes',
        ),
    ).all()
    nodes = security_group.nodes.all()
    
    context = {
        'security_group': security_group,
        'rules': rules,
        'nodes': nodes,
    }
    
    return render(request, 'security_groups/detail.html', context)

# New organization-specific view functions
def check_org_access(user, org_id=None, required_roles=None, organization_slug=None):
    """Helper function to check if user has access to an organization"""
    return require_org_access(
        user,
        org_id=org_id,
        slug=organization_slug,
        required_roles=required_roles,
    )

@login_required
def org_security_group_list(request, slug):
    """List security groups for a specific organization."""
    # Check if user has access to the organization
    org = check_org_access(request.user, organization_slug=slug)
    
    # Get security groups for this organization with the rule relations used by summaries and badges.
    target_rule_qs = target_rules_queryset(org)
    security_groups = (
        Tag.objects.filter(organization=org)
        .select_related('organization')
        .prefetch_related(
            Prefetch('firewall_rules', queryset=target_rule_qs, to_attr='legacy_target_rules'),
            Prefetch('rules_targeting', queryset=target_rule_qs, to_attr='m2m_target_rules'),
            'nodes',
        )
    )

    # Handle search
    search_query = request.GET.get('search', '')
    if search_query:
        security_groups = security_groups.filter(name__icontains=search_query)

    # Materialize so we can attach derived attrs without re-querying
    security_groups = list(security_groups)
    for sg in security_groups:
        rules = target_rules_for_tag(sg)
        sg.rule_count = len(rules)
        sg.summary = summarize_tag(sg, rules=rules)

    # Determine user's role in this organization for UI controls
    user_role = get_org_role(request.user, org)
    context = {
        'organization': org,
        'security_groups': security_groups,
        'search_query': search_query,
        'user_role': user_role,
    }
    
    return render(request, 'security_groups/org_list.html', context)


@login_required
def org_node_tag_matrix(request, slug):
    """Org-wide Node x Tag membership grid."""
    org = check_org_access(request.user, organization_slug=slug)
    tags = list(Tag.objects.filter(organization=org).order_by('name'))
    nodes = list(Node.objects.filter(organization=org).order_by('name'))
    membership = {}
    for nid, tid in Node.tags.through.objects.filter(node__organization=org).values_list('node_id', 'tag_id'):
        membership.setdefault(nid, set()).add(tid)
    for n in nodes:
        n.tag_id_set = membership.get(n.id, set())
    context = {
        'organization': org,
        'tags': tags,
        'nodes': nodes,
        'user_role': get_org_role(request.user, org),
    }
    return render(request, 'security_groups/matrix.html', context)


@login_required
@require_POST
def org_node_tag_matrix_apply(request, slug):
    """Commit a batch of Node x Tag membership changes, org-scoped."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    raw = request.POST.get('changes', '[]')
    try:
        changes = json.loads(raw)
    except (ValueError, TypeError):
        return HttpResponseBadRequest('Invalid matrix changes.')
    if not isinstance(changes, list):
        return HttpResponseBadRequest('Invalid matrix changes.')

    # Bulk-load org-scoped nodes and tags once to avoid N+1 and validate membership.
    nodes_by_id = {n.id: n for n in Node.objects.filter(organization=org)}
    tags_by_id = {t.id: t for t in Tag.objects.filter(organization=org)}
    desired_membership = {}
    for ch in changes:
        if not isinstance(ch, dict):
            return HttpResponseBadRequest('Invalid matrix changes.')
        nid, tid, op = ch.get('node'), ch.get('tag'), ch.get('op')
        if (
            type(nid) is not int
            or type(tid) is not int
            or nid not in nodes_by_id
            or tid not in tags_by_id
            or op not in ('add', 'remove')
        ):
            return HttpResponseBadRequest('Invalid matrix changes.')
        desired_membership[(nid, tid)] = op == 'add'

    existing_membership = set(
        Node.tags.through.objects.filter(
            node__organization=org,
            tag__organization=org,
        ).values_list('node_id', 'tag_id')
    )
    changed_node_ids = set()
    with transaction.atomic():
        for (nid, tid), should_have_tag in desired_membership.items():
            already_has_tag = (nid, tid) in existing_membership
            if should_have_tag == already_has_tag:
                continue
            node = nodes_by_id[nid]
            tag = tags_by_id[tid]
            if should_have_tag:
                node.tags.add(tag)
            else:
                node.tags.remove(tag)
            changed_node_ids.add(nid)
    # Queue re-signs outside the atomic block so a mid-batch crash rolls back all
    # membership changes without queuing any certificate renewals.
    for nid in sorted(changed_node_ids):
        renew_node_certificate.delay(nid)
    return render(request, 'security_groups/_matrix_apply_result.html', {'count': len(changed_node_ids)})


@login_required
def org_security_group_create(request, slug):
    """Create a new security group in a specific organization."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')

        if name:
            security_group = Tag.objects.create(
                name=name,
                organization=org,
                description=description
            )

            messages.success(
                request,
                f'Policy "{security_group.name}" created. Next, define the traffic rules that this group should allow.'
            )
            return redirect('security_groups_org:add_rule', slug=slug, sg_id=security_group.id)

        messages.error(request, 'A policy name is required.')
    
    context = {
        'organization': org,
        'form': {},  # For handling form errors if needed
    }
    
    return render(request, 'security_groups/org_create.html', context)

@login_required
def org_security_group_detail(request, slug, pk):
    """View security group details in an organization context."""
    # Check if user has access to the organization
    org = check_org_access(request.user, organization_slug=slug)
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(Tag, id=pk, organization=org)
    
    # Get rules and nodes for this security group
    rules = target_rules_for_tag(security_group)
    nodes = security_group.nodes.all().filter(organization=org)
    
    context = {
        'organization': org,
        'security_group': security_group,
        'rules': rules,
        'nodes': nodes,
        'user_role': get_org_role(request.user, org),
        'summary': summarize_tag(security_group, rules=rules),
    }
    
    # Use the shared detail template for organization context
    return render(request, 'security_groups/detail.html', context)

@login_required
def org_security_group_edit(request, slug, pk):
    """Edit a security group in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(Tag, id=pk, organization=org)
    
    if request.method == 'POST':
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        
        if name:
            security_group.name = name
            security_group.description = description
            security_group.save()
            
            return redirect('security_groups_org:detail', slug=slug, pk=security_group.id)
    
    context = {
        'organization': org,
        'security_group': security_group,
    }
    
    return render(request, 'security_groups/org_edit.html', context)

@login_required
def org_security_group_delete(request, slug, pk):
    """Delete a security group in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(Tag, id=pk, organization=org)
    
    if request.method == 'POST':
        security_group.delete()
        return redirect('security_groups_org:list', slug=slug)
    
    context = {
        'organization': org,
        'security_group': security_group,
    }
    
    return render(request, 'security_groups/org_delete.html', context)

@login_required
def org_add_rule(request, slug, sg_id):
    """Add a rule to a security group in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(SecurityGroup, id=sg_id, organization=org)
    
    if request.method == 'POST':
        post = request.POST.copy()
        post['dest_type'] = 'group'
        post['dest_group'] = str(security_group.id)
        error_message = None

        ok, field_data, error_message = _validate_policy_fields(org, post)
        if ok:
            ok, source_data, error_message = _validate_policy_source(org, post)
        if ok:
            with transaction.atomic():
                _save_policy_rule(FirewallRule(), field_data, source_data)
            messages.success(request, 'Rule added to the policy.')
            return redirect('security_groups_org:detail', slug=slug, pk=sg_id)
    else:
        error_message = None

    # Get all security groups and nodes in this organization for source selection
    all_groups = SecurityGroup.objects.filter(organization=org)
    from nodes.models import Node
    all_nodes = Node.objects.filter(organization=org)

    context = {
        'organization': org,
        'security_group': security_group,
        'error_message': error_message,
        'all_groups': all_groups,
        'all_nodes': all_nodes,
        'default_source_type': 'group',
    }
    
    return render(request, 'security_groups/org_add_rule.html', context)


def _get_target_rule_or_404(org, security_group, rule_id):
    return get_object_or_404(
        target_rules_queryset(org).filter(
            Q(security_group=security_group) | Q(target_groups=security_group),
        ),
        id=rule_id,
    )


@login_required
def org_edit_rule(request, slug, sg_id, rule_id):
    """Edit a rule in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(SecurityGroup, id=sg_id, organization=org)
    
    # Get the rule and check it belongs to this security group
    rule = _get_target_rule_or_404(org, security_group, rule_id)
    
    if request.method == 'POST':
        post = request.POST.copy()
        post['dest_type'] = 'group'
        post['dest_group'] = str(security_group.id)

        ok, field_data, error_message = _validate_policy_fields(org, post)
        if ok:
            ok, source_data, error_message = _validate_policy_source(org, post)
        if ok:
            with transaction.atomic():
                _save_policy_rule(rule, field_data, source_data)
            messages.success(request, 'Rule updated.')
            return redirect('security_groups_org:detail', slug=slug, pk=sg_id)
    else:
        error_message = None
    
    # Build context for editing sources
    all_groups = SecurityGroup.objects.filter(organization=org)
    from nodes.models import Node
    all_nodes = Node.objects.filter(organization=org)
    selected_group_ids = list(rule.source_groups.values_list('id', flat=True))
    selected_node_id = rule.source_nodes.values_list('id', flat=True).first()
    default_source_type = 'group' if selected_group_ids else ('host' if selected_node_id else 'group')
    
    context = {
        'organization': org,
        'security_group': security_group,
        'rule': rule,
        'all_groups': all_groups,
        'all_nodes': all_nodes,
        'selected_group_ids': selected_group_ids,
        'selected_node_id': selected_node_id,
        'default_source_type': default_source_type,
        'error_message': error_message,
    }
    
    return render(request, 'security_groups/org_edit_rule.html', context)

@login_required
def org_delete_rule(request, slug, sg_id, rule_id):
    """Delete a rule in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(SecurityGroup, id=sg_id, organization=org)
    
    # Get the rule and check it belongs to this security group
    rule = _get_target_rule_or_404(org, security_group, rule_id)
    
    if request.method == 'POST':
        rule.delete()
        messages.success(request, 'Rule removed from the policy.')
        return redirect('security_groups_org:detail', slug=slug, pk=sg_id)
    
    context = {
        'organization': org,
        'security_group': security_group,
        'rule': rule,
    }
    
    return render(request, 'security_groups/org_delete_rule.html', context)

@login_required
def org_assign_nodes(request, slug, sg_id):
    """Assign nodes to a security group in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(Tag, id=sg_id, organization=org)
    
    if request.method == 'POST':
        node_ids = request.POST.getlist('nodes')
        
        # Get existing nodes
        from nodes.models import Node
        nodes = Node.objects.filter(id__in=node_ids, organization=org)
        
        # Track currently assigned to detect removals
        previously_assigned = set(security_group.nodes.values_list('id', flat=True))
        
        # Assign nodes to the security group
        security_group.nodes.set(nodes)
        
        # Regenerate certificates for affected nodes (added or removed)
        affected_ids = previously_assigned.symmetric_difference(set(nodes.values_list('id', flat=True)))
        if affected_ids:
            from nodes.views import regenerate_certificate
            for node in Node.objects.filter(id__in=affected_ids, organization=org):
                regenerate_certificate(node)

        messages.success(request, 'Policy assignments updated.')
        return redirect('security_groups_org:detail', slug=slug, pk=sg_id)
    
    # Get all nodes in this organization
    from nodes.models import Node
    all_nodes = Node.objects.filter(organization=org)
    assigned_nodes = security_group.nodes.all()
    
    context = {
        'organization': org,
        'security_group': security_group,
        'all_nodes': all_nodes,
        'assigned_nodes': assigned_nodes,
    }
    
    return render(request, 'security_groups/org_assign_nodes.html', context)


def _policy_form_choices(org):
    """Shared choices for source and destination policy selectors."""
    from nodes.models import Node

    return {
        'all_groups': Tag.objects.filter(organization=org).order_by('name'),
        'all_nodes': Node.objects.filter(organization=org).order_by('name'),
    }


def _validate_policy_fields(org, post):
    """Validate protocol, port, description, and destination fields without mutating a rule."""
    from nodes.models import Node

    protocol = post.get('protocol')
    port = post.get('port')
    port_min_raw = post.get('port_min') or port
    port_max_raw = post.get('port_max') or port
    description = post.get('description', '')

    if protocol not in {choice[0] for choice in FirewallRule.PROTOCOL_CHOICES}:
        return False, None, 'Choose a protocol.'

    if protocol in ('tcp', 'udp'):
        try:
            port_min = int(port_min_raw) if port_min_raw else None
            port_max = int(port_max_raw) if port_max_raw else port_min
        except ValueError:
            return False, None, 'Ports must be numeric.'
        if port_min is None:
            return False, None, 'A port is required for TCP and UDP rules.'
        if port_min < 1 or port_max > 65535 or port_min > port_max:
            return False, None, 'Ports must be between 1 and 65535, with the minimum no greater than the maximum.'
    else:
        port_min = None
        port_max = None

    dest_type = post.get('dest_type')
    dest_group_id = post.get('dest_group')
    dest_node_id = post.get('dest_node')
    if dest_type == 'group' and dest_group_id:
        try:
            destination_group = Tag.objects.get(id=dest_group_id, organization=org)
        except Tag.DoesNotExist:
            return False, None, 'Destination group not found in this organization.'
        destination_node = None
    elif dest_type == 'host' and dest_node_id:
        try:
            destination_node = Node.objects.get(id=dest_node_id, organization=org)
        except Node.DoesNotExist:
            return False, None, 'Destination host not found in this organization.'
        destination_group = None
    else:
        return False, None, 'Choose a destination group or host.'

    return True, {
        'protocol': protocol,
        'port_min': port_min,
        'port_max': port_max,
        'description': description,
        'destination_group': destination_group,
        'destination_node': destination_node,
    }, None


def _validate_policy_source(org, post):
    """Validate source group or source host fields without mutating a rule."""
    from nodes.models import Node

    source_type = post.get('source_type')
    source_group_ids = post.getlist('source_group')
    source_node_id = post.get('source_node')
    source_cidr = post.get('source_cidr', '').strip()

    if source_type == 'group' and source_group_ids:
        try:
            submitted_ids = [int(source_group_id) for source_group_id in source_group_ids]
        except (TypeError, ValueError):
            return False, None, 'Source group not found in this organization.'
        valid_ids = set(
            Tag.objects.filter(
                id__in=submitted_ids,
                organization=org,
            ).values_list('id', flat=True)
        )
        if valid_ids != set(submitted_ids):
            return False, None, 'Source group not found in this organization.'
        return True, {
            'match_type': 'groups',
            'source_group_ids': list(dict.fromkeys(submitted_ids)),
            'source_node_ids': [],
            'source_cidr': '',
        }, None

    if source_type == 'host' and source_node_id:
        try:
            node_id = int(source_node_id)
            node = Node.objects.get(id=node_id, organization=org)
        except (TypeError, ValueError, Node.DoesNotExist):
            return False, None, 'Source host not found in this organization.'
        return True, {
            'match_type': 'host',
            'source_group_ids': [],
            'source_node_ids': [node.id],
            'source_cidr': '',
        }, None

    if source_cidr and not source_group_ids and not source_node_id:
        try:
            ipaddress.ip_network(source_cidr, strict=False)
        except ValueError:
            return False, None, 'Source CIDR must be a valid network.'
        return True, {
            'match_type': 'cidr',
            'source_group_ids': [],
            'source_node_ids': [],
            'source_cidr': source_cidr,
        }, None

    if source_type == 'any':
        return True, {
            'match_type': 'any',
            'source_group_ids': [],
            'source_node_ids': [],
            'source_cidr': '',
        }, None

    return False, None, 'Choose a source group or host.'


def _save_policy_rule(rule, field_data, source_data):
    """Persist a validated policy rule and its sources."""
    rule.protocol = field_data['protocol']
    rule.port_min = field_data['port_min']
    rule.port_max = field_data['port_max']
    rule.description = field_data['description']
    rule.security_group = field_data['destination_group']
    rule.node = field_data['destination_node']
    rule.match_type = source_data['match_type']
    rule.source_cidr = source_data['source_cidr']
    rule.save()
    rule.source_groups.set(source_data['source_group_ids'])
    rule.source_nodes.set(source_data['source_node_ids'])
    if field_data['destination_group']:
        rule.target_groups.set([field_data['destination_group']])
    else:
        rule.target_groups.clear()
    return rule


def _org_policy_queryset(org):
    """Policies visible in an org, including direction-first target-group rules."""
    from nodes.models import Node

    return (
        FirewallRule.objects.filter(
            Q(security_group__organization=org)
            | Q(node__organization=org)
            | Q(target_groups__organization=org)
        )
        .select_related('security_group', 'node')
        .prefetch_related(
            Prefetch(
                'target_groups',
                queryset=SecurityGroup.objects.filter(organization=org).order_by('name'),
                to_attr='org_target_groups',
            ),
            Prefetch(
                'source_groups',
                queryset=SecurityGroup.objects.filter(organization=org).order_by('name'),
                to_attr='org_source_groups',
            ),
            Prefetch(
                'source_nodes',
                queryset=Node.objects.filter(organization=org).order_by('name'),
                to_attr='org_source_nodes',
            ),
        )
        .distinct()
    )


def _is_legacy_node_destination_rule(rule):
    """Rules that target one node directly still use the legacy host form."""
    return bool(rule.node_id) and not rule.security_group_id and not rule.target_groups.exists()


def _legacy_policy_edit_context(org, rule, error_message=None):
    selected_source_group_ids = list(rule.source_groups.filter(organization=org).values_list('id', flat=True))
    selected_source_node_id = rule.source_nodes.filter(organization=org).values_list('id', flat=True).first()
    return {
        'organization': org,
        'rule': rule,
        'error_message': error_message,
        'selected_source_group_ids': selected_source_group_ids,
        'selected_source_node_id': selected_source_node_id,
        'selected_dest_group_id': rule.security_group_id,
        'selected_dest_node_id': rule.node_id,
        'default_source_type': 'group' if selected_source_group_ids else 'host' if selected_source_node_id else 'group',
        'default_dest_type': 'group' if rule.security_group_id else 'host',
        **_policy_form_choices(org),
    }


@login_required
def org_policy_list(request, slug):
    """List source-to-destination firewall policies for an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    rules = _org_policy_queryset(org).order_by('-created_at')

    search_query = request.GET.get('search', '').strip()
    if search_query:
        rules = rules.filter(description__icontains=search_query)

    context = {
        'organization': org,
        'rules': rules,
        'search_query': search_query,
        'user_role': get_org_role(request.user, org),
    }
    return render(request, 'security_groups/org_policy_list.html', context)


@login_required
def org_policy_create(request, slug):
    """Create a source-to-destination firewall policy."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])

    error_message = None
    if request.method == 'POST':
        ok, field_data, error_message = _validate_policy_fields(org, request.POST)
        if ok:
            ok, source_data, error_message = _validate_policy_source(org, request.POST)
            if ok:
                with transaction.atomic():
                    _save_policy_rule(FirewallRule(), field_data, source_data)
                    messages.success(request, 'Policy created.')
                    return redirect('security_groups_org:policy_list', slug=slug)

    prefill_source_group_ids = []
    prefill_source_node_id = None
    prefill_dest_group_id = None
    prefill_dest_node_id = None
    if request.method == 'GET':
        try:
            source_group_id = int(request.GET.get('source_group', '') or 0) or None
            if source_group_id and Tag.objects.filter(id=source_group_id, organization=org).exists():
                prefill_source_group_ids = [source_group_id]
        except ValueError:
            pass
        try:
            dest_group_id = int(request.GET.get('dest_group', '') or 0) or None
            if dest_group_id and Tag.objects.filter(id=dest_group_id, organization=org).exists():
                prefill_dest_group_id = dest_group_id
        except ValueError:
            pass
        from nodes.models import Node
        try:
            source_node_id = int(request.GET.get('source_node', '') or 0) or None
            if source_node_id and Node.objects.filter(id=source_node_id, organization=org).exists():
                prefill_source_node_id = source_node_id
        except ValueError:
            pass
        try:
            dest_node_id = int(request.GET.get('dest_node', '') or 0) or None
            if dest_node_id and Node.objects.filter(id=dest_node_id, organization=org).exists():
                prefill_dest_node_id = dest_node_id
        except ValueError:
            pass

    context = {
        'organization': org,
        'rule': None,
        'error_message': error_message,
        'default_source_type': 'host' if prefill_source_node_id else request.POST.get('source_type') or 'group',
        'default_dest_type': 'host' if prefill_dest_node_id else request.POST.get('dest_type') or 'group',
        'selected_source_group_ids': prefill_source_group_ids,
        'selected_source_node_id': prefill_source_node_id,
        'selected_dest_group_id': prefill_dest_group_id,
        'selected_dest_node_id': prefill_dest_node_id,
        **_policy_form_choices(org),
    }
    return render(request, 'security_groups/org_policy_form.html', context)


@login_required
def org_policy_edit(request, slug, rule_id):
    """Edit an existing firewall policy with the direction-first rule form."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    rule = get_object_or_404(_org_policy_queryset(org), id=rule_id)

    if _is_legacy_node_destination_rule(rule):
        error_message = None
        if request.method == 'POST':
            ok, field_data, error_message = _validate_policy_fields(org, request.POST)
            if ok:
                ok, source_data, error_message = _validate_policy_source(org, request.POST)
                if ok:
                    with transaction.atomic():
                        _save_policy_rule(rule, field_data, source_data)
                        messages.success(request, 'Policy updated.')
                        return redirect('security_groups_org:policy_list', slug=slug)
        return render(
            request,
            'security_groups/org_policy_form.html',
            _legacy_policy_edit_context(org, rule, error_message),
        )

    error = None
    if request.method == 'POST':
        updated_rule, error = create_rule_from_form(org, request.POST, rule=rule)
        if updated_rule:
            messages.success(request, 'Policy updated.')
            return redirect('security_groups_org:policy_list', slug=slug)

    return render(
        request,
        'security_groups/rule_form.html',
        _direction_first_form_context(
            org,
            request,
            rule=rule,
            error=error,
            form_action_url=reverse('security_groups_org:policy_edit', kwargs={'slug': slug, 'rule_id': rule.id}),
            title='Edit Rule',
            submit_label='Save Rule',
        ),
    )


@login_required
def org_policy_delete(request, slug, rule_id):
    """Delete a source-to-destination firewall policy."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    rule = get_object_or_404(_org_policy_queryset(org), id=rule_id)

    if request.method == 'POST':
        rule.delete()
        messages.success(request, 'Policy deleted.')
        return redirect('security_groups_org:policy_list', slug=slug)

    return render(
        request,
        'security_groups/org_policy_delete.html',
        {'organization': org, 'rule': rule},
    )


@login_required
def org_unassign_node(request, slug, sg_id, node_id):
    """Unassign a node from a security group in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(Tag, id=sg_id, organization=org)
    
    # Get the node and check it belongs to this organization
    from nodes.models import Node
    node = get_object_or_404(Node, id=node_id, organization=org)
    
    if request.method == 'POST':
        # Remove node from security group
        security_group.nodes.remove(node)

        # Regenerate certificate to drop group from cert
        from nodes.views import regenerate_certificate
        regenerate_certificate(node)

        messages.success(request, f'"{node.name}" was removed from the policy.')
        return redirect('security_groups_org:detail', slug=slug, pk=sg_id)

    return redirect('security_groups_org:detail', slug=slug, pk=sg_id)


# ---------------------------------------------------------------------------
# Direction-first rule editor (Slice 4b)
# ---------------------------------------------------------------------------

def _parse_id_list(raw_ids):
    ids = []
    try:
        for raw_id in raw_ids:
            ids.append(int(raw_id))
    except (TypeError, ValueError):
        return None
    return list(dict.fromkeys(ids))


def _ordered_org_tags(org, ids):
    tags_by_id = {
        tag.id: tag
        for tag in Tag.objects.filter(id__in=ids, organization=org)
    }
    if set(tags_by_id) != set(ids):
        return None
    return [tags_by_id[tag_id] for tag_id in ids]


def _validate_direction_first_payload(org, post):
    direction = post.get('direction')
    if direction not in ('in', 'out'):
        return None, 'Choose a direction (inbound or outbound).'

    target_ids = _parse_id_list(post.getlist('target_group'))
    if not target_ids:
        return None, 'Choose at least one tag this rule applies to.'
    target_tags = _ordered_org_tags(org, target_ids)
    if target_tags is None:
        return None, 'Target tag not found in this organization.'

    protocol = post.get('protocol')
    if protocol not in {p[0] for p in FirewallRule.PROTOCOL_CHOICES}:
        return None, 'Choose a protocol.'

    port_min = port_max = None
    if protocol in ('tcp', 'udp'):
        raw = post.get('port') or ''
        try:
            if '-' in raw:
                lo, hi = raw.split('-', 1)
                port_min, port_max = int(lo), int(hi)
            else:
                port_min = port_max = int(raw)
        except (ValueError, TypeError):
            return None, 'A numeric port (or min-max range) is required for TCP/UDP.'
        if port_min < 1 or port_min > 65535 or port_max < 1 or port_max > 65535:
            return None, 'Port numbers must be between 1 and 65535.'
        if port_min > port_max:
            return None, 'Port range start must not exceed port range end.'

    source_type = post.get('source_type')
    source_type_to_match_type = {
        'group': 'groups',
        'host': 'host',
        'cidr': 'cidr',
        'any': 'any',
    }
    if source_type not in source_type_to_match_type:
        return None, 'Choose a valid source type.'
    match_type = source_type_to_match_type[source_type]
    source_group_ids = []
    source_node_ids = []
    source_cidr = ''

    if match_type == 'groups':
        source_group_ids = _parse_id_list(post.getlist('source_group'))
        if not source_group_ids:
            return None, 'Choose at least one source tag.'
        if _ordered_org_tags(org, source_group_ids) is None:
            return None, 'Source tag not found in this organization.'
    elif match_type == 'host':
        try:
            source_node_id = int(post.get('source_node') or '')
        except (TypeError, ValueError):
            return None, 'Choose a source host.'
        if not Node.objects.filter(id=source_node_id, organization=org).exists():
            return None, 'Source host not found in this organization.'
        source_node_ids = [source_node_id]
    elif match_type == 'cidr':
        source_cidr = (post.get('source_cidr') or '').strip()
        if not source_cidr:
            return None, 'Enter a source CIDR.'
        try:
            ipaddress.ip_network(source_cidr, strict=False)
        except ValueError:
            return None, 'Enter a valid CIDR.'

    return {
        'direction': direction,
        'target_ids': [tag.id for tag in target_tags],
        'protocol': protocol,
        'port_min': port_min,
        'port_max': port_max,
        'description': post.get('description', ''),
        'match_type': match_type,
        'source_group_ids': source_group_ids,
        'source_node_ids': source_node_ids,
        'source_cidr': source_cidr,
    }, None


def create_rule_from_form(org, post, rule=None):
    """Validate, build, and save a direction-first FirewallRule.

    Returns (rule, None) on success or (None, error_message). All submitted
    targets and sources are org-scoped before the first save.
    """
    payload, error = _validate_direction_first_payload(org, post)
    if error:
        return None, error

    with transaction.atomic():
        rule = rule or FirewallRule()
        rule.direction = payload['direction']
        rule.protocol = payload['protocol']
        rule.port_min = payload['port_min']
        rule.port_max = payload['port_max']
        rule.description = payload['description']
        rule.match_type = payload['match_type']
        rule.source_cidr = payload['source_cidr']
        rule.node = None
        # Temp target so save() passes clean(); final storage is target_groups.
        rule.security_group_id = payload['target_ids'][0]
        rule.save()
        rule.target_groups.set(payload['target_ids'])
        rule.source_groups.set(payload['source_group_ids'])
        rule.source_nodes.set(payload['source_node_ids'])
        rule.security_group = None
        rule.save()  # clean() passes via pk + target_groups.exists()
    return rule, None


def _rule_port_value(rule):
    if not rule or rule.protocol not in ('tcp', 'udp') or rule.port_min is None:
        return ''
    if rule.port_max and rule.port_max != rule.port_min:
        return f'{rule.port_min}-{rule.port_max}'
    return str(rule.port_min)


def _rule_source_type(rule):
    if not rule:
        return 'group'
    return {
        'groups': 'group',
        'host': 'host',
        'cidr': 'cidr',
        'any': 'any',
    }.get(rule.match_type, 'any')


def _direction_first_form_context(
    org,
    request,
    *,
    rule=None,
    error=None,
    form_action_url=None,
    title='Create Rule',
    submit_label='Create Rule',
):
    is_post = request.method == 'POST'
    post = request.POST
    target_ids = post.getlist('target_group') if is_post else []
    source_group_ids = post.getlist('source_group') if is_post else []
    source_node_id = post.get('source_node', '') if is_post else ''
    source_cidr = post.get('source_cidr', '') if is_post else ''

    if not is_post and rule:
        target_ids = list(rule.target_groups.filter(organization=org).values_list('id', flat=True))
        if not target_ids and rule.security_group_id and rule.security_group.organization_id == org.id:
            target_ids = [rule.security_group_id]
        source_group_ids = list(rule.source_groups.filter(organization=org).values_list('id', flat=True))
        source_node_id = rule.source_nodes.filter(organization=org).values_list('id', flat=True).first() or ''
        source_cidr = rule.source_cidr

    selected_direction = post.get('direction') if is_post else (rule.direction if rule else 'in')
    selected_source_type = post.get('source_type') if is_post else _rule_source_type(rule)
    selected_protocol = post.get('protocol') if is_post else (rule.protocol if rule else 'tcp')
    selected_port = post.get('port') if is_post else _rule_port_value(rule)

    return {
        'organization': org,
        'rule': rule,
        'tags': Tag.objects.filter(organization=org).order_by('name'),
        'nodes': Node.objects.filter(organization=org).order_by('name'),
        'protocols': FirewallRule.PROTOCOL_CHOICES,
        'error': error,
        'form_title': title,
        'submit_label': submit_label,
        'form_action_url': form_action_url
        or reverse('security_groups_org:rule_create', kwargs={'slug': org.slug}),
        'preview_url': reverse('security_groups_org:rule_preview', kwargs={'slug': org.slug}),
        'selected_direction': selected_direction or 'in',
        'selected_source_type': selected_source_type or 'group',
        'selected_protocol': selected_protocol or 'tcp',
        'selected_port': selected_port,
        'selected_target_group_ids': [str(target_id) for target_id in target_ids],
        'selected_source_group_ids': [str(source_group_id) for source_group_id in source_group_ids],
        'selected_source_node_id': str(source_node_id) if source_node_id else '',
        'selected_source_cidr': source_cidr,
    }


@login_required
def org_rule_create(request, slug):
    """Direction-first rule editor."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    error = None
    if request.method == 'POST':
        rule, error = create_rule_from_form(org, request.POST)
        if rule:
            messages.success(request, 'Rule created.')
            return redirect('security_groups_org:policy_list', slug=slug)
    context = _direction_first_form_context(
        org,
        request,
        error=error,
        title='Create Rule',
        submit_label='Create Rule',
        form_action_url=reverse('security_groups_org:rule_create', kwargs={'slug': slug}),
    )
    return render(request, 'security_groups/rule_form.html', context)


@login_required
@require_POST
def org_rule_preview(request, slug):
    """Render a transient rule to its Nebula firewall entries without persisting."""
    from nodes.api_registration import render_rule_entries
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    entries = []
    targets = 0
    direction = request.POST.get('direction', 'in')
    egress_warning = False
    rule = None
    error = None
    with transaction.atomic():
        rule, error = create_rule_from_form(org, request.POST)
        if rule is not None:
            entries = render_rule_entries(rule)
            targets = Node.objects.filter(organization=org, tags__in=rule.target_groups.all()).distinct().count()
            if direction == 'out':
                # first outbound rule for these target nodes -> deny-by-default egress
                target_nodes = Node.objects.filter(organization=org, tags__in=rule.target_groups.all()).distinct()
                existing_outbound = FirewallRule.objects.filter(
                    direction='out', target_groups__in=rule.target_groups.all()
                ).exclude(id=rule.id).exists()
                egress_warning = target_nodes.exists() and not existing_outbound
        transaction.set_rollback(True)
    return render(request, 'security_groups/_rule_preview.html', {
        'entries': entries, 'direction': direction, 'targets': targets,
        'egress_warning': egress_warning, 'error': error if rule is None else None,
    })
