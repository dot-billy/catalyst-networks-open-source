import ipaddress

from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import FirewallRule, SecurityGroup, Tag
from .summaries import summarize_tag, target_rules_for_tag, target_rules_queryset
from organizations.permissions import IsOrganizationOwnerOrAdmin
from organizations.access import get_org_role, require_org_access
from django.http import JsonResponse
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


@login_required
def org_policy_list(request, slug):
    """List source-to-destination firewall policies for an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    from nodes.models import Node

    rules = (
        FirewallRule.objects.filter(
            Q(security_group__organization=org) | Q(node__organization=org)
        )
        .select_related('security_group', 'node')
        .prefetch_related(
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
        .order_by('-created_at')
    )

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
    """Edit an existing source-to-destination firewall policy."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    rule = get_object_or_404(
        FirewallRule.objects.filter(
            Q(security_group__organization=org) | Q(node__organization=org)
        ),
        id=rule_id,
    )

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

    selected_source_group_ids = list(rule.source_groups.filter(organization=org).values_list('id', flat=True))
    selected_source_node_id = rule.source_nodes.filter(organization=org).values_list('id', flat=True).first()
    context = {
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
    return render(request, 'security_groups/org_policy_form.html', context)


@login_required
def org_policy_delete(request, slug, rule_id):
    """Delete a source-to-destination firewall policy."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    rule = get_object_or_404(
        FirewallRule.objects.filter(
            Q(security_group__organization=org) | Q(node__organization=org)
        ),
        id=rule_id,
    )

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
