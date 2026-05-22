from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import viewsets, status, serializers
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import SecurityGroup, FirewallRule
# from .serializers import (
#     SecurityGroupSerializer, 
#     FirewallRuleSerializer,
#     FirewallRuleCreateSerializer
# )
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
from django.db.models import Q
# from organizations.decorators import organization_owner_or_admin_required
from organizations.mixins import OrganizationFilterMixin

# REST API ViewSets
# class SecurityGroupViewSet(viewsets.ModelViewSet):
#     """
#     ViewSet for managing security groups.
#     """
#     serializer_class = SecurityGroupSerializer
#     permission_classes = [IsOrganizationOwnerOrAdmin]
#     
#     def get_queryset(self):
#         """
#         Filter security groups to only show those from organizations the user is a member of.
#         """
#         return SecurityGroup.objects.filter(organization__memberships__user=self.request.user)
#     
#     def perform_create(self, serializer):
#         """
#         Ensure that user can only create security groups in organizations they are a member of.
#         """
#         organization_id = self.request.data.get('organization')
#         if not self.request.user.memberships.filter(
#             organization_id=organization_id, 
#             role__in=['owner', 'admin']
#         ).exists():
#             raise serializers.ValidationError(
#                 {"organization": "You don't have permission to create security groups in this organization"}
#             )
#         
#         serializer.save()
#     
#     @action(detail=True, methods=['get'])
#     def rules(self, request, pk=None):
#         """
#         List all rules for a security group.
#         """
#         security_group = self.get_object()
#         rules = security_group.rules.all()
#         serializer = FirewallRuleSerializer(rules, many=True)
#         return Response(serializer.data)
#     
#     @action(detail=True, methods=['get'])
#     def nodes(self, request, pk=None):
#         """
#         List all nodes in this security group.
#         """
#         security_group = self.get_object()
#         nodes = security_group.nodes.all()
#         
#         # Use NodeSerializer to serialize the nodes
#         from nodes.serializers import NodeSerializer
#         serializer = NodeSerializer(nodes, many=True)
#         return Response(serializer.data)

# class OrgSecurityGroupViewSet(OrganizationFilterMixin, SecurityGroupViewSet):
#     """
#     ViewSet for managing security groups within a specific organization.
#     
#     This ViewSet provides the same functionality as SecurityGroupViewSet,
#     but filters security groups by the organization specified in the URL.
#     """
#     pass

# class FirewallRuleViewSet(viewsets.ModelViewSet):
#     """
#     ViewSet for managing security rules.
#     """
#     permission_classes = [IsOrganizationOwnerOrAdmin]
#     
#     def get_serializer_class(self):
#         """
#         Use different serializers for create and retrieve operations.
#         """
#         if self.action in ['create', 'update', 'partial_update']:
#             return FirewallRuleCreateSerializer
#         return FirewallRuleSerializer
#     
#     def get_queryset(self):
#         """
#         Filter security rules to only show those from security groups in organizations 
#         the user is a member of.
#         """
#         user = self.request.user
#         return FirewallRule.objects.filter(
#             security_group__organization__memberships__user=user
#         )
#     
#     def perform_create(self, serializer):
#         """
#         Ensure that user can only create rules in security groups they have access to.
#         """
#         security_group_id = self.request.data.get('security_group')
#         security_group = get_object_or_404(SecurityGroup, id=security_group_id)
#         
#         # Check if user can access this security group
#         if not self.request.user.memberships.filter(
#             organization=security_group.organization, 
#             role__in=['owner', 'admin']
#         ).exists():
#             raise serializers.ValidationError(
#                 {"security_group": "You don't have permission to add rules to this security group"}
#             )
#         
#         serializer.save()

# @method_decorator(csrf_exempt, name='dispatch')
# class ExecuteSQLView(APIView):
#     """
#     Debug endpoint for executing SQL (TESTING ONLY - NOT FOR PRODUCTION).
#     """
#     def post(self, request, format=None):
#         try:
#             sql = request.data.get('sql')
#             params = request.data.get('params', [])
#             
#             if not sql:
#                 return JsonResponse({'error': 'SQL query is required'}, status=400)
#                 
#             # For security, only allow specific SQL operations
#             sql_lower = sql.lower()
#             if not (sql_lower.startswith('insert into nodes_node_security_groups') or 
#                     sql_lower.startswith('delete from nodes_node_security_groups')):
#                 return JsonResponse({'error': 'Only security group assignment operations are allowed'}, status=403)
#             
#             # Execute the SQL
#             from django.db import connection
#             with connection.cursor() as cursor:
#                 cursor.execute(sql, params)
#                 
#             return JsonResponse({'status': 'success'})
#             
#         except Exception as e:
#             return JsonResponse({'error': str(e)}, status=500)

# Legacy web views (flat hierarchy)
@login_required
def security_group_list(request):
    """List security groups that the user has access to."""
    # Get organizations the user is a member of
    user_orgs = request.user.memberships.values_list('organization_id', flat=True)
    
    # Get security groups in those organizations
    security_groups = SecurityGroup.objects.filter(organization_id__in=user_orgs)
    
    # Handle organization filter
    selected_org = request.GET.get('organization', None)
    if selected_org:
        security_groups = security_groups.filter(organization_id=selected_org)
        selected_org_name = SecurityGroup.objects.filter(organization_id=selected_org).first().organization.name if security_groups.exists() else None
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
            # Create the security group
            security_group = SecurityGroup.objects.create(
                name=name,
                organization_id=organization_id,
                description=description
            )
            
            # Handle initial firewall rule if provided
            protocol = request.POST.get('protocol')
            port_min = request.POST.get('port_min')
            port_max = request.POST.get('port_max')
            source_cidr = request.POST.get('source_cidr')
            rule_description = request.POST.get('rule_description')
            
            if protocol and (protocol == 'icmp' or (port_min and port_max)) and source_cidr:
                FirewallRule.objects.create(
                    security_group=security_group,
                    protocol=protocol,
                    port_min=port_min if port_min else None,
                    port_max=port_max if port_max else None,
                    source_cidr=source_cidr,
                    description=rule_description
                )
            
            return redirect('security_groups:detail', pk=security_group.id)
    
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

@login_required
def security_group_detail(request, pk):
    """View security group details."""
    security_group = get_object_or_404(SecurityGroup, id=pk)
    
    # Check if user has access to this security group
    if not request.user.memberships.filter(
        organization=security_group.organization
    ).exists():
        from django.core.exceptions import PermissionDenied
        raise PermissionDenied("You don't have permission to view this security group")
    
    # Get rules and nodes for this security group
    rules = security_group.firewall_rules.all()
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
    
    # Get security groups for this organization
    security_groups = SecurityGroup.objects.filter(organization=org)
    
    # Handle search
    search_query = request.GET.get('search', '')
    if search_query:
        security_groups = security_groups.filter(name__icontains=search_query)
    
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
            security_group = SecurityGroup.objects.create(
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
    security_group = get_object_or_404(SecurityGroup, id=pk, organization=org)
    
    # Get rules and nodes for this security group
    rules = security_group.firewall_rules.prefetch_related('source_groups', 'source_nodes').all()
    nodes = security_group.nodes.all().filter(organization=org)
    
    context = {
        'organization': org,
        'security_group': security_group,
        'rules': rules,
        'nodes': nodes,
        'user_role': get_org_role(request.user, org),
    }
    
    # Use the shared detail template for organization context
    return render(request, 'security_groups/detail.html', context)

@login_required
def org_security_group_edit(request, slug, pk):
    """Edit a security group in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(SecurityGroup, id=pk, organization=org)
    
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
    security_group = get_object_or_404(SecurityGroup, id=pk, organization=org)
    
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
        protocol = request.POST.get('protocol')
        port = request.POST.get('port')
        port_val = int(port) if port and port.isdigit() else None
        description = request.POST.get('description', '')
        source_type = request.POST.get('source_type')
        source_group_ids = request.POST.getlist('source_group')
        source_node_id = request.POST.get('source_node')
        error_message = None

        # Validation: port only applies to TCP/UDP and a source is always required.
        valid = protocol and (protocol in ['icmp', 'any'] or port)
        has_source = (
            (source_type == 'group' and source_group_ids) or
            (source_type == 'host' and source_node_id)
        )
        if valid and has_source:
            rule = FirewallRule.objects.create(
                security_group=security_group,
                protocol=protocol,
                port_min=port_val if protocol in ['tcp', 'udp'] else None,
                port_max=port_val if protocol in ['tcp', 'udp'] else None,
                description=description
            )
            if source_type == 'group' and source_group_ids:
                rule.source_groups.set(source_group_ids)
            elif source_type == 'host' and source_node_id:
                rule.source_nodes.set([source_node_id])
            messages.success(request, 'Rule added to the policy.')
            return redirect('security_groups_org:detail', slug=slug, pk=sg_id)
        else:
            error_message = 'Choose a protocol, define a source, and add a port for TCP/UDP rules.'
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

@login_required
def org_edit_rule(request, slug, sg_id, rule_id):
    """Edit a rule in an organization context."""
    # Check if user has admin access to the organization
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    # Get the security group and check it belongs to this organization
    security_group = get_object_or_404(SecurityGroup, id=sg_id, organization=org)
    
    # Get the rule and check it belongs to this security group
    rule = get_object_or_404(FirewallRule, id=rule_id, security_group=security_group)
    
    if request.method == 'POST':
        protocol = request.POST.get('protocol')
        port_min = request.POST.get('port_min')
        port_max = request.POST.get('port_max')
        source_cidr = request.POST.get('source_cidr', '')
        description = request.POST.get('description', '')
        source_type = request.POST.get('source_type')  # 'group' or 'host'
        source_group_ids = request.POST.getlist('source_group')
        source_node_id = request.POST.get('source_node')
        
        # Update simple fields
        rule.protocol = protocol
        rule.port_min = port_min if port_min else None
        rule.port_max = port_max if port_max else None
        rule.description = description
        
        # Reset sources
        rule.source_cidr = ''
        rule.save()  # Save first so M2M updates apply cleanly
        rule.source_groups.clear()
        rule.source_nodes.clear()
        
        # Apply source selection in priority order like add flow
        if source_type == 'group' and source_group_ids:
            rule.source_groups.set(source_group_ids)
        elif source_type == 'host' and source_node_id:
            from nodes.models import Node
            try:
                node_obj = Node.objects.get(id=source_node_id, organization=org)
                rule.source_nodes.set([node_obj.id])
            except Node.DoesNotExist:
                pass
        else:
            # Fallback to CIDR if provided
            rule.source_cidr = source_cidr
        
        rule.save()
        messages.success(request, 'Rule updated.')
        return redirect('security_groups_org:detail', slug=slug, pk=sg_id)
    
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
    rule = get_object_or_404(FirewallRule, id=rule_id, security_group=security_group)
    
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
    security_group = get_object_or_404(SecurityGroup, id=sg_id, organization=org)
    
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
        'all_groups': SecurityGroup.objects.filter(organization=org).order_by('name'),
        'all_nodes': Node.objects.filter(organization=org).order_by('name'),
    }


def _apply_policy_fields(rule, org, post):
    """Apply protocol, port, description, and destination fields to a rule."""
    from nodes.models import Node

    protocol = post.get('protocol')
    port = post.get('port')
    port_min_raw = post.get('port_min') or port
    port_max_raw = post.get('port_max') or port
    description = post.get('description', '')

    if protocol not in {choice[0] for choice in FirewallRule.PROTOCOL_CHOICES}:
        return False, 'Choose a protocol.'

    rule.protocol = protocol
    rule.description = description

    if protocol in ('tcp', 'udp'):
        try:
            port_min = int(port_min_raw) if port_min_raw else None
            port_max = int(port_max_raw) if port_max_raw else port_min
        except ValueError:
            return False, 'Ports must be numeric.'
        if port_min is None:
            return False, 'A port is required for TCP and UDP rules.'
        if port_min < 1 or port_max > 65535 or port_min > port_max:
            return False, 'Ports must be between 1 and 65535, with the minimum no greater than the maximum.'
        rule.port_min = port_min
        rule.port_max = port_max
    else:
        rule.port_min = None
        rule.port_max = None

    dest_type = post.get('dest_type')
    dest_group_id = post.get('dest_group')
    dest_node_id = post.get('dest_node')
    if dest_type == 'group' and dest_group_id:
        try:
            rule.security_group = SecurityGroup.objects.get(id=dest_group_id, organization=org)
            rule.node = None
        except SecurityGroup.DoesNotExist:
            return False, 'Destination group not found in this organization.'
    elif dest_type == 'host' and dest_node_id:
        try:
            rule.node = Node.objects.get(id=dest_node_id, organization=org)
            rule.security_group = None
        except Node.DoesNotExist:
            return False, 'Destination host not found in this organization.'
    else:
        return False, 'Choose a destination group or host.'

    return True, None


def _apply_policy_source(rule, org, post):
    """Apply a source group or source host to a saved rule."""
    from nodes.models import Node

    source_type = post.get('source_type')
    source_group_ids = post.getlist('source_group')
    source_node_id = post.get('source_node')

    if source_type == 'group' and source_group_ids:
        valid_ids = list(
            SecurityGroup.objects.filter(
                id__in=source_group_ids,
                organization=org,
            ).values_list('id', flat=True)
        )
        if not valid_ids:
            return False, 'Source group not found in this organization.'
        rule.source_cidr = ''
        rule.save()
        rule.source_groups.set(valid_ids)
        rule.source_nodes.clear()
        return True, None

    if source_type == 'host' and source_node_id:
        try:
            node = Node.objects.get(id=source_node_id, organization=org)
        except Node.DoesNotExist:
            return False, 'Source host not found in this organization.'
        rule.source_cidr = ''
        rule.save()
        rule.source_groups.clear()
        rule.source_nodes.set([node.id])
        return True, None

    return False, 'Choose a source group or host.'


@login_required
def org_policy_list(request, slug):
    """List source-to-destination firewall policies for an organization."""
    org = check_org_access(request.user, organization_slug=slug)

    rules = (
        FirewallRule.objects.filter(
            Q(security_group__organization=org) | Q(node__organization=org)
        )
        .select_related('security_group', 'node')
        .prefetch_related('source_groups', 'source_nodes')
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
        rule = FirewallRule()
        ok, error_message = _apply_policy_fields(rule, org, request.POST)
        if ok:
            rule.save()
            ok, error_message = _apply_policy_source(rule, org, request.POST)
            if ok:
                messages.success(request, 'Policy created.')
                return redirect('security_groups_org:policy_list', slug=slug)
            rule.delete()

    prefill_source_group_ids = []
    prefill_source_node_id = None
    prefill_dest_group_id = None
    prefill_dest_node_id = None
    if request.method == 'GET':
        try:
            source_group_id = int(request.GET.get('source_group', '') or 0) or None
            if source_group_id and SecurityGroup.objects.filter(id=source_group_id, organization=org).exists():
                prefill_source_group_ids = [source_group_id]
        except ValueError:
            pass
        try:
            dest_group_id = int(request.GET.get('dest_group', '') or 0) or None
            if dest_group_id and SecurityGroup.objects.filter(id=dest_group_id, organization=org).exists():
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
        ok, error_message = _apply_policy_fields(rule, org, request.POST)
        if ok:
            rule.save()
            ok, error_message = _apply_policy_source(rule, org, request.POST)
            if ok:
                messages.success(request, 'Policy updated.')
                return redirect('security_groups_org:policy_list', slug=slug)

    selected_source_group_ids = list(rule.source_groups.values_list('id', flat=True))
    selected_source_node_id = rule.source_nodes.values_list('id', flat=True).first()
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
    security_group = get_object_or_404(SecurityGroup, id=sg_id, organization=org)
    
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
