from urllib.parse import urlencode

from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from .models import Organization, Membership, NetworkRange, Invitation
from .forms import OrganizationForm, NetworkRangeForm, InvitationForm
import ipaddress
from django.db import transaction
from django.contrib.auth import get_user_model
from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme
from nodes.models import Node
from security_groups.models import SecurityGroup
from certificates.models import CertificateAuthority
from .emails import resend_invitation_email, send_invitation_email
from django.http import JsonResponse, HttpResponse
from .decorators import organization_member_required


def _safe_next_url(request, fallback_url):
    next_url = request.POST.get('next') or request.GET.get('next')
    if next_url and url_has_allowed_host_and_scheme(
        next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        return next_url
    return fallback_url


# Web views
@login_required
def organization_list(request):
    """List organizations that the user is a member of."""
    organizations = Organization.objects.filter(members=request.user)
    
    # Include role info with each organization
    for org in organizations:
        membership = org.memberships.get(user=request.user)
        org.role = membership.role
    
    return render(request, 'organizations/list.html', {'organizations': organizations})

@login_required
def organization_create(request):
    """Create a new organization and add the user as an owner."""
    if request.method == 'POST':
        # Get form data
        name = request.POST.get('name')
        description = request.POST.get('description', '')
        network_cidr = request.POST.get('network_cidr')
        ca_name = request.POST.get('ca_name')
        create_lighthouse = request.POST.get('create_lighthouse') == 'true'
        lighthouse_name = request.POST.get('lighthouse_name')
        
        # Validate essential data
        if not name:
            messages.error(request, 'Organization name is required')
            return redirect('organizations:create')
            
        try:
            # Step 1: Create the organization
            with transaction.atomic():
                organization = Organization(
                    name=name,
                    created_by=request.user
                )
                organization.save()
                
                # Add the current user as owner
                Membership.objects.create(
                    user=request.user,
                    organization=organization,
                    role='owner'
                )
                
                # Step 2: Create network range if provided
                if network_cidr:
                    try:
                        # Validate CIDR format
                        ipaddress.ip_network(network_cidr)
                        NetworkRange.objects.create(
                            organization=organization,
                            cidr=network_cidr,
                            description=f"Default network range for {organization.name}"
                        )
                    except ValueError:
                        messages.warning(request, f"Could not create network range with CIDR {network_cidr}. Invalid format.")
                
                # Step 3: Create Certificate Authority if needed
                if ca_name:
                    try:
                        # Import here to avoid circular imports
                        from certificates.models import CertificateAuthority
                        from django.conf import settings
                        import os
                        import subprocess
                        from django.core.files import File
                        
                        # Create CA directory in dedicated cert storage
                        ca_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'ca', str(organization.id))
                        os.makedirs(ca_dir, exist_ok=True)
                        
                        # Generate CA certificate and key
                        safe_name = ca_name.lower().replace(" ", "_")
                        cert_path = os.path.join(ca_dir, f'{safe_name}_ca.crt')
                        key_path = os.path.join(ca_dir, f'{safe_name}_ca.key')
                        
                        # Generate CA with nebula-cert
                        subprocess.run([
                            'nebula-cert', 'ca',
                            '-name', ca_name,
                            '-out-crt', cert_path,
                            '-out-key', key_path,
                            '-duration', '8760h'  # 1 year
                        ], check=True)
                        
                        # Create the CA instance
                        with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
                            ca = CertificateAuthority.objects.create(
                                name=ca_name,
                                organization=organization,
                                created_by=request.user,
                                ca_cert=File(cert_file, name=os.path.basename(cert_path)),
                                ca_key=File(key_file, name=os.path.basename(key_path))
                            )
                            
                        # Step 4: Create lighthouse node if requested
                        if create_lighthouse and lighthouse_name and ca:
                            from nodes.views import generate_node_cert
                            
                            lighthouse_node = Node.objects.create(
                                name=lighthouse_name,
                                organization=organization,
                                created_by=request.user,
                                certificate_authority=ca,
                                is_lighthouse=True,
                                nebula_ip=f"{network_cidr.split('/')[0].rsplit('.', 1)[0]}.1"  # Use .1 in the network
                            )
                            
                            # Generate certificate for the lighthouse node
                            generate_node_cert(lighthouse_node)
                            
                    except Exception as e:
                        messages.warning(request, f"Could not create Certificate Authority: {str(e)}")
            
            messages.success(request, f'Organization "{name}" created successfully!')
            return redirect('organizations:detail', slug=organization.slug)
        
        except Exception as e:
            messages.error(request, f'Error creating organization: {str(e)}')
            return redirect('organizations:create')
            
    return render(request, 'organizations/create.html')

@login_required
def organization_detail(request, slug):
    """View an organization's details."""
    organization = get_object_or_404(Organization, slug=slug)
    if not organization.members.filter(id=request.user.id).exists():
        messages.error(request, 'You do not have permission to view this organization.')
        return redirect('organizations:list')
    
    membership = organization.memberships.get(user=request.user)
    organization.role = membership.role
    organization.lighthouse_nodes = organization.nodes.filter(is_lighthouse=True)

    # Setup steps
    has_ca = CertificateAuthority.objects.filter(organization=organization).exists()
    has_network_range = NetworkRange.objects.filter(organization=organization).exists()
    has_node = Node.objects.filter(organization=organization).exists()
    setup_steps_completed = sum([has_ca, has_network_range, has_node])
    setup_steps_total = 3
    setup_steps_percent = int((setup_steps_completed / setup_steps_total) * 100) if setup_steps_total > 0 else 0

    return render(request, 'organizations/detail.html', {
        'organization': organization,
        'has_ca': has_ca,
        'has_network_range': has_network_range,
        'has_node': has_node,
        'setup_steps_completed': setup_steps_completed,
        'setup_steps_total': setup_steps_total,
        'setup_steps_percent': setup_steps_percent,
    })

def get_members_table_context(organization, user):
    """
    Helper to build the context for the members table and invitations.
    """
    user_membership = organization.memberships.get(user=user)
    
    # Add the user's role to the organization object
    organization.role = user_membership.role
    
    memberships = organization.memberships.select_related('user').order_by('user__email')
    now = timezone.now()
    pending_invitations = organization.invitations.filter(
        status='pending',
        expires_at__gt=now
    ).order_by('-created_at')
    expired_invitations = organization.invitations.filter(
        status='pending',
        expires_at__lte=now
    ).order_by('-expires_at')
    context = {
        'organization': organization,
        'user_membership': user_membership,
        'memberships': memberships,
        'pending_invitations': pending_invitations,
        'expired_invitations': expired_invitations,
    }
    return context

@login_required
@organization_member_required
def organization_members(request, slug):
    """
    Display organization members and invitations.
    Only organization members can view this page.
    """
    organization = get_object_or_404(Organization, slug=slug)
    context = get_members_table_context(organization, request.user)
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        return render(request, 'organizations/_members_table.html', context)
    return render(request, 'organizations/members.html', context)

@login_required
def delete_organization(request, slug):
    """Delete an organization."""
    organization = get_object_or_404(Organization, slug=slug)
    if not organization.members.filter(id=request.user.id).exists():
        messages.error(request, 'You do not have permission to delete this organization.')
        return redirect('organizations:list')
    
    # Check if user is owner
    membership = organization.memberships.get(user=request.user)
    if membership.role != 'owner':
        messages.error(request, "Only organization owners can delete an organization.")
        return redirect('organizations:detail', slug=organization.slug)
    
    if request.method == 'POST':
        # Store the name for the success message
        org_name = organization.name
        
        try:
            # Delete the organization and all related objects through cascade
            organization.delete()
            messages.success(request, f'Organization "{org_name}" has been deleted successfully.')
            return redirect('organizations:list')
        except Exception as e:
            messages.error(request, f'Error deleting organization: {str(e)}')
    
    return redirect('organizations:detail', slug=slug)

@login_required
def network_range_view(request, slug):
    """Manage network ranges for an organization."""
    organization = get_object_or_404(Organization, slug=slug)
    if not organization.members.filter(id=request.user.id).exists():
        messages.error(request, 'You do not have permission to view this organization.')
        return redirect('organizations:list')
    
    # Check if user is owner or admin
    membership = organization.memberships.get(user=request.user)
    if membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to manage network ranges for this organization.")
        return redirect('organizations:detail', slug=organization.slug)
    
    # Include role with the organization
    organization.role = membership.role
    
    if request.method == 'POST':
        form = NetworkRangeForm(request.POST)
        if form.is_valid():
            network_range = form.save(commit=False)
            network_range.organization = organization
            network_range.save()
            messages.success(request, 'Network range added successfully.')
            return redirect('organizations:detail', slug=organization.slug)
    else:
        form = NetworkRangeForm()
    
    return render(request, 'organizations/network_range.html', {
        'organization': organization,
        'form': form,
        'network_ranges': organization.network_ranges.all()
    })

@login_required
def delete_network_range(request, slug):
    """Delete a network range from an organization."""
    organization = get_object_or_404(Organization, slug=slug)
    if not organization.members.filter(id=request.user.id).exists():
        messages.error(request, 'You do not have permission to modify this organization.')
        return redirect('organizations:list')
    
    # Check if user is owner or admin
    membership = organization.memberships.get(user=request.user)
    if membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to delete network ranges for this organization.")
        return redirect('organizations:detail', slug=organization.slug)
    
    if request.method == 'POST':
        range_id = request.POST.get('range_id')
        if range_id:
            try:
                network_range = NetworkRange.objects.get(id=range_id, organization=organization)
                
                # Check if any nodes are using this range
                nodes_count = 0
                cidr_prefix = network_range.cidr.split('/')[0]
                for node in organization.nodes.all():
                    if node.nebula_ip and node.nebula_ip.startswith(cidr_prefix):
                        nodes_count += 1
                
                if nodes_count > 0:
                    messages.warning(request, f"Cannot delete network range {network_range.cidr} because {nodes_count} nodes are using it. Reassign those nodes first.")
                else:
                    cidr = network_range.cidr
                    network_range.delete()
                    messages.success(request, f"Network range {cidr} deleted successfully.")
            except NetworkRange.DoesNotExist:
                messages.error(request, "Network range not found.")
    
    return redirect('organizations:network_range', slug=organization.slug)

@login_required
def organization_activity(request, slug):
    organization = get_object_or_404(Organization, slug=slug)
    # Optionally, check user permissions here

    activities = []

    # Node activity
    for history in Node.history.filter(organization=organization).order_by('-history_date')[:10]:
        if history.history_type == '+':
            activities.append({
                'type': 'node_created',
                'message': f'Node "{history.name}" was created.',
                'timestamp': history.history_date
            })
        elif history.history_type == '~':
            activities.append({
                'type': 'node_updated',
                'message': f'Node "{history.name}" was updated.',
                'timestamp': history.history_date
            })

    # Security group activity
    for history in SecurityGroup.history.filter(organization=organization).order_by('-history_date')[:10]:
        if history.history_type == '+':
            activities.append({
                'type': 'security_group_created',
                'message': f'Security group "{history.name}" was created.',
                'timestamp': history.history_date
            })
        elif history.history_type == '~':
            activities.append({
                'type': 'security_group_updated',
                'message': f'Security group "{history.name}" was updated.',
                'timestamp': history.history_date
            })

    # Sort and limit
    activities.sort(key=lambda x: x['timestamp'], reverse=True)
    activities = activities[:10]

    return render(request, 'dashboard/recent_activity.html', {'activities': activities})

@login_required
def invitation_list(request, slug):
    """List and manage invitations for an organization."""
    organization = get_object_or_404(Organization, slug=slug)
    membership = get_object_or_404(
        Membership,
        organization=organization,
        user=request.user,
        role__in=['owner', 'admin']
    )
    
    invitations = organization.invitations.all().order_by('-created_at')
    
    # Update expired status
    now = timezone.now()
    for invitation in invitations:
        if invitation.status == 'pending' and invitation.is_expired:
            invitation.status = 'expired'
            invitation.save()
    
    return render(request, 'organizations/invitation_list.html', {
        'organization': organization,
        'invitations': invitations,
        'membership': membership
    })

@login_required
@organization_member_required
def invitation_create(request, slug):
    """
    Create a new invitation for the organization.
    Only organization admins can perform this action.
    """
    organization = get_object_or_404(Organization, slug=slug)
    user_membership = organization.memberships.get(user=request.user)
    
    # Only admins can create invitations
    if user_membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to create invitations.")
        if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
            context = get_members_table_context(organization, request.user)
            return render(request, 'organizations/_members_table.html', context)
        return redirect('organizations:members', slug=slug)
    
    if request.method == 'POST':
        email = request.POST.get('email')
        role = request.POST.get('role', 'member')
        
        # Validate email
        if not email:
            messages.error(request, "Email address is required.")
        else:
            # Check if user is already a member
            if organization.memberships.filter(user__email=email).exists():
                messages.error(request, f"{email} is already a member of this organization.")
            else:
                # Check if there's already a pending invitation
                existing_invitation = organization.invitations.filter(
                    email=email,
                    status='pending',
                    expires_at__gt=timezone.now()
                ).first()
                
                if existing_invitation:
                    messages.error(request, f"There's already a pending invitation for {email}.")
                else:
                    # Create invitation first
                    try:
                        invitation = Invitation.objects.create(
                            organization=organization,
                            email=email,
                            inviter=request.user,
                            role=role
                        )
                        
                        # Then try to send the email
                        try:
                            send_invitation_email(invitation)
                            messages.success(request, f"Invitation sent to {email}. They will receive an email with instructions to join.")
                        except Exception as email_error:
                            # If email fails, still keep the invitation but warn user
                            messages.warning(
                                request, 
                                f"Invitation created for {email}, but the email couldn't be delivered. "
                                f"You may need to contact them directly. Error: {str(email_error)}"
                            )
                    except Exception as e:
                        messages.error(request, f"Error creating invitation: {str(e)}")
    
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        context = get_members_table_context(organization, request.user)
        return render(request, 'organizations/_members_table.html', context)
    
    return redirect('organizations:members', slug=slug)

def invitation_accept(request, token):
    """Handle invitation acceptance."""
    invitation = get_object_or_404(Invitation, token=token)

    if not request.user.is_authenticated:
        if not invitation.is_valid:
            messages.error(request, 'This invitation is no longer valid.')
            return redirect('login')

        invited_user_exists = get_user_model().objects.filter(
            email__iexact=invitation.email
        ).exists()
        if invited_user_exists:
            accept_path = reverse(
                'organizations:invitation_accept',
                kwargs={'token': invitation.token},
            )
            return redirect(f"{reverse('login')}?{urlencode({'next': accept_path})}")

        return redirect(f"{reverse('register')}?{urlencode({'invitation': invitation.token})}")

    if request.user.email.lower() != invitation.email.lower():
        messages.error(request, 'This invitation was sent to a different email address.')
        return redirect('organizations:list')

    # Recovery path: invitation was marked accepted, but membership was never created.
    if invitation.status == 'accepted':
        membership = Membership.objects.filter(
            organization=invitation.organization,
            user=request.user
        ).first()
        if membership:
            messages.info(request, f'You are already a member of {invitation.organization.name}.')
            return redirect('organizations:detail', slug=invitation.organization.slug)

        membership = Membership.objects.create(
            organization=invitation.organization,
            user=request.user,
            role=invitation.role
        )
        if not invitation.accepted_at:
            invitation.accepted_at = timezone.now()
            invitation.save(update_fields=['accepted_at'])
        messages.success(
            request,
            f'Welcome to {invitation.organization.name}! Your membership was repaired as {membership.role}.'
        )
        return redirect('organizations:detail', slug=invitation.organization.slug)

    if not invitation.is_valid:
        messages.error(request, 'This invitation is no longer valid.')
        return redirect('organizations:list')

    membership = invitation.accept(request.user)
    if membership:
        messages.success(
            request,
            f'Welcome to {invitation.organization.name}! You have been added as a {membership.role}.'
        )
        return redirect('organizations:detail', slug=invitation.organization.slug)
    
    messages.error(request, 'Failed to accept invitation.')
    return redirect('organizations:list')

@login_required
@organization_member_required
def change_member_role(request, slug, membership_id):
    organization = get_object_or_404(Organization, slug=slug)
    user_membership = organization.memberships.get(user=request.user)
    if user_membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to change member roles.")
        if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
            context = get_members_table_context(organization, request.user)
            return render(request, 'organizations/_members_table.html', context)
        return redirect('organizations:members', slug=slug)
    if request.method == 'POST':
        membership = get_object_or_404(Membership, id=membership_id, organization=organization)
        if membership.user == request.user:
            messages.warning(request, "You cannot change your own role.")
        else:
            new_role = request.POST.get('role')
            if new_role in ['owner', 'admin', 'member']:
                membership.role = new_role
                membership.save()
                messages.success(request, f"Role for {membership.user.email} updated to {new_role}.")
            else:
                messages.error(request, "Invalid role selected.")
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        context = get_members_table_context(organization, request.user)
        return render(request, 'organizations/_members_table.html', context)
    return redirect('organizations:members', slug=slug)

@login_required
@organization_member_required
def remove_member(request, slug, membership_id):
    organization = get_object_or_404(Organization, slug=slug)
    user_membership = organization.memberships.get(user=request.user)
    if user_membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to remove members.")
        if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
            context = get_members_table_context(organization, request.user)
            return render(request, 'organizations/_members_table.html', context)
        return redirect('organizations:members', slug=slug)
    if request.method == 'POST':
        membership = get_object_or_404(Membership, id=membership_id, organization=organization)
        if membership.user == request.user:
            messages.warning(request, "You cannot remove yourself from the organization.")
        else:
            membership.delete()
            messages.success(request, f"{membership.user.email} has been removed from the organization.")
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        context = get_members_table_context(organization, request.user)
        return render(request, 'organizations/_members_table.html', context)
    return redirect('organizations:members', slug=slug)

@login_required
@organization_member_required
def resend_invitation(request, slug, invitation_id):
    """
    Resend an invitation email.
    Only organization admins can perform this action.
    """
    if request.method != 'POST':
        return redirect('organizations:members', slug=slug)
    
    organization = get_object_or_404(Organization, slug=slug)
    redirect_url = _safe_next_url(
        request,
        reverse('organizations:members', kwargs={'slug': slug}),
    )
    user_membership = organization.memberships.get(user=request.user)
    
    # Only admins can resend invitations
    if user_membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to resend invitations.")
        if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
            context = get_members_table_context(organization, request.user)
            return render(request, 'organizations/_members_table.html', context)
        return redirect(redirect_url)
    
    invitation = get_object_or_404(
        Invitation,
        id=invitation_id,
        organization=organization,
        status='pending'
    )
    
    # Update expiration and resend
    try:
        resend_invitation_email(invitation)
        messages.success(request, f"Invitation resent to {invitation.email}.")
    except Exception as e:
        messages.error(request, f"Error resending invitation: {str(e)}")
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        context = get_members_table_context(organization, request.user)
        return render(request, 'organizations/_members_table.html', context)
    return redirect(redirect_url)

@login_required
@organization_member_required
def revoke_invitation(request, slug, invitation_id):
    """
    Revoke a pending invitation.
    Only organization admins can perform this action.
    """
    if request.method != 'POST':
        return redirect('organizations:members', slug=slug)
    
    organization = get_object_or_404(Organization, slug=slug)
    user_membership = organization.memberships.get(user=request.user)
    
    # Only admins can revoke invitations
    if user_membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to revoke invitations.")
        if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
            context = get_members_table_context(organization, request.user)
            return render(request, 'organizations/_members_table.html', context)
        return redirect('organizations:members', slug=slug)
    
    invitation = get_object_or_404(
        Invitation,
        id=invitation_id,
        organization=organization,
        status='pending'
    )
    
    try:
        invitation.status = 'revoked'
        invitation.revoked_at = timezone.now()
        invitation.save()
        messages.success(request, f"Invitation to {invitation.email} has been revoked.")
    except Exception as e:
        messages.error(request, f"Error revoking invitation: {str(e)}")
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        context = get_members_table_context(organization, request.user)
        return render(request, 'organizations/_members_table.html', context)
    return redirect('organizations:members', slug=slug)

@login_required
@organization_member_required
def add_member(request, slug):
    organization = get_object_or_404(Organization, slug=slug)

    user_membership = organization.memberships.get(user=request.user)
    if user_membership.role not in ['owner', 'admin']:
        messages.error(request, "You don't have permission to add members.")
        if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
            context = get_members_table_context(organization, request.user)
            return render(request, 'organizations/_members_table.html', context)
        return redirect('organizations:members', slug=slug)
    if request.method == 'POST':
        email = request.POST.get('email', '').strip().lower()
        role = request.POST.get('role', 'member')
        allowed_roles = {'owner', 'admin', 'member'}
        if role not in allowed_roles:
            role = 'member'
        if not email:
            messages.error(request, "Email is required.")
        else:
            user = get_user_model().objects.filter(email=email).first()
            if not user:
                # If account doesn't exist yet, fall back to invitation flow.
                existing_invitation = organization.invitations.filter(
                    email=email,
                    status='pending',
                    expires_at__gt=timezone.now()
                ).first()
                if existing_invitation:
                    messages.warning(request, f"There is already a pending invitation for {email}.")
                else:
                    try:
                        invitation = Invitation.objects.create(
                            organization=organization,
                            email=email,
                            inviter=request.user,
                            role=role
                        )
                        try:
                            send_invitation_email(invitation)
                            messages.success(request, f"{email} does not have an account yet. Invitation sent.")
                        except Exception as email_error:
                            messages.warning(
                                request,
                                f"{email} does not have an account yet. Invitation created, but email delivery failed: {str(email_error)}"
                            )
                    except Exception as create_error:
                        messages.error(request, f"Could not create invitation for {email}: {str(create_error)}")
            elif organization.memberships.filter(user=user).exists():
                messages.warning(request, f"{email} is already a member.")
            else:
                Membership.objects.create(organization=organization, user=user, role=role)
                messages.success(request, f"{email} added as {role}.")
    if request.headers.get("HX-Request") == "true" or request.GET.get("partial") == "1":
        context = get_members_table_context(organization, request.user)
        return render(request, 'organizations/_members_table.html', context)
    return redirect('organizations:members', slug=slug)
