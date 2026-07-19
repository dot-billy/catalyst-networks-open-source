from django.shortcuts import render, redirect, get_object_or_404
from rest_framework import viewsets, permissions, status
from rest_framework.decorators import action
from rest_framework.response import Response
from django.conf import settings
import subprocess
import os
import tempfile
import uuid
from rest_framework.exceptions import APIException
from .models import CertificateAuthority, CertificateAuthorityQRCode
# from .serializers import CertificateAuthoritySerializer, CertificateAuthorityCreateSerializer
from organizations.access import get_org_role, require_org_access
from organizations.permissions import IsOrganizationOwnerOrAdmin
from django.contrib.auth.decorators import login_required
from organizations.models import Organization
from django.contrib import messages
from django.core.files import File
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.utils import timezone
from datetime import timedelta
from django.http import HttpResponse, Http404, JsonResponse
from django.core.exceptions import PermissionDenied
from nodes.models import Node
from nodes.views import regenerate_certificate

class CertificateGenerationError(APIException):
    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    default_detail = 'Failed to generate certificate'
    default_code = 'certificate_generation_error'

# Web UI views
@login_required
def certificate_authority_list(request):
    """View for listing certificate authorities"""
    # Get organizations where the user is a member
    user_orgs = request.user.organizations.values_list('id', flat=True)
    
    # Get CAs in those organizations
    cas = CertificateAuthority.objects.filter(organization_id__in=user_orgs).order_by('-created_at')
    
    # Handle organization filter
    selected_org = request.GET.get('organization', None)
    if selected_org:
        cas = cas.filter(organization_id=selected_org)
        selected_org_name = Organization.objects.filter(id=selected_org).first().name if selected_org else None
    else:
        selected_org_name = None
    
    # Handle search
    search_query = request.GET.get('search', '')
    if search_query:
        cas = cas.filter(name__icontains=search_query)
    
    # Pagination
    paginator = Paginator(cas, 10)  # 10 CAs per page
    page = request.GET.get('page')
    
    try:
        certificate_authorities = paginator.page(page)
    except PageNotAnInteger:
        certificate_authorities = paginator.page(1)
    except EmptyPage:
        certificate_authorities = paginator.page(paginator.num_pages)
    
    # Get organizations for the filter dropdown
    organizations = request.user.organizations.all()
    
    context = {
        'certificate_authorities': certificate_authorities,
        'organizations': organizations,
        'selected_org': selected_org,
        'selected_org_name': selected_org_name,
        'search_query': search_query,
    }
    
    return render(request, 'certificates/list.html', context)

@login_required
def certificate_authority_create(request):
    """View for creating a new certificate authority"""
    if request.method == 'POST':
        name = request.POST.get('name')
        organization_id = request.POST.get('organization')
        common_name = request.POST.get('common_name')
        validity_days = int(request.POST.get('validity_days', 365))
        
        if not all([name, organization_id, common_name]):
            messages.error(request, 'Name, organization, and common name are required.')
            return redirect('certificates:create')
        
        # Verify organization access
        organization = get_object_or_404(Organization, id=organization_id)
        if not request.user.memberships.filter(
            organization=organization, 
            role__in=['owner', 'admin']
        ).exists():
            messages.error(request, 'You don\'t have permission to create a CA in this organization.')
            return redirect('certificates:list')
        
        # Create CA directory in dedicated cert storage
        ca_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'ca', str(organization_id))
        os.makedirs(ca_dir, exist_ok=True)
        
        # Generate CA certificate and key
        safe_name = name.lower().replace(" ", "_")
        unique_suffix = uuid.uuid4().hex[:8]
        cert_path = os.path.join(ca_dir, f'{safe_name}_ca_{unique_suffix}.crt')
        key_path = os.path.join(ca_dir, f'{safe_name}_ca_{unique_suffix}.key')
        
        try:
            # Convert validity_days to hours for nebula-cert
            validity_hours = validity_days * 24
            
            subprocess.run([
                'nebula-cert',
                'ca',
                '-name', name,
                '-out-crt', cert_path,
                '-out-key', key_path,
                '-duration', f'{validity_hours}h'
            ], check=True)
            
            # Create the CA instance
            with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
                ca = CertificateAuthority.objects.create(
                    name=name,
                    organization=organization,
                    created_by=request.user,
                    ca_cert=File(cert_file, name=os.path.basename(cert_path)),
                    ca_key=File(key_file, name=os.path.basename(key_path))
                )
            
            messages.success(request, f'Certificate Authority "{name}" created successfully.')
            return redirect('certificates:detail', pk=ca.id)
            
        except Exception as e:
            messages.error(request, f'Error creating certificate authority: {str(e)}')
    
    # Get organizations for which the user is an admin or owner
    # Use the direct relationship from User to Organization
    organizations = request.user.organizations.filter(
        memberships__user=request.user,
        memberships__role__in=['owner', 'admin']
    ).distinct()
    
    # Debug: Print organizations to check if any are found
    print(f"Found {organizations.count()} organizations for user {request.user.email}")
    for org in organizations:
        print(f"- {org.id}: {org.name}")
    
    context = {
        'organizations': organizations,
    }
    
    return render(request, 'certificates/create.html', context)

@login_required
def certificate_authority_detail(request, pk):
    """View for CA details"""
    ca = get_object_or_404(CertificateAuthority, id=pk)
    
    # Check permission
    if not request.user.memberships.filter(organization=ca.organization).exists():
        messages.error(request, "You don't have permission to view this certificate authority.")
        return redirect('certificates:list')
    
    # Get nodes using this CA
    nodes = ca.nodes.all().order_by('-created_at')
    
    # Add current time plus 30 days for certificate expiration checks
    current_time_plus_30_days = timezone.now() + timedelta(days=30)
    
    context = {
        'ca': ca,
        'nodes': nodes,
        'current_time_plus_30_days': current_time_plus_30_days,
    }
    
    return render(request, 'certificates/detail.html', context)

@login_required
def certificate_list(request):
    """List certificates that the user has access to."""
    return render(request, 'certificates/list.html')

@login_required
def certificate_create(request):
    """Create a new certificate authority."""
    return render(request, 'certificates/create.html')

@login_required
def certificate_detail(request, pk):
    """View certificate details."""
    return render(request, 'certificates/detail.html')

@login_required
def certificate_renew(request, pk):
    """Renew certificate."""
    # This would include actual renewal logic
    return redirect('certificates:detail', pk=pk)

# Helper function for organization access
def check_org_access(user, org_id, required_roles=None):
    """Helper function to check if user has access to an organization"""
    return require_org_access(user, org_id=org_id, required_roles=required_roles)

# Organization-specific views (placeholder implementations)
@login_required
def org_certificate_authority_list(request, slug):
    """List all certificate authorities for an organization."""
    org = require_org_access(request.user, slug=slug)
    
    cas = CertificateAuthority.objects.filter(organization=org)
    
    context = {
        'organization': org,
        'certificate_authorities': cas
    }
    
    return render(request, 'certificates/org_list.html', context)

@login_required
def org_certificate_authority_create(request, slug):
    """Create a new certificate authority for an organization."""
    org = require_org_access(request.user, slug=slug, required_roles=['owner', 'admin'])
    
    if request.method == 'POST':
        # Handle form submission
        name = request.POST.get('name')
        common_name = request.POST.get('common_name')
        validity_days = int(request.POST.get('validity_days', 365))
        
        if name and common_name:
            # Create CA directory in dedicated cert storage
            ca_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'ca', str(org.id))
            os.makedirs(ca_dir, exist_ok=True)
            
            # Generate CA certificate and key paths
            safe_name = name.lower().replace(' ', '_')
            unique_suffix = uuid.uuid4().hex[:8]
            cert_path = os.path.join(ca_dir, f'{safe_name}_ca_{unique_suffix}.crt')
            key_path = os.path.join(ca_dir, f'{safe_name}_ca_{unique_suffix}.key')
            ca_qr_path = os.path.join(ca_dir, f'{safe_name}_ca_qr_{unique_suffix}.png')
            nebula_qr_generated = False
            
            try:
                # Convert validity_days to hours for nebula-cert
                validity_hours = validity_days * 24
                create_cmd = [
                    'nebula-cert', 'ca',
                    '-name', name,
                    '-out-crt', cert_path,
                    '-out-key', key_path,
                    '-duration', f'{validity_hours}h',
                    '-out-qr', ca_qr_path,
                ]
                try:
                    subprocess.run(create_cmd, check=True, capture_output=True, text=True)
                    nebula_qr_generated = os.path.exists(ca_qr_path)
                except subprocess.CalledProcessError:
                    # Fallback for nebula-cert versions without -out-qr support.
                    fallback_cmd = []
                    skip_next = False
                    for part in create_cmd:
                        if skip_next:
                            skip_next = False
                            continue
                        if part == '-out-qr':
                            skip_next = True
                            continue
                        fallback_cmd.append(part)
                    subprocess.run(fallback_cmd, check=True)
                
                # Create the CA instance with generated files
                with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
                    ca = CertificateAuthority.objects.create(
                        name=name,
                        organization=org,
                        created_by=request.user,
                        ca_cert=File(cert_file, name=os.path.basename(cert_path)),
                        ca_key=File(key_file, name=os.path.basename(key_path))
                    )

                try:
                    if nebula_qr_generated and os.path.exists(ca_qr_path):
                        with open(ca_qr_path, 'rb') as qr_file:
                            CertificateAuthorityQRCode.create_or_update_for_ca_image(
                                ca,
                                qr_file.read(),
                                source='nebula_out_qr',
                            )
                    else:
                        CertificateAuthorityQRCode.create_or_update_for_ca(ca)
                except Exception as qr_error:
                    messages.warning(
                        request,
                        f'CA created, but failed to generate CA QR code automatically: {qr_error}'
                    )
                
                # Rotate old CAs: reassign nodes and delete old CA files
                old_cas = CertificateAuthority.objects.filter(organization=org).exclude(pk=ca.pk)
                for old_ca in old_cas:
                    # Reassign nodes to new CA and regenerate their certificates
                    nodes = Node.objects.filter(organization=org)
                    for node in nodes:
                        node.certificate_authority = ca
                        node.save()
                        regenerate_certificate(node)
                    # Remove old CA files and delete old CA record
                    if old_ca.ca_cert:
                        old_ca.ca_cert.delete(save=False)
                    if old_ca.ca_key:
                        old_ca.ca_key.delete(save=False)
                    old_ca.delete()
                
                messages.success(request, f'Certificate Authority "{name}" created and rotated successfully.')
                return redirect('certificates_org:detail', slug=org.slug, pk=ca.id)
            except Exception as e:
                messages.error(request, f'Error creating certificate authority: {e}')
        else:
            messages.error(request, 'Name and Common Name are required to create a CA.')
    
    context = {
        'organization': org
    }
    
    return render(request, 'certificates/org_create.html', context)

@login_required
def org_certificate_authority_detail(request, slug, pk):
    """View details of a certificate authority in an organization."""
    org = require_org_access(request.user, slug=slug)
    ca = get_object_or_404(CertificateAuthority, id=pk, organization=org)

    # Handle CA QR generation/regeneration from detail page.
    if request.GET.get('generate_qr') == '1' or request.GET.get('regenerate_qr') == '1':
        can_edit = get_org_role(request.user, org) in ['owner', 'admin']
        if not can_edit:
            messages.error(request, "You don't have permission to generate CA QR codes.")
            return redirect('certificates_org:detail', slug=slug, pk=pk)
        try:
            CertificateAuthorityQRCode.create_or_update_for_ca(ca)
            messages.success(request, f"CA QR code generated for {ca.name}.")
        except Exception as qr_error:
            messages.error(request, f"Failed to generate CA QR code: {qr_error}")
        return redirect('certificates_org:detail', slug=slug, pk=pk)
    
    # Parse expiration date from CA certificate
    ca_expiration = None
    try:
        result = subprocess.run([
            'nebula-cert', 'print',
            '-path', ca.ca_cert.path
        ], capture_output=True, text=True, check=True)
        for line in result.stdout.split('\n'):
            if 'Not After' in line:
                exp_str = line.split(': ', 1)[1].strip()
                parts = exp_str.split()
                if len(parts) >= 2:
                    date_part, time_part = parts[0], parts[1]
                    dt = timezone.datetime.strptime(f"{date_part} {time_part}", "%Y-%m-%d %H:%M:%S")
                    ca_expiration = dt.replace(tzinfo=timezone.utc)
                break
    except Exception:
        pass
    
    # Get nodes using this CA
    nodes = ca.nodes.all().order_by('-created_at')
    try:
        ca_qr = ca.qr_code
    except CertificateAuthorityQRCode.DoesNotExist:
        ca_qr = None
    
    # Add current time plus 30 days for certificate expiration checks
    current_time_plus_30_days = timezone.now() + timedelta(days=30)
    
    context = {
        'organization': org,
        'certificate_authority': ca,
        'nodes': nodes,
        'ca_qr': ca_qr,
        'current_time_plus_30_days': current_time_plus_30_days,
        'ca_expiration': ca_expiration,
    }
    
    return render(request, 'certificates/org_detail.html', context)

@login_required
def org_certificate_authority_renew(request, slug, pk):
    """Renew a certificate authority in an organization."""
    org = require_org_access(request.user, slug=slug, required_roles=['owner', 'admin'])
    
    ca = get_object_or_404(CertificateAuthority, id=pk, organization=org)
    
    # Placeholder for CA renewal logic
    
    return redirect('certificates_org:detail', slug=slug, pk=ca.id)

@login_required
def org_certificate_authority_revoke(request, slug, pk):
    """Revoke a certificate authority in an organization."""
    org = require_org_access(request.user, slug=slug, required_roles=['owner', 'admin'])
    
    ca = get_object_or_404(CertificateAuthority, id=pk, organization=org)
    
    # Placeholder for CA revocation logic
    
    return redirect('certificates_org:list', slug=slug)
