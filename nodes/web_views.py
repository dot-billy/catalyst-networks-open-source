import csv
import io
import os
import subprocess
import tempfile
import traceback
import zipfile
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.core.files import File
from django.core.paginator import Paginator
from django.db import models, transaction
from django.http import FileResponse, HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_http_methods

from certificates.models import CertificateAuthority
from organizations.access import require_org_access
from organizations.models import Organization
from security_groups.models import Tag

from notifications import dispatch as notification_dispatch

from .api_registration import NodeRegistrationView
from .effective_rules import effective_rules
from .models import Node, NodeQRCode, NodeRegistrationToken
from .services import _get_latest_org_ca

def node_list(request):
    """List nodes that the user has access to."""
    return render(request, 'nodes/list.html')

@login_required
def node_create(request):
    """Create a new node."""
    return render(request, 'nodes/create.html')

@login_required
def node_detail(request, pk):
    """View node details."""
    return render(request, 'nodes/detail.html')

# Helper function for organization access
def check_org_access(user, org_id=None, required_roles=None, organization_slug=None):
    """Helper function to check if user has access to an organization"""
    return require_org_access(
        user,
        org_id=org_id,
        slug=organization_slug,
        required_roles=required_roles,
    )


def _get_visible_org_node(request, org, pk):
    node = get_object_or_404(Node, id=pk, organization=org)
    membership_role = request.user.memberships.filter(
        organization=org
    ).values_list('role', flat=True).first()
    can_edit = membership_role in ['owner', 'admin']

    if not can_edit and node.assigned_user_id != request.user.id and node.created_by_id != request.user.id:
        raise PermissionDenied("You don't have access to this mobile node.")

    return node, can_edit

# Organization-specific views (placeholder implementations)
@login_required
def org_node_list(request, slug):
    """List all nodes for an organization, with search and pagination, HTMX support."""
    org = check_org_access(request.user, organization_slug=slug)
    membership_role = request.user.memberships.filter(
        organization=org
    ).values_list('role', flat=True).first()
    can_manage_nodes = membership_role in ['owner', 'admin']

    nodes = Node.objects.filter(organization=org)
    if not can_manage_nodes:
        # Members should only see endpoints associated with them.
        nodes = nodes.filter(
            models.Q(assigned_user=request.user) |
            models.Q(created_by=request.user)
        )

    # Search filter
    search_query = request.GET.get('search', '').strip()
    if search_query:
        nodes = nodes.filter(
            models.Q(name__icontains=search_query) |
            models.Q(nebula_ip__icontains=search_query)
        )

    # Pagination
    page_number = request.GET.get('page', 1)
    paginator = Paginator(nodes.order_by('-created_at'), 10)
    page_obj = paginator.get_page(page_number)

    # Calculate current time and future dates for expiration warnings
    from datetime import datetime, timedelta
    now = datetime.now()
    now_plus_30_days = now + timedelta(days=30)

    context = {
        'organization': org,
        'nodes': page_obj,
        'search_query': search_query,
        'current_time': now,
        'current_time_plus_30_days': now_plus_30_days,
        'can_manage_nodes': can_manage_nodes,
    }

    if request.headers.get('HX-Request'):
        return render(request, 'nodes/_org_node_table.html', context)
    else:
        return render(request, 'nodes/org_list.html', context)

@login_required
def org_node_create_mobile(request, slug):
    """Create a new mobile node for an organization with mobile-specific defaults."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    latest_ca = _get_latest_org_ca(org)
    assignable_memberships = org.memberships.select_related('user').order_by('user__email')

    if request.method == 'POST':
        # Handle form submission with mobile-specific defaults
        name = request.POST.get('name', '').strip()
        assigned_user_id = request.POST.get('assigned_user')
        cert_expiration_str = request.POST.get('key_expiration')

        if not latest_ca:
            messages.error(request, "No certificate authority exists for this organization.")
            return redirect('certificates_org:create', slug=org.slug)

        if not name:
            messages.error(request, "Please provide a node name.")
            context = {
                'organization': org,
                'latest_ca': latest_ca,
                'assignable_memberships': assignable_memberships,
                'form_data': request.POST,
            }
            return render(request, 'nodes/org_create_mobile.html', context)

        if not assigned_user_id:
            messages.error(request, "Please select the user this mobile node belongs to.")
            context = {
                'organization': org,
                'latest_ca': latest_ca,
                'assignable_memberships': assignable_memberships,
                'form_data': request.POST,
            }
            return render(request, 'nodes/org_create_mobile.html', context)

        assigned_membership = org.memberships.filter(user_id=assigned_user_id).select_related('user').first()
        if not assigned_membership:
            messages.error(request, "Selected user is not a member of this organization.")
            context = {
                'organization': org,
                'latest_ca': latest_ca,
                'assignable_memberships': assignable_memberships,
                'form_data': request.POST,
            }
            return render(request, 'nodes/org_create_mobile.html', context)

        # Parse certificate expiration date
        cert_expiration = None
        if cert_expiration_str:
            try:
                from datetime import datetime
                cert_expiration = datetime.strptime(cert_expiration_str, '%Y-%m-%d').date()
            except ValueError:
                messages.error(request, "Invalid certificate expiration date format.")
                context = {
                    'organization': org,
                    'latest_ca': latest_ca,
                    'assignable_memberships': assignable_memberships,
                    'form_data': request.POST,
                }
                return render(request, 'nodes/org_create_mobile.html', context)
        # Create the mobile node with automatic IP assignment and mobile-specific settings
        node = Node.objects.create(
            name=name,
            organization=org,
            certificate_authority=latest_ca,
            is_lighthouse=False,  # Mobile nodes are never lighthouses
            public_ip=None,  # Mobile nodes don't need public IP
            fqdn=None,  # Mobile nodes don't need FQDN
            external_port=4242,  # Standard port for mobile nodes
            created_by=request.user,
            assigned_user=assigned_membership.user,
        )

        # Set certificate expiration if provided
        if cert_expiration:
            from datetime import datetime
            node.cert_expiration = timezone.make_aware(datetime.combine(cert_expiration, datetime.min.time()))
            node.save()

        # Generate the certificate
        cert_success = regenerate_certificate(node)
        qr_success = cert_success and NodeQRCode.objects.filter(node=node).exists()

        if cert_success:
            notification_dispatch.queue_node_lifecycle_events(
                node,
                ['node.created', 'cert.issued', 'ip.allocated'],
            )

        # Build success message
        if cert_success and qr_success:
            messages.success(
                request,
                f"Mobile node {node.name} created and assigned to {assigned_membership.user.email}."
            )
        elif cert_success and not qr_success:
            messages.warning(
                request,
                f"Mobile node {node.name} created for {assigned_membership.user.email}, but QR generation failed."
            )
        else:
            messages.error(request, "Mobile node created, but certificate generation failed.")

        return redirect('nodes_org:detail', slug=slug, pk=node.id)

    context = {
        'organization': org,
        'latest_ca': latest_ca,
        'assignable_memberships': assignable_memberships,
        'form_data': {},
    }

    return render(request, 'nodes/org_create_mobile.html', context)


@login_required
def org_node_create(request, slug):
    """Legacy create endpoint now redirects to mobile-only creation."""
    check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    messages.info(request, "Standalone node creation is disabled. Create a mobile node instead.")
    return redirect('nodes_org:create_mobile', slug=slug)

@login_required
def org_node_detail(request, slug, pk):
    """View details of a node in an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    node, can_edit = _get_visible_org_node(request, org, pk)

    # Handle QR code generation/regeneration
    if request.GET.get('generate_qr') == '1' or request.GET.get('regenerate_qr') == '1':
        if not can_edit:
            messages.error(request, "You don't have permission to generate QR codes for this node.")
            return redirect('nodes_org:detail', slug=slug, pk=node.id)
        if node.is_lighthouse:
            messages.error(request, "QR enrollment is only available for mobile endpoints.")
            return redirect('nodes_org:detail', slug=slug, pk=node.id)

        # Deactivate existing QR code if regenerating
        if request.GET.get('regenerate_qr') == '1':
            try:
                existing_qr = node.qr_code
                existing_qr.deactivate()
                messages.info(request, "Previous QR code deactivated.")
            except NodeQRCode.DoesNotExist:
                pass

        # Generate new QR code via nebula-cert-backed certificate regeneration
        try:
            if regenerate_certificate(node):
                messages.success(request, f"QR code generated successfully for node {node.name}.")
            else:
                messages.error(request, "Failed to generate QR code. Please try again.")
        except Exception as e:
            logger.error(f"Failed to generate QR code for node {node.name}: {str(e)}")
            messages.error(request, "Failed to generate QR code. Please try again.")

        return redirect('nodes_org:detail', slug=slug, pk=node.id)

    # Get the count of lighthouse nodes in this organization
    lighthouse_count = Node.objects.filter(organization=org, is_lighthouse=True).count()

    # Calculate expiration warning dates
    from datetime import datetime, timedelta
    now = datetime.now()
    now_plus_30_days = now + timedelta(days=30)
    now_plus_90_days = now + timedelta(days=90)
    try:
        ca_qr = node.certificate_authority.qr_code
    except Exception:
        ca_qr = None

    context = {
        'organization': org,
        'node': node,
        'ca_qr': ca_qr,
        'lighthouse_count': lighthouse_count,
        'can_edit': can_edit,
        'can_sign_mobile': (can_edit or node.assigned_user_id == request.user.id or node.created_by_id == request.user.id),
        'now_plus_30_days': now_plus_30_days,
        'now_plus_90_days': now_plus_90_days
    }

    return render(request, 'nodes/org_detail.html', context)

@login_required
def org_node_edit(request, slug, pk):
    """Edit a node in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    node = get_object_or_404(Node, id=pk, organization=org)
    
    if request.method == 'POST':
        # Handle form submission
        name = request.POST.get('name')
        original_name = node.name
        original_is_lighthouse = node.is_lighthouse
        original_public_ip = node.public_ip
        original_fqdn = node.fqdn
        original_external_port = node.external_port
        
        is_lighthouse = request.POST.get('is_lighthouse') == 'on'
        
        # Get shared network settings and lighthouse-specific fields.
        public_ip = None
        fqdn = None
        external_port = node.external_port or 4242
        external_port_str = request.POST.get('external_port', '').strip()
        if external_port_str:
            try:
                external_port = int(external_port_str)
                if external_port < 1 or external_port > 65535:
                    raise ValueError
            except ValueError:
                messages.error(request, "External port must be a number between 1 and 65535.")
                return render(request, 'nodes/org_edit.html', {
                    'organization': org,
                    'node': node,
                })
        
        if is_lighthouse:
            public_ip = request.POST.get('public_ip')
            fqdn = request.POST.get('fqdn')
            
            # Validate that lighthouse nodes have either public_ip or fqdn
            if not public_ip and not fqdn:
                messages.error(request, "Lighthouse nodes must have either a Public IP Address or an FQDN.")
                context = {
                    'organization': org,
                    'node': node
                }
                return render(request, 'nodes/org_edit.html', context)
        
        if name:
            # Check if any certificate-impacting settings have changed
            name_changed = original_name != name
            fqdn_changed = node.fqdn != fqdn
            
            # For lighthouse nodes, we care about public IP and lighthouse status changes
            lighthouse_related_changes = (
                original_is_lighthouse != is_lighthouse or 
                (is_lighthouse and original_public_ip != public_ip)
            )
            external_port_changed = (original_external_port or 4242) != external_port
            
            # Determine if certificate regeneration is needed
            needs_cert_regeneration = name_changed or fqdn_changed or lighthouse_related_changes or external_port_changed
            
            # Update node properties
            node.name = name
            node.is_lighthouse = is_lighthouse
            
            if is_lighthouse:
                node.public_ip = public_ip
                node.fqdn = fqdn
            else:
                # Clear lighthouse-specific fields if it's not a lighthouse
                node.public_ip = None
                node.fqdn = None
            node.external_port = external_port
                
            node.save()
            
            # If configuration changed that impacts certificates, regenerate them
            if needs_cert_regeneration:
                regenerate_certificate(node)
                messages.success(request, f"Node updated and certificate regenerated for {node.name}.")
            else:
                messages.success(request, f"Node {node.name} updated successfully.")
            
            return redirect('nodes_org:detail', slug=slug, pk=node.id)
    
    context = {
        'organization': org,
        'node': node
    }
    
    return render(request, 'nodes/org_edit.html', context)

def regenerate_certificate(node):
    """
    Regenerate certificate for a node. Used when node properties that affect the certificate change.
    """
    # Get the necessary parameters for certificate generation
    ca = node.certificate_authority
    name = node.name
    ip = node.nebula_ip
    
    # Create cert directory if it doesn't exist (dedicated cert storage)
    cert_dir = os.path.join(settings.CERT_STORAGE_ROOT, 'certs', f'org-{node.organization.id}')
    os.makedirs(cert_dir, exist_ok=True)
    
    # Generate new certificate file paths (use a UTC datetime to ensure uniqueness)
    timestamp_str = timezone.now().strftime("%Y%m%dT%H%M%SZ")
    cert_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.crt')
    key_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.key')
    qr_path = os.path.join(cert_dir, f'{name}-{timestamp_str}.png')
    nebula_qr_generated = False
    
    try:
        # Generate new certificate using nebula-cert with just the essential parameters
        cmd = [
            'nebula-cert', 'sign',
            '-name', name,
            '-ip', f'{ip}/24',
            '-ca-crt', ca.ca_cert.path,
            '-ca-key', ca.ca_key.path,
            '-out-crt', cert_path,
            '-out-key', key_path
        ]
        if not node.is_lighthouse:
            cmd.extend(['-out-qr', qr_path])
        
        # Include Nebula groups from org security groups and lighthouse role
        group_names = []
        if node.is_lighthouse:
            group_names.append('lighthouse')
        group_names.extend(list(node.tags.values_list('name', flat=True)))
        if group_names:
            cmd.extend(['-groups', ','.join(group_names)])
        
        # REMOVED: We don't add public IP as subnets anymore, it's not essential for certificate
        
        print(f"Generating certificate with command: {' '.join(cmd)}")
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True)
            nebula_qr_generated = (not node.is_lighthouse) and os.path.exists(qr_path)
        except subprocess.CalledProcessError:
            if not node.is_lighthouse and '-out-qr' in cmd:
                # Compatibility fallback for nebula-cert versions without -out-qr.
                fallback_cmd = []
                skip_next = False
                for part in cmd:
                    if skip_next:
                        skip_next = False
                        continue
                    if part == '-out-qr':
                        skip_next = True
                        continue
                    fallback_cmd.append(part)
                print("nebula-cert -out-qr not supported; falling back to internal QR generation.")
                subprocess.run(fallback_cmd, check=True)
                nebula_qr_generated = False
            else:
                raise
        
        # Save the files to the node
        with open(cert_path, 'rb') as cert_file, open(key_path, 'rb') as key_file:
            # Keep track of old paths to clean up
            old_cert_path = node.cert_path.path if node.cert_path else None
            old_key_path = node.key_path.path if node.key_path else None
            
            # Update node with new certificate files
            node.cert_path.save(f'{name}-{timestamp_str}.crt', File(cert_file), save=False)
            node.key_path.save(f'{name}-{timestamp_str}.key', File(key_file), save=False)
        
        # Get certificate expiration
        result = subprocess.run([
            'nebula-cert', 'print',
            '-path', cert_path
        ], capture_output=True, text=True, check=True)
        
        # Parse expiration from output
        for line in result.stdout.split('\n'):
            if 'Not After' in line:
                exp_str = line.split(': ')[1].strip()
                # Convert the date format to Django-compatible format
                try:
                    # Parse the date format: "2025-05-03 11:54:04 +0000 UTC"
                    # Convert to YYYY-MM-DD HH:MM:SS format
                    exp_parts = exp_str.split()
                    if len(exp_parts) >= 3:
                        # Extract date and time, ignore timezone for now
                        date_part = exp_parts[0]
                        time_part = exp_parts[1]
                        node.cert_expiration = f"{date_part}T{time_part}Z"
                    else:
                        # Fallback: use current time + 1 year
                        node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                except Exception as e:
                    print(f"Error parsing certificate expiration: {e}")
                    # Fallback: use current time + 1 year
                    node.cert_expiration = timezone.now() + timezone.timedelta(days=365)
                break
        
        node.save()

        # Keep mobile QR generation tied to cert issuance.
        if not node.is_lighthouse:
            if nebula_qr_generated and os.path.exists(qr_path):
                with open(qr_path, 'rb') as qr_file:
                    NodeQRCode.create_or_update_for_node_image(
                        node=node,
                        qr_bytes=qr_file.read(),
                        days_valid=30,
                    )
            else:
                NodeQRCode.create_for_node(node, days_valid=30)
        
        # Clean up old certificate files if they exist
        try:
            if old_cert_path and os.path.exists(old_cert_path):
                os.remove(old_cert_path)
            if old_key_path and os.path.exists(old_key_path):
                os.remove(old_key_path)
        except OSError as e:
            # Log but don't fail if cleanup fails
            print(f"Warning: Could not remove old certificate files: {str(e)}")
            
        return True
    
    except Exception as e:
        print(f"Error regenerating certificate: {str(e)}")
        return False

@login_required
def org_node_delete(request, slug, pk):
    """Delete a node in an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    node = get_object_or_404(Node, id=pk, organization=org)
    
    if request.method == 'POST':
        payload = notification_dispatch.node_lifecycle_payload(node)
        organization_id = node.organization_id
        node.delete()
        notification_dispatch.queue_notification_event('node.revoked', organization_id, payload)
        return redirect('nodes_org:list', slug=slug)
    
    context = {
        'organization': org,
        'node': node
    }
    
    return render(request, 'nodes/org_delete.html', context)

@login_required
def org_node_download_cert(request, slug, pk):
    """Download a node certificate in an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    node = get_object_or_404(Node, id=pk, organization=org)
    
    # Placeholder for certificate download logic
    
    return HttpResponse("Certificate download")

@login_required
def org_node_download_key(request, slug, pk):
    """Download a node private key in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    node = get_object_or_404(Node, id=pk, organization=org)
    
    # Placeholder for key download logic
    
    return HttpResponse("Key download")

@login_required
def org_node_download_config(request, slug, pk):
    """Download or view a node configuration in an organization (returns raw YAML)."""
    org = check_org_access(request.user, organization_slug=slug)
    node = get_object_or_404(Node, id=pk, organization=org)
    
    # Attempt to prepare the config, regenerate certificates on missing files and retry
    reg_view = NodeRegistrationView()
    try:
        response = reg_view._prepare_node_package(node, format_type='json')
    except ValueError:
        # Missing cert or key, regenerate and retry
        regenerate_certificate(node)
        response = reg_view._prepare_node_package(node, format_type='json')
    
    # Extract the YAML string
    config_yaml = response.data.get('config_yaml', '')
    
    return HttpResponse(config_yaml, content_type='text/yaml')

@login_required
@never_cache
@require_http_methods(["GET", "POST"])
def org_node_mobile_sign(request, slug, pk):
    """
    Mobile-friendly flow:
    - User uploads a Nebula public key exported from the mobile app
    - Server signs it with the org CA (no private key upload/download)
    - Server returns a zip containing ca.crt + signed client cert
    """
    org = check_org_access(request.user, organization_slug=slug)
    node = get_object_or_404(Node, id=pk, organization=org)

    membership_role = request.user.memberships.filter(
        organization=org
    ).values_list('role', flat=True).first()
    can_edit = membership_role in ['owner', 'admin']
    if not can_edit and node.assigned_user_id != request.user.id and node.created_by_id != request.user.id:
        raise PermissionDenied("You don't have access to this mobile node.")
    if node.is_lighthouse:
        messages.error(request, "Signing is only available for mobile endpoints (non-lighthouse nodes).")
        return redirect('nodes_org:detail', slug=slug, pk=node.id)

    if request.method == "GET":
        return render(request, "nodes/org_mobile_sign.html", {"organization": org, "node": node, "can_edit": can_edit})

    uploaded = request.FILES.get("public_key")
    if not uploaded:
        messages.error(request, "Please upload the public key file exported from the Nebula mobile app.")
        return redirect('nodes_org:mobile_sign', slug=slug, pk=node.id)

    if uploaded.size and uploaded.size > 64 * 1024:
        messages.error(request, "That file is unexpectedly large. Please upload the Nebula public key file.")
        return redirect('nodes_org:mobile_sign', slug=slug, pk=node.id)

    try:
        pub_bytes = uploaded.read()
    except Exception:
        messages.error(request, "Could not read the uploaded file.")
        return redirect('nodes_org:mobile_sign', slug=slug, pk=node.id)

    # Basic content sanity check to reduce user confusion.
    try:
        pub_text = pub_bytes.decode("utf-8", errors="replace")
    except Exception:
        pub_text = ""
    if "BEGIN NEBULA CERTIFICATE" in pub_text or "BEGIN CERTIFICATE" in pub_text:
        messages.error(request, "This looks like a certificate, not a public key. Export the public key from the mobile app and upload that instead.")
        return redirect('nodes_org:mobile_sign', slug=slug, pk=node.id)

    ca = node.certificate_authority
    if not ca or not ca.ca_cert or not ca.ca_key:
        messages.error(request, "This device is missing a certificate authority configuration.")
        return redirect('nodes_org:detail', slug=slug, pk=node.id)

    # Respect per-node expiration if present (best-effort).
    duration_arg = None
    if node.cert_expiration:
        delta = node.cert_expiration - timezone.now()
        seconds = int(delta.total_seconds())
        if seconds <= 0:
            messages.error(request, "This device's certificate expiration is in the past. Update the node expiration and try again.")
            return redirect('nodes_org:detail', slug=slug, pk=node.id)
        # Ensure at least 60 seconds to avoid nebula-cert rejecting tiny durations.
        duration_arg = f"{max(60, seconds)}s"

    # Include Nebula groups from org security groups and lighthouse role (mobile nodes won't be lighthouses).
    group_names = list(node.security_groups.values_list('name', flat=True))

    try:
        with tempfile.TemporaryDirectory(prefix="nebula_mobile_sign_") as tmpdir:
            in_pub_path = os.path.join(tmpdir, "mobile.pub")
            out_crt_path = os.path.join(tmpdir, f"{node.name}.crt")

            with open(in_pub_path, "wb") as f:
                f.write(pub_bytes)

            cmd = [
                "nebula-cert", "sign",
                "-name", node.name,
                "-ip", f"{node.nebula_ip}/24",
                "-ca-crt", ca.ca_cert.path,
                "-ca-key", ca.ca_key.path,
                "-in-pub", in_pub_path,
                "-out-crt", out_crt_path,
            ]
            if duration_arg:
                cmd.extend(["-duration", duration_arg])
            if group_names:
                cmd.extend(["-groups", ",".join(group_names)])

            subprocess.run(cmd, check=True, capture_output=True, text=True)

            with open(out_crt_path, "rb") as f:
                signed_crt = f.read()
            with open(ca.ca_cert.path, "rb") as f:
                ca_crt = f.read()

        # Minimal audit trail via logs (no dedicated audit table found).
        logger.info(
            "nebula_mobile_sign user_id=%s org_id=%s node_id=%s node_name=%s",
            getattr(request.user, "id", None),
            getattr(org, "id", None),
            getattr(node, "id", None),
            node.name,
        )

        bundle = io.BytesIO()
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("ca.crt", ca_crt)
            zf.writestr(f"{node.name}.crt", signed_crt)
        bundle.seek(0)

        resp = HttpResponse(bundle.getvalue(), content_type="application/zip")
        resp["Content-Disposition"] = f'attachment; filename="{node.name}-nebula-mobile-certs.zip"'
        resp["Cache-Control"] = "no-store, max-age=0"
        resp["Pragma"] = "no-cache"
        resp["X-Content-Type-Options"] = "nosniff"
        return resp

    except subprocess.CalledProcessError as e:
        logger.error("nebula_mobile_sign failed: %s", getattr(e, "stderr", "") or str(e))
        messages.error(request, "Signing failed. Please try again or contact an administrator.")
        return redirect('nodes_org:mobile_sign', slug=slug, pk=node.id)
    except Exception as e:
        logger.exception("nebula_mobile_sign unexpected error: %s", e)
        messages.error(request, "Unexpected error while signing. Please try again.")
        return redirect('nodes_org:mobile_sign', slug=slug, pk=node.id)

@login_required
def org_node_renew_cert(request, slug, pk):
    """Renew a node certificate in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    node = get_object_or_404(Node, id=pk, organization=org)
    
    if regenerate_certificate(node):
        notification_dispatch.queue_node_lifecycle_events(node, ['cert.renewed'])
        messages.success(request, f"Certificate successfully renewed for {node.name}.")
    else:
        messages.error(request, f"Failed to renew certificate for {node.name}. Please check the logs.")
    
    return redirect('nodes_org:detail', slug=slug, pk=node.id)

@login_required
def org_node_security_groups(request, slug, pk):
    """Manage security groups for a node in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    node = get_object_or_404(Node, id=pk, organization=org)
    
    # Get all security groups for this organization
    security_groups = Tag.objects.filter(organization=org)

    # Get security groups assigned to this node
    assigned_groups = node.tags.all()

    if request.method == 'POST':
        # Handle form submission for adding/removing security groups
        security_group_id = request.POST.get('security_group_id')
        action = request.POST.get('action')

        if security_group_id and action:
            security_group = get_object_or_404(Tag, id=security_group_id, organization=org)
            security_groups_changed = False

            if action == 'add':
                # Add security group to node
                if security_group not in assigned_groups:
                    node.tags.add(security_group)
                    security_groups_changed = True
                    messages.success(request, f"Security group '{security_group.name}' added to node.")
            elif action == 'remove':
                # Remove security group from node
                if security_group in assigned_groups:
                    node.tags.remove(security_group)
                    security_groups_changed = True
                    messages.success(request, f"Security group '{security_group.name}' removed from node.")
            
            # If security groups changed, regenerate the certificate
            if security_groups_changed:
                if regenerate_certificate(node):
                    notification_dispatch.queue_node_lifecycle_events(node, ['cert.renewed'])
                    messages.success(request, f"Certificate regenerated for {node.name} due to security group changes.")
                else:
                    messages.error(request, f"Failed to regenerate certificate for {node.name}.")
            
            return redirect('nodes_org:assign_security_group', slug=slug, pk=node.id)

    context = {
        'organization': org,
        'node': node,
        'security_groups': security_groups,
        'assigned_groups': assigned_groups
    }

    return render(request, 'nodes/org_security_groups.html', context)


@login_required
def org_node_enroll(request, slug, pk):
    """Enrollment endpoint for mobile devices using QR code token."""
    org = check_org_access(request.user, organization_slug=slug)
    node = get_object_or_404(Node, id=pk, organization=org)
    membership_role = request.user.memberships.filter(
        organization=org
    ).values_list('role', flat=True).first()
    can_edit = membership_role in ['owner', 'admin']

    if not can_edit and node.assigned_user_id != request.user.id and node.created_by_id != request.user.id:
        messages.error(request, "You don't have access to this mobile node enrollment link.")
        return redirect('nodes_org:list', slug=slug)

    token = request.GET.get('token')
    if not token:
        messages.error(request, "Enrollment token is required.")
        return redirect('nodes_org:detail', slug=slug, pk=node.id)

    try:
        qr_code = NodeQRCode.objects.get(
            node=node,
            enrollment_token=token,
            is_active=True
        )

        if not qr_code.is_valid:
            messages.error(request, "This enrollment QR code has expired or been deactivated.")
            return redirect('nodes_org:detail', slug=slug, pk=node.id)

    except NodeQRCode.DoesNotExist:
        messages.error(request, "Invalid enrollment token.")
        return redirect('nodes_org:detail', slug=slug, pk=node.id)

    reg_view = NodeRegistrationView()
    try:
        response = reg_view._prepare_node_package(node, format_type='zip')
        return response
    except ValueError as e:
        messages.error(request, f"Failed to prepare node configuration: {str(e)}")
        return redirect('nodes_org:detail', slug=slug, pk=node.id)


@login_required
def org_node_effective_rules(request, slug, pk):
    """What firewall rules effectively apply to this node, and why."""
    org = check_org_access(request.user, organization_slug=slug)
    node, _can_edit = _get_visible_org_node(request, org, pk)
    context = {
        'organization': org,
        'node': node,
        'effective': effective_rules(node),
    }
    return render(request, 'nodes/effective_rules.html', context)


# Registration token views
@login_required
def org_registration_token_list(request, slug):
    """List all registration tokens for an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    
    tokens = NodeRegistrationToken.objects.filter(organization=org)
    
    context = {
        'organization': org,
        'tokens': tokens
    }
    
    return render(request, 'nodes/org_token_list.html', context)

@login_required
def org_registration_token_create(request, slug):
    """Create a new registration token for an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    
    if request.method == 'POST':
        # Handle form submission
        description = request.POST.get('description')
        
        # Check if the description field is provided
        if not description:
            messages.error(request, "Description is required")
            return render(request, 'nodes/org_token_create.html', {'organization': org, 'error': "Description is required"})
        
        # Handle max uses
        max_uses_str = request.POST.get('max_uses', '')
        if max_uses_str.strip():  # If max_uses is provided
            try:
                uses_allowed = int(max_uses_str)
            except ValueError:
                messages.error(request, "Max uses must be a valid number")
                return render(request, 'nodes/org_token_create.html', {'organization': org, 'error': "Max uses must be a valid number"})
        else:
            # Default to unlimited uses
            uses_allowed = -1
            
        # Handle expiration date
        expires_at_str = request.POST.get('expires_at')
        if expires_at_str:
            try:
                # Parse the datetime from the form and make it timezone-aware
                expires_at = timezone.datetime.fromisoformat(expires_at_str)
                # If the datetime is naive (no timezone info), make it timezone aware
                if expires_at.tzinfo is None:
                    # Make it timezone aware using the current timezone
                    expires_at = timezone.make_aware(expires_at)
                    
                # Calculate days valid (used by the model create method)
                now = timezone.now()
                days_valid = (expires_at - now).days
                if days_valid <= 0:
                    messages.error(request, "Expiration date must be in the future")
                    return render(request, 'nodes/org_token_create.html', {'organization': org, 'error': "Expiration date must be in the future"})
            except ValueError:
                messages.error(request, "Invalid expiration date format")
                return render(request, 'nodes/org_token_create.html', {'organization': org, 'error': "Invalid expiration date format"})
        else:
            # Default to 30 days
            days_valid = 30
            
        # Handle node type permissions
        can_register_regular = request.POST.get('can_register_regular') == 'on'
        can_register_lighthouse = request.POST.get('can_register_lighthouse') == 'on'
        
        if not (can_register_regular or can_register_lighthouse):
            messages.error(request, "At least one node type must be selected")
            return render(request, 'nodes/org_token_create.html', {'organization': org, 'error': "At least one node type must be selected"})
        
        try:
            # Create the token
            token = NodeRegistrationToken.create_for_organization(
                organization=org,
                description=description,
                created_by=request.user,
                days_valid=days_valid,
                uses_allowed=uses_allowed
            )
            
            # Set node type permissions
            token.can_register_regular = can_register_regular
            token.can_register_lighthouse = can_register_lighthouse
            token.save()
            
            # Set up success message with the token value
            messages.success(
                request, 
                f"Token created successfully! Token value: {token.token}. Please save this value as it will not be shown again."
            )
            
            return redirect('nodes_org:token_detail', slug=slug, pk=token.id)
        except Exception as e:
            messages.error(request, f"Error creating token: {str(e)}")
            return render(request, 'nodes/org_token_create.html', {'organization': org, 'error': str(e)})
    
    context = {
        'organization': org
    }
    
    return render(request, 'nodes/org_token_create.html', context)

@login_required
def org_registration_token_detail(request, slug, pk):
    """View details of a registration token in an organization."""
    org = check_org_access(request.user, organization_slug=slug)
    token = get_object_or_404(NodeRegistrationToken, id=pk, organization=org)
    
    context = {
        'organization': org,
        'token': token
    }
    
    return render(request, 'nodes/org_token_detail.html', context)

@login_required
def org_registration_token_revoke(request, slug, pk):
    """Revoke a registration token in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    token = get_object_or_404(NodeRegistrationToken, id=pk, organization=org)
    
    if request.method == 'POST':
        token.is_active = False
        token.save()
        
        messages.success(request, f"Token '{token.description}' has been successfully revoked.")
        return redirect('nodes_org:token_list', slug=slug)
    
    context = {
        'organization': org,
        'token': token
    }
    
    return render(request, 'nodes/org_token_revoke.html', context)


# ── Bulk Operations ──────────────────────────────────────────────────────

@login_required
def org_node_export_csv(request, slug):
    """Export all nodes in an organization as a CSV file."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    nodes = Node.objects.filter(organization=org).select_related(
        'assigned_user', 'certificate_authority', 'created_by'
    ).order_by('name')

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{org.slug}-nodes.csv"'

    writer = csv.writer(response)
    writer.writerow([
        'name', 'nebula_ip', 'is_lighthouse', 'public_ip', 'fqdn',
        'external_port', 'assigned_user_email', 'security_groups',
        'cert_expiration', 'last_checkin', 'created_at',
    ])
    for node in nodes:
        groups = ', '.join(node.security_groups.values_list('name', flat=True))
        writer.writerow([
            node.name,
            node.nebula_ip or '',
            node.is_lighthouse,
            node.public_ip or '',
            node.fqdn or '',
            node.external_port or 4242,
            node.assigned_user.email if node.assigned_user else '',
            groups,
            node.cert_expiration.isoformat() if node.cert_expiration else '',
            node.last_checkin.isoformat() if node.last_checkin else '',
            node.created_at.isoformat() if node.created_at else '',
        ])

    return response


@login_required
def org_node_import_csv(request, slug):
    """Import nodes from a CSV file into an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])
    latest_ca = _get_latest_org_ca(org)

    if request.method == 'GET':
        context = {
            'organization': org,
            'has_ca': latest_ca is not None,
            'has_ranges': org.network_ranges.exists(),
        }
        return render(request, 'nodes/org_import_csv.html', context)

    # POST: process the upload
    csv_file = request.FILES.get('csv_file')
    if not csv_file:
        messages.error(request, "No file was uploaded.")
        return redirect('nodes_org:import_csv', slug=slug)

    if not csv_file.name.endswith('.csv'):
        messages.error(request, "Please upload a .csv file.")
        return redirect('nodes_org:import_csv', slug=slug)

    if not latest_ca:
        messages.error(request, "No certificate authority exists. Create one first.")
        return redirect('nodes_org:import_csv', slug=slug)

    try:
        decoded = csv_file.read().decode('utf-8')
    except UnicodeDecodeError:
        messages.error(request, "File is not valid UTF-8 text.")
        return redirect('nodes_org:import_csv', slug=slug)

    reader = csv.DictReader(io.StringIO(decoded))
    required_fields = {'name'}
    if not required_fields.issubset(set(reader.fieldnames or [])):
        messages.error(request, "CSV must have at least a 'name' column.")
        return redirect('nodes_org:import_csv', slug=slug)

    created = 0
    errors = []

    for row_num, row in enumerate(reader, start=2):
        name = row.get('name', '').strip()
        if not name:
            errors.append(f"Row {row_num}: name is empty, skipped.")
            continue

        if Node.objects.filter(organization=org, name=name).exists():
            errors.append(f"Row {row_num}: node '{name}' already exists, skipped.")
            continue

        is_lighthouse = row.get('is_lighthouse', '').strip().lower() in ('true', '1', 'yes')
        public_ip = row.get('public_ip', '').strip() or None
        fqdn = row.get('fqdn', '').strip() or None
        external_port = None
        port_str = row.get('external_port', '').strip()
        if port_str:
            try:
                external_port = int(port_str)
            except ValueError:
                errors.append(f"Row {row_num}: invalid external_port '{port_str}', using default.")
                external_port = 4242

        if is_lighthouse and not public_ip and not fqdn:
            errors.append(f"Row {row_num}: lighthouse '{name}' needs public_ip or fqdn, skipped.")
            continue

        try:
            node = Node(
                name=name,
                organization=org,
                certificate_authority=latest_ca,
                is_lighthouse=is_lighthouse,
                public_ip=public_ip,
                fqdn=fqdn,
                external_port=external_port or 4242,
                created_by=request.user,
            )
            node.full_clean()
            node.save()
            cert_success = regenerate_certificate(node)
            if cert_success:
                notification_dispatch.queue_node_lifecycle_events(
                    node,
                    ['node.created', 'cert.issued', 'ip.allocated'],
                )
            created += 1
        except Exception as e:
            errors.append(f"Row {row_num}: '{name}' failed — {e}")

    if created:
        messages.success(request, f"Successfully imported {created} node(s).")
    if errors:
        messages.warning(request, f"{len(errors)} row(s) had issues. See details below.")

    context = {
        'organization': org,
        'created': created,
        'errors': errors,
        'has_ca': latest_ca is not None,
        'has_ranges': org.network_ranges.exists(),
    }
    return render(request, 'nodes/org_import_csv.html', context)


@login_required
@require_http_methods(["GET", "POST"])
def org_node_bulk_delete(request, slug):
    """Bulk delete selected nodes in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])

    if request.method == 'GET':
        nodes = Node.objects.filter(organization=org).order_by('name')
        context = {
            'organization': org,
            'nodes': nodes,
        }
        return render(request, 'nodes/org_bulk_delete.html', context)

    # POST: delete selected nodes
    node_ids = request.POST.getlist('node_ids')
    if not node_ids:
        messages.warning(request, "No nodes were selected.")
        return redirect('nodes_org:bulk_delete', slug=slug)

    nodes = Node.objects.filter(organization=org, id__in=node_ids)
    count = nodes.count()
    revoked_payloads = [
        (node.organization_id, notification_dispatch.node_lifecycle_payload(node))
        for node in nodes
    ]

    for node in nodes:
        node.delete()
    for organization_id, payload in revoked_payloads:
        notification_dispatch.queue_notification_event('node.revoked', organization_id, payload)

    messages.success(request, f"Deleted {count} node(s).")
    return redirect('nodes_org:list', slug=slug)


@login_required
@require_http_methods(["GET", "POST"])
def org_node_bulk_renew(request, slug):
    """Bulk renew certificates for nodes in an organization."""
    org = check_org_access(request.user, organization_slug=slug, required_roles=['owner', 'admin'])

    nodes = Node.objects.filter(organization=org).select_related('certificate_authority').order_by('name')

    # Filter by expiration window
    days = int(request.GET.get('days', 30))
    now = timezone.now()
    threshold = now + timedelta(days=days)
    expiring_nodes = nodes.filter(cert_expiration__lte=threshold)

    if request.method == 'GET':
        context = {
            'organization': org,
            'expiring_nodes': expiring_nodes,
            'all_nodes': nodes,
            'days': days,
            'now': now,
        }
        return render(request, 'nodes/org_bulk_renew.html', context)

    # POST: renew selected nodes
    node_ids = request.POST.getlist('node_ids')
    if not node_ids:
        messages.warning(request, "No nodes were selected.")
        return redirect('nodes_org:bulk_renew', slug=slug)

    selected_nodes = Node.objects.filter(organization=org, id__in=node_ids)
    renewed = 0
    failed = 0

    for node in selected_nodes:
        if regenerate_certificate(node):
            notification_dispatch.queue_node_lifecycle_events(node, ['cert.renewed'])
            renewed += 1
        else:
            failed += 1

    if renewed:
        messages.success(request, f"Successfully renewed {renewed} certificate(s).")
    if failed:
        messages.error(request, f"Failed to renew {failed} certificate(s). Check the logs.")

    return redirect('nodes_org:list', slug=slug)
