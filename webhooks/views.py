from django.shortcuts import render, redirect, get_object_or_404
from .models import Webhook, WebhookDelivery
# from .serializers import WebhookSerializer, WebhookDeliverySerializer
from organizations.permissions import IsOrganizationOwnerOrAdmin
import requests
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from organizations.access import require_org_access

# class IsWebhookOrganizationOwnerOrAdmin(permissions.BasePermission):
#     """
#     Custom permission to only allow owners and admins of the webhook's organization to access it.
#     """
#     def has_object_permission(self, request, view, obj):
#         # Check if user is a member of the organization
#         membership = obj.organization.memberships.filter(user=request.user).first()
#         if not membership:
#             return False
#         # Check if user is owner or admin
#         return membership.role in ['owner', 'admin']

@login_required
def webhook_list(request):
    """List webhooks that the user has access to."""
    return render(request, 'webhooks/list.html')

@login_required
def webhook_create(request):
    """Create a new webhook."""
    return render(request, 'webhooks/create.html')

@login_required
def webhook_detail(request, pk):
    """View webhook details."""
    return render(request, 'webhooks/detail.html')

# Helper function for organization access
def check_org_access(user, slug, required_roles=None):
    """Helper function to check if user has access to an organization by slug"""
    return require_org_access(user, slug=slug, required_roles=required_roles)

# Organization-specific views (placeholder implementations)
@login_required
def org_webhook_list(request, slug):
    """List all webhooks for an organization."""
    org = check_org_access(request.user, slug)
    webhooks = Webhook.objects.filter(organization=org)
    context = {
        'organization': org,
        'webhooks': webhooks
    }
    return render(request, 'webhooks/org_list.html', context)

@login_required
def org_webhook_create(request, slug):
    """Create a new webhook for an organization."""
    org = check_org_access(request.user, slug, required_roles=['owner', 'admin'])
    if request.method == 'POST':
        url = request.POST.get('url')
        events = request.POST.getlist('events')
        description = request.POST.get('description', '')
        secret = request.POST.get('secret', '')
        active = bool(request.POST.get('active'))
        if url and events:
            webhook = Webhook.objects.create(
                url=url,
                events=events,
                description=description,
                secret=secret,
                active=active,
                organization=org
            )
            return redirect('webhooks_org:list', slug=slug)
    context = {
        'organization': org,
        'events': Webhook.EVENT_CHOICES
    }
    return render(request, 'webhooks/org_create.html', context)

@login_required
def org_webhook_detail(request, slug, pk):
    """View details of a webhook in an organization."""
    org = check_org_access(request.user, slug)
    webhook = get_object_or_404(Webhook, id=pk, organization=org)
    context = {
        'organization': org,
        'webhook': webhook
    }
    return render(request, 'webhooks/org_detail.html', context)

@login_required
def org_webhook_edit(request, slug, pk):
    """Edit a webhook in an organization."""
    org = check_org_access(request.user, slug, required_roles=['owner', 'admin'])
    webhook = get_object_or_404(Webhook, id=pk, organization=org)
    if request.method == 'POST':
        url = request.POST.get('url')
        events = request.POST.getlist('events')
        description = request.POST.get('description', '')
        secret = request.POST.get('secret', '')
        active = bool(request.POST.get('active'))
        if url and events:
            webhook.url = url
            webhook.events = events
            webhook.description = description
            webhook.secret = secret
            webhook.active = active
            webhook.save()
            return redirect('webhooks_org:list', slug=slug)
    context = {
        'organization': org,
        'webhook': webhook,
        'events': Webhook.EVENT_CHOICES
    }
    return render(request, 'webhooks/org_edit.html', context)

@login_required
def org_webhook_delete(request, slug, pk):
    """Delete a webhook in an organization."""
    org = check_org_access(request.user, slug, required_roles=['owner', 'admin'])
    webhook = get_object_or_404(Webhook, id=pk, organization=org)
    if request.method == 'POST':
        webhook.delete()
        return redirect('webhooks_org:list', slug=slug)
    context = {
        'organization': org,
        'webhook': webhook
    }
    return render(request, 'webhooks/org_delete.html', context)

@login_required
def org_webhook_test(request, slug, pk):
    """Test a webhook in an organization."""
    org = check_org_access(request.user, slug, required_roles=['owner', 'admin'])
    webhook = get_object_or_404(Webhook, id=pk, organization=org)
    # Placeholder for webhook test logic
    return redirect('webhooks_org:detail', slug=slug, pk=webhook.id)

@login_required
def org_webhook_logs(request, slug):
    """View webhook delivery logs for an organization."""
    org = check_org_access(request.user, slug)
    # Placeholder for webhook logs logic
    context = {
        'organization': org,
        'logs': []
    }
    return render(request, 'webhooks/org_logs.html', context)
