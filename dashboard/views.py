from datetime import datetime, timedelta
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.db.models import Count
from organizations.models import Organization
from nodes.models import Node
from security_groups.models import SecurityGroup
from simple_history.models import HistoricalRecords


@login_required
def dashboard(request):
    """Main dashboard view showing summary data and recent activity"""
    # Get organizations the user is a member of
    user_orgs = Organization.objects.filter(
        memberships__user=request.user
    ).annotate(
        node_count=Count('nodes')
    )
    
    # Get counts for the stats cards
    context = {
        'organizations_count': user_orgs.count(),
        'nodes_count': Node.objects.filter(organization__in=user_orgs).count(),
        'security_groups_count': SecurityGroup.objects.filter(organization__in=user_orgs).count(),
        'organizations': user_orgs
    }
    
    return render(request, 'dashboard/index.html', context)


@login_required
def recent_activity(request):
    """HTMX endpoint for loading recent activity"""
    # Get organizations the user is a member of
    user_orgs = Organization.objects.filter(memberships__user=request.user)
    
    # Collect recent history from various models
    activities = []
    
    # Node creation/updates
    for history in Node.history.filter(
        organization__in=user_orgs
    ).order_by('-history_date')[:10]:
        if history.history_type == '+':
            activities.append({
                'type': 'node_created',
                'message': f'Node "{history.name}" was created in {history.organization.name}',
                'timestamp': history.history_date
            })
        elif history.history_type == '~':
            activities.append({
                'type': 'node_updated',
                'message': f'Node "{history.name}" was updated in {history.organization.name}',
                'timestamp': history.history_date
            })
    
    # Security group updates
    for history in SecurityGroup.history.filter(
        organization__in=user_orgs
    ).order_by('-history_date')[:10]:
        if history.history_type == '+':
            activities.append({
                'type': 'security_group_created',
                'message': f'Security group "{history.name}" was created in {history.organization.name}',
                'timestamp': history.history_date
            })
        elif history.history_type == '~':
            activities.append({
                'type': 'security_group_updated',
                'message': f'Security group "{history.name}" was updated in {history.organization.name}',
                'timestamp': history.history_date
            })
    
    # Sort all activities by timestamp
    activities.sort(key=lambda x: x['timestamp'], reverse=True)
    activities = activities[:10]  # Take only 10 most recent
    
    return render(request, 'dashboard/recent_activity.html', {'activities': activities})


@login_required
def certificate_warnings(request):
    """HTMX endpoint for loading certificate expiry warnings"""
    # Get organizations the user is a member of
    user_orgs = Organization.objects.filter(memberships__user=request.user)
    
    # Find certificates expiring in the next 30 days
    now = datetime.now().date()
    expiry_threshold = now + timedelta(days=30)
    
    expiring_certificates = []
    nodes_expiring = Node.objects.filter(
        organization__in=user_orgs,
        cert_expiration__lte=expiry_threshold
    )
    
    for node in nodes_expiring:
        days_remaining = (node.cert_expiration - now).days
        expiring_certificates.append({
            'node': node,
            'days_remaining': days_remaining
        })
    
    # Sort by days remaining (ascending)
    expiring_certificates.sort(key=lambda x: x['days_remaining'])
    
    return render(request, 'dashboard/certificate_warnings.html', {
        'expiring_certificates': expiring_certificates
    }) 