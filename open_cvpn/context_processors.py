from django.conf import settings
from copy import copy

def project_meta(request):
    """Add project metadata to template context"""
    project_data = copy(settings.PROJECT_METADATA)
    return {
        "project_meta": project_data,
        "static_asset_version": settings.STATIC_ASSET_VERSION,
    }

def breadcrumb_navigation(request):
    """Add breadcrumb navigation data to template context"""
    breadcrumb_items = []

    # Get current path segments
    path_segments = [segment for segment in request.path.split('/') if segment]

    # Build breadcrumb items based on current path
    if path_segments:
        current_path = ''

        for i, segment in enumerate(path_segments):
            current_path += f'/{segment}'

            # Map path segments to human-readable names
            if segment == 'dashboard':
                name = 'Dashboard'
            elif segment == 'organizations':
                name = 'Organizations'
            elif segment == 'create':
                name = 'Create Organization'
            elif segment == 'list':
                name = 'List'
            elif segment == 'detail':
                name = 'Details'
            elif segment == 'edit':
                name = 'Edit'
            elif segment == 'members':
                name = 'Members'
            elif segment == 'nodes':
                name = 'Nodes'
            elif segment == 'security-groups':
                name = 'Security Groups'
            elif segment == 'webhooks':
                name = 'Webhooks'
            elif segment == 'certificates':
                name = 'Certificates'
            elif segment == 'profile':
                name = 'Profile'
            elif segment == 'docs':
                name = 'Documentation'
            else:
                # Try to get organization name if it's a slug
                try:
                    from organizations.models import Organization
                    org = Organization.objects.get(slug=segment)
                    name = org.name
                except:
                    name = segment.replace('-', ' ').title()

            # Don't include the last segment as a link (current page)
            is_last = i == len(path_segments) - 1
            breadcrumb_items.append({
                'name': name,
                'url': current_path if not is_last else None
            })

    return {
        "breadcrumb_items": breadcrumb_items,
    }
