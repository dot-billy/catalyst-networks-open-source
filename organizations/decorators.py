from functools import wraps
from django.shortcuts import redirect
from django.contrib import messages

from .access import get_org_role, require_org_access

def organization_member_required(view_func):
    """
    Decorator that checks if the user is a member of the organization.
    Must be used on views that have a 'slug' parameter in their URL.
    """
    @wraps(view_func)
    def _wrapped_view(request, slug, *args, **kwargs):
        try:
            organization = require_org_access(request.user, slug=slug)
        except Exception:
            messages.error(request, 'You do not have permission to access this organization.')
            return redirect('organizations:list')

        request.user_role = get_org_role(request.user, organization)
        return view_func(request, slug, *args, **kwargs)

    return _wrapped_view 