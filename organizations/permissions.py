from rest_framework import permissions

from .access import get_organization_for_object, is_org_manager

class IsOrganizationOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to only allow owners and admins of an organization to edit it.
    """
    def has_permission(self, request, view):
        # Allow creation for any authenticated user
        if request.method == 'POST' and view.action == 'create':
            return request.user and request.user.is_authenticated
        return True

    def has_object_permission(self, request, view, obj):
        if request.method in permissions.SAFE_METHODS:
            return True
        organization = get_organization_for_object(obj)
        return is_org_manager(request.user, organization)