from rest_framework.permissions import BasePermission
from organizations.models import Organization
from organizations.access import is_org_manager
from .models import Node
import logging

logger = logging.getLogger(__name__)

class NodeAccessPermission(BasePermission):
    """
    Custom permission to allow:
    1. Nodes to access their own resources (via API token)
    2. Organization owners/admins to access any node in their organization
    """
    
    def _log_decision(self, method, view, allowed, reason):
        logger.debug(
            "%s action=%s allowed=%s reason=%s",
            method,
            getattr(view, 'action', 'unknown'),
            allowed,
            reason,
        )

    def has_permission(self, request, view):
        
        # Check if request is authenticated
        if not getattr(request, 'user', None) and not hasattr(request, 'node'):
            self._log_decision('NodeAccessPermission.has_permission', view, False, 'not_authenticated')
            return False
            
        # Get organization from URL parameters
        parser_context = getattr(request, 'parser_context', {}) or {}
        org_slug = parser_context.get('kwargs', {}).get('slug')
        
        # If we have a node (API token authentication)
        if hasattr(request, 'node'):
            # For organization-specific endpoints, verify the node belongs to the correct organization
            if org_slug and request.node.organization.slug != org_slug:
                self._log_decision('NodeAccessPermission.has_permission', view, False, 'node_org_mismatch')
                return False

            self._log_decision('NodeAccessPermission.has_permission', view, True, 'node_authenticated')
            return True
            
        # If we have a user (session authentication)
        if getattr(request, 'user', None):
            try:
                org = Organization.objects.get(slug=org_slug)

                if is_org_manager(request.user, org):
                    self._log_decision('NodeAccessPermission.has_permission', view, True, 'user_org_manager')
                    return True

                self._log_decision('NodeAccessPermission.has_permission', view, False, 'user_not_org_manager')
                return False
            except Organization.DoesNotExist:
                self._log_decision('NodeAccessPermission.has_permission', view, False, 'org_not_found')
                return False

        self._log_decision('NodeAccessPermission.has_permission', view, False, 'unsupported_auth_context')
        return False
    
    def has_object_permission(self, request, view, obj):
        # If we have a node (API token authentication)
        if hasattr(request, 'node'):
            # Check if node is trying to access its own resources
            if isinstance(obj, Node) and obj.id == request.node.id:
                self._log_decision('NodeAccessPermission.has_object_permission', view, True, 'node_own_object')
                return True

            self._log_decision('NodeAccessPermission.has_object_permission', view, False, 'node_object_mismatch')
            return False
            
        # If we have a user (session authentication)
        if getattr(request, 'user', None):
            try:
                org = obj.organization

                if is_org_manager(request.user, org):
                    self._log_decision('NodeAccessPermission.has_object_permission', view, True, 'user_org_manager')
                    return True

                self._log_decision('NodeAccessPermission.has_object_permission', view, False, 'user_not_org_manager')
                return False
            except Exception:
                self._log_decision('NodeAccessPermission.has_object_permission', view, False, 'object_permission_error')
                return False

        self._log_decision('NodeAccessPermission.has_object_permission', view, False, 'unsupported_auth_context')
        return False
