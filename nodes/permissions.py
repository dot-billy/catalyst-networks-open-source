from rest_framework.permissions import BasePermission
from organizations.models import Organization
from organizations.access import is_org_manager
from .models import Node
import logging
import traceback

logger = logging.getLogger(__name__)

class NodeAccessPermission(BasePermission):
    """
    Custom permission to allow:
    1. Nodes to access their own resources (via API token)
    2. Organization owners/admins to access any node in their organization
    """
    
    def has_permission(self, request, view):
        logger.info("=== Starting NodeAccessPermission.has_permission ===")
        logger.info(f"Request path: {request.path}")
        logger.info(f"Request method: {request.method}")
        logger.info(f"View: {view.__class__.__name__}")
        logger.info(f"View action: {getattr(view, 'action', 'unknown')}")
        logger.info(f"View kwargs: {getattr(view, 'kwargs', {})}")
        
        # Check if request is authenticated
        if not request.user and not hasattr(request, 'node'):
            logger.warning("Request is not authenticated - no user or node found")
            return False
            
        # Get organization from URL parameters
        org_slug = request.parser_context.get('kwargs', {}).get('slug')
        logger.info(f"Organization slug from URL: {org_slug}")
        
        # If we have a node (API token authentication)
        if hasattr(request, 'node'):
            logger.info(f"Request authenticated with node: {request.node.id} (name={request.node.name})")
            logger.info(f"Node organization: {request.node.organization.slug}")
            
            # For organization-specific endpoints, verify the node belongs to the correct organization
            if org_slug and request.node.organization.slug != org_slug:
                logger.warning(f"Node {request.node.id} does not belong to organization {org_slug}")
                return False
                
            # Allow node to access its own resources
            if view.action in ['download_config', 'checkin']:
                logger.info(f"Allowing node {request.node.id} to access {view.action}")
                return True
                
            return True
            
        # If we have a user (session authentication)
        if request.user:
            logger.info(f"Request authenticated with user: {request.user.id} (email={request.user.email})")
            try:
                org = Organization.objects.get(slug=org_slug)
                logger.info(f"Found organization: {org.slug} (id={org.id})")

                if is_org_manager(request.user, org):
                    logger.info("User has organization-level access")
                    return True

                logger.warning("User does not have organization-level access")
                return False
            except Organization.DoesNotExist:
                logger.warning(f"Organization {org_slug} not found")
                return False
                
        return False
    
    def has_object_permission(self, request, view, obj):
        logger.info("=== Starting NodeAccessPermission.has_object_permission ===")
        logger.info(f"Request path: {request.path}")
        logger.info(f"Request method: {request.method}")
        logger.info(f"View: {view.__class__.__name__}")
        logger.info(f"View action: {getattr(view, 'action', 'unknown')}")
        logger.info(f"Object type: {type(obj)}")
        logger.info(f"Object ID: {getattr(obj, 'id', 'N/A')}")
        
        # If we have a node (API token authentication)
        if hasattr(request, 'node'):
            logger.info(f"Request authenticated with node: {request.node.id} (name={request.node.name})")
            logger.info(f"Target object: {obj.id} (name={getattr(obj, 'name', 'N/A')})")
            
            # Check if node is trying to access its own resources
            if isinstance(obj, Node) and obj.id == request.node.id:
                logger.info("Node is accessing its own resources")
                return True
                
            logger.warning(f"Node {request.node.id} is trying to access another node's resources")
            return False
            
        # If we have a user (session authentication)
        if request.user:
            logger.info(f"Request authenticated with user: {request.user.id} (email={request.user.email})")
            try:
                org = obj.organization
                logger.info(f"Object organization: {org.slug} (id={org.id})")

                if is_org_manager(request.user, org):
                    logger.info("User has organization-level access to object")
                    return True

                logger.warning("User does not have organization-level access to object")
                return False
            except Exception as e:
                logger.error(f"Error checking object permissions: {str(e)}")
                logger.error(traceback.format_exc())
                return False
                
        return False
