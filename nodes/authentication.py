from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import AnonymousUser
from .models import Node
import logging
import traceback

logger = logging.getLogger(__name__)

class NodeAPITokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        logger.info("=== Starting NodeAPITokenAuthentication.authenticate ===")
        logger.info(f"Request path: {request.path}")
        logger.info(f"Request headers: {dict(request.headers)}")
        
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.lower().startswith('bearer '):
            logger.info("No Bearer token found in Authorization header")
            return None
            
        api_token = auth_header[7:].strip()
        logger.info(f"Found Bearer token: {api_token[:6]}...{api_token[-4:] if len(api_token) > 10 else ''}")
        
        try:
            # Try to get route parameters for debugging
            pk = request.parser_context.get('kwargs', {}).get('pk')
            slug = request.parser_context.get('kwargs', {}).get('slug')
            logger.info(f"Looking up node with token for pk={pk}, slug={slug}")
            
            # Attempt to find node by token and organization
            try:
                if slug:
                    # If we have an organization slug, use it to filter
                    from organizations.models import Organization
                    org = Organization.objects.get(slug=slug)
                    logger.info(f"Found organization: {org.slug} (id={org.id})")
                    node = Node.objects.get(api_token=api_token, organization=org)
                    logger.info(f"Found node: {node.id} (name={node.name}) in organization {org.slug}")
                else:
                    # Fall back to just token if no slug
                    node = Node.objects.get(api_token=api_token)
                    logger.info(f"Found node: {node.id} (name={node.name}) without organization filter")
                    
                logger.info(f"Successfully found node {node.id} (name={node.name}) for token")
                # Attach the node to the request for use in views
                request.node = node
                return (AnonymousUser(), None)
            except Node.DoesNotExist:
                logger.warning(f"No node found with the provided API token")
                return None
            except Organization.DoesNotExist:
                logger.warning(f"No organization found with slug {slug}")
                return None
        except Exception as e:
            logger.error(f"Error in NodeAPITokenAuthentication: {str(e)}")
            logger.error(traceback.format_exc())
            return None 