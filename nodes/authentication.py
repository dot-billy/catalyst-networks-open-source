from rest_framework.authentication import BaseAuthentication
from django.contrib.auth.models import AnonymousUser
from .models import Node
import logging

logger = logging.getLogger(__name__)
AUTH_SCHEME = 'bearer'

class NodeAPITokenAuthentication(BaseAuthentication):
    def authenticate(self, request):
        auth_header = request.headers.get('Authorization')
        auth_parts = auth_header.split(None, 1) if auth_header else []
        if len(auth_parts) != 2 or auth_parts[0].lower() != AUTH_SCHEME:
            return None
            
        api_token = auth_parts[1].strip()
        
        try:
            slug = request.parser_context.get('kwargs', {}).get('slug')
            
            if slug:
                try:
                    from organizations.models import Organization
                    org = Organization.objects.get(slug=slug)
                    node = Node.objects.get(api_token=api_token, organization=org)
                except (Organization.DoesNotExist, Node.DoesNotExist):
                    return None
            else:
                try:
                    node = Node.objects.get(api_token=api_token)
                except Node.DoesNotExist:
                    return None

            request.node = node
            return (AnonymousUser(), None)
        except Exception:
            logger.error("NodeAPITokenAuthentication error")
            return None
