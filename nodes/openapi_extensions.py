"""
OpenAPI extensions for drf-spectacular to support custom authentication classes.
"""
from drf_spectacular.extensions import OpenApiAuthenticationExtension
from drf_spectacular.plumbing import build_bearer_security_scheme_object
from .authentication import NodeAPITokenAuthentication


class NodeAPITokenAuthenticationExtension(OpenApiAuthenticationExtension):
    """
    OpenAPI extension for NodeAPITokenAuthentication.
    
    This allows drf-spectacular to properly document the NodeAPITokenAuthentication
    class in the OpenAPI schema.
    """
    target_class = NodeAPITokenAuthentication
    name = 'NodeAPITokenAuth'
    
    def get_security_definition(self, auto_schema):
        """
        Return the security definition for NodeAPITokenAuthentication.
        
        This creates a Bearer token authentication scheme that can be used
        with node API tokens.
        """
        return build_bearer_security_scheme_object(
            header_name='Authorization',
            token_prefix='Bearer',
            bearer_format='NodeAPIToken'
        )
