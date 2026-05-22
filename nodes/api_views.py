import logging

from django.utils import timezone
from drf_spectacular.utils import extend_schema
from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.exceptions import NotFound

from open_cvpn.response_schemas import ERROR_RESPONSES, SUCCESS_EXAMPLES
from organizations.models import Organization
from organizations.mixins import OrganizationFilterMixin
from organizations.permissions import IsOrganizationOwnerOrAdmin

from .api_registration import NodeRegistrationView
from .authentication import NodeAPITokenAuthentication
from .models import Node, NodeRegistrationToken
from .permissions import NodeAccessPermission
from .serializers import NodeRegistrationTokenSerializer, NodeSerializer

logger = logging.getLogger(__name__)

class NodeViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing nodes.
    """
    serializer_class = NodeSerializer
    permission_classes = [IsAuthenticated, IsOrganizationOwnerOrAdmin]
    
    def get_queryset(self):
        """
        Filter nodes to only show those from organizations the user is a member of.
        """
        # Ensure user is authenticated before filtering
        if not self.request.user or self.request.user.is_anonymous:
            return Node.objects.none()  # Return empty queryset for unauthenticated users
        return Node.objects.filter(organization__memberships__user=self.request.user)
    
    def get_next_available_ip(self, organization, max_retries=3):
        # Implementation details...
        pass
        
    def perform_create(self, serializer):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['get'])
    def download_cert(self, request, pk=None):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['get'])
    def download_key(self, request, pk=None):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['get'], authentication_classes=[NodeAPITokenAuthentication], permission_classes=[NodeAccessPermission])
    def download_config(self, request, pk=None, **kwargs):
        """
        Download the node's configuration package.
        
        This endpoint returns either a JSON response or a ZIP file containing:
        - The node's certificate
        - The node's private key
        - The CA certificate
        - The node's configuration file
        
        The format can be specified using the 'format' query parameter:
        - format=json (default): Returns a JSON response with all the data
        - format=zip: Returns a ZIP file containing the files
        
        Authentication options:
        - Node API token (for nodes to access their own config)
        - User authentication (for admin access)
        """
        node = self.get_object()
        format_type = request.query_params.get('format', 'json')

        # Generate and return the node package
        reg_view = NodeRegistrationView()
        return reg_view._prepare_node_package(node, format_type)
        
    @extend_schema(
        summary='Renew Node Certificate',
        description='Renew the certificate for a specific node.',
        responses={
            200: {
                'description': 'Certificate renewed successfully',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'message': {'type': 'string', 'example': 'Certificate renewed successfully'},
                                'expiration': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    @action(detail=True, methods=['post'])
    def renew_cert(self, request, pk=None):
        # Implementation details...
        pass
        
    @extend_schema(
        summary='Get Node Security Groups',
        description='Retrieve the security groups assigned to a specific node.',
        responses={
            200: {
                'description': 'Node security groups',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'security_groups': {
                                    'type': 'array',
                                    'items': {'type': 'object'}
                                }
                            }
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    @action(detail=True, methods=['get'])
    def security_groups(self, request, pk=None):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['post']) 
    def assign_security_group(self, request, pk=None):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['post'])
    def remove_security_group(self, request, pk=None):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['post'])
    def direct_assign_security_group(self, request, pk=None):
        # Implementation details...
        pass
        
    @action(detail=True, methods=['post'], authentication_classes=[NodeAPITokenAuthentication], permission_classes=[NodeAccessPermission])
    def checkin(self, request, pk=None):
        """
        Node check-in endpoint. Requires node API token authentication.
        Updates the node's last_checkin timestamp.
        """
        node = self.get_object()
        node.last_checkin = timezone.now()
        node.save(update_fields=['last_checkin'])
        return Response({
            'success': True,
            'last_checkin': node.last_checkin.isoformat()
        })

    def get_object(self):
        """
        Override get_object to allow node API token access.
        If the request has a node attribute (set by NodeAPITokenAuthentication),
        return that node directly without permission checks.
        """
        if hasattr(self.request, 'node') and self.request.node:
            # If authenticated by NodeAPITokenAuthentication, return that node
            # This bypasses permission checks for the node's own resources
            lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field
            node_id = self.kwargs.get(lookup_url_kwarg)
            
            if str(self.request.node.id) == str(node_id):
                # For organization-specific endpoints, verify the node belongs to the correct organization
                if hasattr(self, 'get_organization'):
                    try:
                        org = self.get_organization()
                        if self.request.node.organization.id != org.id:
                            logger.warning("Authenticated node does not belong to requested organization")
                            raise NotFound(f"Node {node_id} not found in organization {org.slug}")
                    except NotFound:
                        raise
                    except Exception as e:
                        logger.error("Error checking organization: %s", e)
                        raise
                return self.request.node
            else:
                logger.warning("Authenticated node attempted to access a different node")
        
        return super().get_object()

class OrgNodeViewSet(OrganizationFilterMixin, NodeViewSet):
    """
    ViewSet for managing nodes within a specific organization.
    
    This ViewSet provides the same functionality as NodeViewSet,
    but filters nodes by the organization specified in the URL.
    """
    
    def get_serializer_class(self):
        """Return the appropriate serializer class."""
        return NodeSerializer
    
    def get_queryset(self):
        """Get queryset with proper error handling for schema generation."""
        try:
            return super().get_queryset()
        except Exception:
            # During schema generation, return empty queryset if there's no proper request context
            return Node.objects.none()
    
    def get_permissions(self):
        """
        Ensure node self-actions are authorized via NodeAccessPermission (node API token),
        while leaving other actions to the default user-based permissions.
        """
        if getattr(self, 'action', None) in ('download_config', 'checkin'):
            return [NodeAccessPermission()]
        return super().get_permissions()

    def get_authenticators(self):
        """
        Allow node API token authentication for self-actions, in addition to defaults.
        """
        if getattr(self, 'action', None) in ('download_config', 'checkin'):
            return [NodeAPITokenAuthentication()]
        return super().get_authenticators()
    
    @extend_schema(
        summary='List Organization Nodes',
        description='Get a paginated list of nodes in the specified organization.',
        responses={
            200: {
                'description': 'List of organization nodes',
                'content': {
                    'application/json': {
                        'examples': {
                            'success': SUCCESS_EXAMPLES['node_list']
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    def list(self, request, *args, **kwargs):
        """List nodes in the organization."""
        return super().list(request, *args, **kwargs)
    
    @extend_schema(
        summary='Create Organization Node',
        description='Create a new node in the specified organization.',
        responses={
            201: {
                'description': 'Node created successfully',
                'content': {
                    'application/json': {
                        'examples': {
                            'success': SUCCESS_EXAMPLES['node_list']
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    def create(self, request, *args, **kwargs):
        """Create a new node in the organization."""
        return super().create(request, *args, **kwargs)
    
    @extend_schema(
        summary='Get Organization Node',
        description='Retrieve details of a specific node in the organization.',
        responses={
            200: {
                'description': 'Node details',
                'content': {
                    'application/json': {
                        'examples': {
                            'success': SUCCESS_EXAMPLES['node_list']
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    def retrieve(self, request, *args, **kwargs):
        """Retrieve a specific node."""
        return super().retrieve(request, *args, **kwargs)
    
    @extend_schema(
        summary='Update Organization Node',
        description='Update a specific node in the organization.',
        responses={
            200: {
                'description': 'Node updated successfully',
                'content': {
                    'application/json': {
                        'examples': {
                            'success': SUCCESS_EXAMPLES['node_list']
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    def update(self, request, *args, **kwargs):
        """Update a specific node."""
        return super().update(request, *args, **kwargs)
    
    @extend_schema(
        summary='Partially Update Organization Node',
        description='Partially update a specific node in the organization.',
        responses={
            200: {
                'description': 'Node updated successfully',
                'content': {
                    'application/json': {
                        'examples': {
                            'success': SUCCESS_EXAMPLES['node_list']
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    def partial_update(self, request, *args, **kwargs):
        """Partially update a specific node."""
        return super().partial_update(request, *args, **kwargs)
    
    @extend_schema(
        summary='Download Node Configuration',
        description='Download the complete configuration package for a specific node.',
        responses={
            200: {
                'description': 'Node configuration package',
                'content': {
                    'application/zip': {
                        'schema': {'type': 'string', 'format': 'binary'}
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    @action(detail=True, methods=['get'], authentication_classes=[NodeAPITokenAuthentication], permission_classes=[NodeAccessPermission])
    def download_config(self, request, pk=None, **kwargs):
        """
        Download node configuration.
        
        This endpoint allows nodes to download their configuration files.
        The format can be specified using the 'format' query parameter:
        - format=json (default): Returns a JSON response with all the data
        - format=zip: Returns a ZIP file containing the files
        
        Authentication options:
        - Node API token (for nodes to access their own config)
        - User authentication (for admin access)
        """
        return super().download_config(request, pk, **kwargs)
        
    @extend_schema(
        summary='Node Check-in',
        description='Update the last check-in timestamp for a specific node.',
        responses={
            200: {
                'description': 'Check-in successful',
                'content': {
                    'application/json': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'message': {'type': 'string', 'example': 'Check-in successful'},
                                'last_checkin': {'type': 'string', 'format': 'date-time'}
                            }
                        }
                    }
                }
            },
            **ERROR_RESPONSES
        }
    )
    @action(detail=True, methods=['post'], authentication_classes=[NodeAPITokenAuthentication], permission_classes=[NodeAccessPermission])
    def checkin(self, request, pk=None):
        """
        Node check-in endpoint. Requires node API token authentication.
        Updates the node's last_checkin timestamp.
        """
        return super().checkin(request, pk)
        
    def get_organization(self):
        """
        Get the organization based on the slug from the URL.
        
        Raises:
            NotFound: If the organization does not exist.
        """
        org_slug = self.kwargs.get('slug')
        
        if not org_slug:
            raise NotFound('Organization slug not provided in URL')
        
        try:
            organization = Organization.objects.get(slug=org_slug)
            return organization
        except Organization.DoesNotExist:
            raise NotFound(f'Organization with slug {org_slug} does not exist')

class TokenViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing registration tokens.
    """
    serializer_class = NodeRegistrationTokenSerializer
    permission_classes = [IsAuthenticated, IsOrganizationOwnerOrAdmin]
    
    def get_queryset(self):
        """
        Filter tokens to only show those from organizations the user is a member of.
        """
        if not self.request.user or self.request.user.is_anonymous:
            return NodeRegistrationToken.objects.none()
        return NodeRegistrationToken.objects.filter(
            organization__memberships__user=self.request.user
        )
    
    def perform_create(self, serializer):
        """
        Set the created_by field to the current user.
        """
        serializer.save(created_by=self.request.user)
    
    @action(detail=True, methods=['post'])
    def revoke(self, request, pk=None):
        """
        Revoke a token.
        """
        token = self.get_object()
        token.is_active = False
        token.save()
        return Response({'status': 'token revoked'})
    
    @action(detail=False, methods=['get'])
    def active(self, request):
        """
        List only active tokens.
        """
        active_tokens = self.get_queryset().filter(
            is_active=True,
            expires_at__gt=timezone.now()
        )
        page = self.paginate_queryset(active_tokens)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)
        
        serializer = self.get_serializer(active_tokens, many=True)
        return Response(serializer.data)

class OrgTokenViewSet(OrganizationFilterMixin, TokenViewSet):
    """
    ViewSet for managing registration tokens within a specific organization.
    
    This ViewSet provides the same functionality as TokenViewSet,
    but filters tokens by the organization specified in the URL.
    """
    def get_organization(self):
        """
        Get the organization based on the slug from the URL.
        
        Raises:
            NotFound: If the organization does not exist.
        """
        org_slug = self.kwargs.get('slug')
        
        if not org_slug:
            raise NotFound('Organization slug not provided in URL')
        
        try:
            organization = Organization.objects.get(slug=org_slug)
            return organization
        except Organization.DoesNotExist:
            raise NotFound(f'Organization with slug {org_slug} does not exist')
