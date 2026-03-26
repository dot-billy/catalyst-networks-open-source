from rest_framework import mixins, permissions, viewsets
from drf_spectacular.utils import extend_schema

from .models import Organization
from .serializers import OrganizationSerializer
from open_cvpn.response_schemas import ERROR_RESPONSES, SUCCESS_EXAMPLES

@extend_schema(
    summary='List Organizations',
    description='Get a paginated list of organizations that the authenticated user has access to.',
    responses={
        200: {
            'description': 'List of organizations',
            'content': {
                'application/json': {
                    'examples': {
                        'success': SUCCESS_EXAMPLES['organization_list']
                    }
                }
            }
        },
        **ERROR_RESPONSES
    }
)
class OrganizationViewSet(mixins.ListModelMixin, viewsets.GenericViewSet):
    """
    Read-only organization API surface for node-aware clients.

    Administrative organization, membership, and invitation management is
    intentionally handled through the web UI rather than nested DRF routes.
    """

    queryset = Organization.objects.all()
    serializer_class = OrganizationSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'slug'

    def get_queryset(self):
        """Return only organizations the authenticated user belongs to."""
        return self.queryset.filter(memberships__user=self.request.user).distinct()