from rest_framework.exceptions import NotFound
from .models import Organization

class OrganizationFilterMixin:
    """
    Mixin for filtering resources by organization ID or slug.
    
    This mixin filters the queryset to only include resources related to
    the organization specified by either 'org_id', 'organization_slug', or 'slug' URL parameter.
    """
    organization_field = 'organization'
    
    def get_organization(self):
        """
        Get the organization based on the ID or slug from the URL.
        
        Raises:
            NotFound: If the organization does not exist.
        """
        org_id = self.kwargs.get('org_id')
        org_slug = self.kwargs.get('organization_slug') or self.kwargs.get('slug')
        
        if not org_id and not org_slug:
            raise NotFound('Organization ID or slug not provided in URL')
        
        try:
            if org_id:
                organization = Organization.objects.get(id=org_id)
            else:
                organization = Organization.objects.get(slug=org_slug)
            return organization
        except Organization.DoesNotExist:
            identifier = org_id if org_id else org_slug
            raise NotFound(f'Organization with identifier {identifier} does not exist')
    
    def get_queryset(self):
        """
        Filter the queryset by the organization.
        """
        queryset = super().get_queryset()
        organization = self.get_organization()
        
        # Filter by organization
        filter_kwargs = {self.organization_field: organization}
        
        return queryset.filter(**filter_kwargs) 