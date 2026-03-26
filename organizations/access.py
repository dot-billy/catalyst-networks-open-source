from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404

from .models import Membership, Organization


ORG_MANAGER_ROLES = ("owner", "admin")


def normalize_roles(required_roles=None):
    if not required_roles:
        return ()
    return tuple(role.lower() for role in required_roles)


def get_organization(*, org_id=None, slug=None):
    if org_id is not None:
        return get_object_or_404(Organization, id=org_id)
    if slug is not None:
        return get_object_or_404(Organization, slug=slug)
    raise ValueError("Either org_id or slug must be provided")


def get_membership(user, organization):
    if not getattr(user, "is_authenticated", False):
        return None
    return Membership.objects.filter(user=user, organization=organization).first()


def get_org_role(user, organization):
    membership = get_membership(user, organization)
    return membership.role if membership else None


def user_has_org_access(user, organization, required_roles=None):
    membership = get_membership(user, organization)
    if not membership:
        return False

    normalized_roles = normalize_roles(required_roles)
    if not normalized_roles:
        return True

    return membership.role in normalized_roles


def is_org_manager(user, organization):
    return user_has_org_access(user, organization, ORG_MANAGER_ROLES)


def require_org_access(user, *, org_id=None, slug=None, required_roles=None):
    organization = get_organization(org_id=org_id, slug=slug)
    if not user_has_org_access(user, organization, required_roles):
        raise PermissionDenied("You don't have access to this organization")
    return organization


def get_organization_for_object(obj):
    if isinstance(obj, Organization):
        return obj

    organization = getattr(obj, "organization", None)
    if organization is None:
        raise AttributeError(f"{type(obj).__name__} does not expose an organization")
    return organization
