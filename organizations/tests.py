from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.test import Client, TestCase
from django.urls import reverse
from rest_framework.test import APIRequestFactory

from .access import ORG_MANAGER_ROLES, normalize_roles, require_org_access
from .models import Membership, NetworkRange, Organization
from .permissions import IsOrganizationOwnerOrAdmin

User = get_user_model()


class OrganizationTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(email='owner@example.com', password='testpass')
        self.client.force_login(self.user)
        self.organization = Organization.objects.create(name='Test Organization', created_by=self.user)
        self.membership = Membership.objects.create(
            user=self.user,
            organization=self.organization,
            role='owner',
        )

    def test_organization_list(self):
        response = self.client.get(reverse('organizations:list'))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Organization')

    def test_organization_create(self):
        response = self.client.post(reverse('organizations:create'), {'name': 'New Organization'})
        self.assertEqual(response.status_code, 302)
        self.assertTrue(Organization.objects.filter(name='New Organization').exists())

    def test_organization_detail(self):
        response = self.client.get(reverse('organizations:detail', kwargs={'slug': self.organization.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Test Organization')

    def test_authenticated_shell_uses_two_rail_console(self):
        response = self.client.get(reverse('organizations:detail', kwargs={'slug': self.organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'catalyst-shell-nav')
        self.assertContains(response, 'catalyst-global-rail')
        self.assertContains(response, 'catalyst-workspace-rail')
        self.assertContains(response, 'aria-label="Global navigation"')
        self.assertContains(response, 'aria-label="Organization navigation"')
        self.assertContains(response, 'Current Organization')
        self.assertContains(response, 'Summary')
        self.assertContains(response, 'Nodes')
        self.assertContains(response, 'Groups')
        self.assertContains(response, 'Policies')
        self.assertContains(response, 'Certificates')
        self.assertContains(response, 'Members')
        self.assertContains(response, 'Webhooks')

    def test_organization_detail_uses_command_center_surface(self):
        response = self.client.get(reverse('organizations:detail', kwargs={'slug': self.organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'ops-command-center')
        self.assertContains(response, 'Organization Command Center')
        self.assertContains(response, 'Node Operations')
        self.assertContains(response, 'Access & Invitations')
        self.assertContains(response, 'SSO Settings')

    def test_oss_shell_keeps_oss_navigation_product_specific(self):
        response = self.client.get(reverse('organizations:detail', kwargs={'slug': self.organization.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '/docs/getting-started/')
        self.assertContains(response, 'Documentation')
        self.assertNotContains(response, 'https://docs.catalystnetworks.io/')
        self.assertNotContains(response, 'Licensing')
        self.assertNotContains(response, 'Get Help')
        self.assertNotContains(response, '/support/')

    def test_network_range_add(self):
        response = self.client.post(
            reverse('organizations:network_range', kwargs={'slug': self.organization.slug}),
            {'cidr': '192.168.1.0/24'}
        )
        self.assertEqual(response.status_code, 302)
        self.assertTrue(NetworkRange.objects.filter(cidr='192.168.1.0/24').exists())

    def test_network_range_delete(self):
        network_range = NetworkRange.objects.create(
            organization=self.organization,
            cidr='192.168.1.0/24'
        )
        response = self.client.post(
            reverse('organizations:delete_network_range', kwargs={'slug': self.organization.slug}),
            {'range_id': network_range.id}
        )
        self.assertEqual(response.status_code, 302)
        self.assertFalse(NetworkRange.objects.filter(cidr='192.168.1.0/24').exists())


class OrganizationAccessTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.owner = User.objects.create_user(email='owner@example.com', password='testpass')
        self.admin = User.objects.create_user(email='admin@example.com', password='testpass')
        self.member = User.objects.create_user(email='member@example.com', password='testpass')
        self.outsider = User.objects.create_user(email='outsider@example.com', password='testpass')

        self.organization = Organization.objects.create(name='Access Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        Membership.objects.create(user=self.admin, organization=self.organization, role='admin')
        Membership.objects.create(user=self.member, organization=self.organization, role='member')

    def test_normalize_roles_lowercases_requested_roles(self):
        self.assertEqual(normalize_roles(['Owner', 'ADMIN']), ORG_MANAGER_ROLES)

    def test_require_org_access_allows_member_without_role_filter(self):
        organization = require_org_access(self.member, slug=self.organization.slug)
        self.assertEqual(organization, self.organization)

    def test_require_org_access_denies_member_for_manager_roles(self):
        with self.assertRaises(PermissionDenied):
            require_org_access(self.member, slug=self.organization.slug, required_roles=['Owner', 'Admin'])

    def test_owner_or_admin_permission_uses_related_organization(self):
        permission = IsOrganizationOwnerOrAdmin()
        request = self.factory.patch('/api/org/access-org/nodes/1/')
        request.user = self.admin

        allowed = permission.has_object_permission(
            request,
            SimpleNamespace(action='partial_update'),
            SimpleNamespace(organization=self.organization),
        )

        self.assertTrue(allowed)

    def test_owner_or_admin_permission_denies_non_manager(self):
        permission = IsOrganizationOwnerOrAdmin()
        request = self.factory.patch('/api/org/access-org/nodes/1/')
        request.user = self.member

        allowed = permission.has_object_permission(
            request,
            SimpleNamespace(action='partial_update'),
            SimpleNamespace(organization=self.organization),
        )

        self.assertFalse(allowed)
