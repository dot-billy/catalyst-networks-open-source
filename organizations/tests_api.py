from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APIClient

from .models import Membership, Organization

User = get_user_model()


class OrganizationAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(email='testuser@example.com', password='testpass')
        self.other_user = User.objects.create_user(email='other@example.com', password='testpass')
        self.client.force_authenticate(user=self.user)

        self.organization = Organization.objects.create(name='Test Organization', created_by=self.user)
        Membership.objects.create(user=self.user, organization=self.organization, role='owner')

        self.other_organization = Organization.objects.create(name='Other Organization', created_by=self.other_user)
        Membership.objects.create(user=self.other_user, organization=self.other_organization, role='owner')

    def test_organization_list_returns_only_memberships_for_authenticated_user(self):
        response = self.client.get(reverse('organization-list'))
        results = response.data.get('results', response.data)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['name'], 'Test Organization')

    def test_organization_list_is_read_only(self):
        response = self.client.post(reverse('organization-list'), {'name': 'New Organization'})

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)