from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from organizations.models import Membership, Organization
from security_groups.models import Tag


User = get_user_model()


class DashboardTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(email='dashboard-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Dashboard Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')

    def test_dashboard_uses_tag_relation_for_security_policy_count(self):
        Tag.objects.create(name='app-policy', organization=self.organization)
        self.client.force_login(self.owner)

        response = self.client.get(reverse('dashboard:dashboard'))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, '<span>1 security policies</span>', html=True)
