from django.contrib.auth import get_user_model
from django.test import Client, TestCase
from django.urls import reverse

from organizations.models import Membership, Organization
from security_groups.models import FirewallRule, SecurityGroup

User = get_user_model()


class OrganizationSecurityGroupListTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(email='owner@example.com', password='testpass')
        self.member = User.objects.create_user(email='member@example.com', password='testpass')

        self.organization = Organization.objects.create(name='Security Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        Membership.objects.create(user=self.member, organization=self.organization, role='member')

    def test_owner_sees_create_policy_call_to_action(self):
        self.client.force_login(self.owner)

        response = self.client.get(
            reverse('security_groups_org:list', kwargs={'slug': self.organization.slug})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Create Policy')

    def test_member_does_not_see_create_policy_call_to_action(self):
        self.client.force_login(self.member)

        response = self.client.get(
            reverse('security_groups_org:list', kwargs={'slug': self.organization.slug})
        )

        self.assertEqual(response.status_code, 200)
        self.assertNotContains(response, 'Create Policy')


class OrganizationSecurityGroupWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(email='owner2@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Workflow Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')

    def test_create_policy_redirects_to_rule_builder(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('security_groups_org:create', kwargs={'slug': self.organization.slug}),
            {
                'name': 'Ingress',
                'description': 'Public entry policy',
            },
        )

        policy = SecurityGroup.objects.get(name='Ingress', organization=self.organization)

        self.assertRedirects(
            response,
            reverse('security_groups_org:add_rule', kwargs={'slug': self.organization.slug, 'sg_id': policy.id}),
        )
        self.assertEqual(policy.firewall_rules.count(), 0)

    def test_create_policy_ignores_legacy_inline_rule_fields(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('security_groups_org:create', kwargs={'slug': self.organization.slug}),
            {
                'name': 'Application',
                'description': 'Application tier',
                'protocol': 'tcp',
                'port_min': '443',
                'port_max': '443',
                'source_cidr': '0.0.0.0/0',
                'rule_description': 'Legacy inline rule',
            },
        )

        policy = SecurityGroup.objects.get(name='Application', organization=self.organization)

        self.assertRedirects(
            response,
            reverse('security_groups_org:add_rule', kwargs={'slug': self.organization.slug, 'sg_id': policy.id}),
        )
        self.assertFalse(FirewallRule.objects.filter(security_group=policy).exists())
