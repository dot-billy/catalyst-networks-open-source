from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import Client, TestCase
from django.urls import reverse

from certificates.models import CertificateAuthority
from nodes.models import Node
from organizations.models import Membership, NetworkRange, Organization
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


class OrganizationSecurityPolicyWorkflowTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(email='policy-owner@example.com', password='testpass')
        self.member = User.objects.create_user(email='policy-member@example.com', password='testpass')
        self.foreign_owner = User.objects.create_user(email='foreign-policy-owner@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Policy Org', created_by=self.owner)
        self.foreign_organization = Organization.objects.create(name='Foreign Policy Org', created_by=self.foreign_owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        Membership.objects.create(user=self.member, organization=self.organization, role='member')
        Membership.objects.create(user=self.foreign_owner, organization=self.foreign_organization, role='owner')
        NetworkRange.objects.create(
            organization=self.organization,
            cidr='10.50.0.0/24',
            description='policy test range',
        )
        NetworkRange.objects.create(
            organization=self.foreign_organization,
            cidr='10.51.0.0/24',
            description='foreign policy test range',
        )
        self.source_group = SecurityGroup.objects.create(
            name='Ingress',
            organization=self.organization,
            description='Ingress nodes',
        )
        self.destination_group = SecurityGroup.objects.create(
            name='Application',
            organization=self.organization,
            description='Application nodes',
        )
        self.alternate_destination_group = SecurityGroup.objects.create(
            name='Database',
            organization=self.organization,
            description='Database nodes',
        )
        self.foreign_source_group = SecurityGroup.objects.create(
            name='Foreign Source',
            organization=self.foreign_organization,
            description='Foreign source nodes',
        )
        self.ca = CertificateAuthority.objects.create(
            name='Policy CA',
            organization=self.organization,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('policy-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('policy-ca.key', b'key-bytes'),
        )
        self.foreign_ca = CertificateAuthority.objects.create(
            name='Foreign Policy CA',
            organization=self.foreign_organization,
            created_by=self.foreign_owner,
            ca_cert=SimpleUploadedFile('foreign-policy-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('foreign-policy-ca.key', b'key-bytes'),
        )
        self.source_node = Node.objects.create(
            name='source-host',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.50.0.10',
            created_by=self.owner,
        )
        self.destination_node = Node.objects.create(
            name='destination-host',
            organization=self.organization,
            certificate_authority=self.ca,
            nebula_ip='10.50.0.20',
            created_by=self.owner,
        )
        self.foreign_source_node = Node.objects.create(
            name='foreign-source-host',
            organization=self.foreign_organization,
            certificate_authority=self.foreign_ca,
            nebula_ip='10.51.0.10',
            created_by=self.foreign_owner,
        )

    def test_owner_can_create_source_to_destination_policy(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('security_groups_org:policy_create', kwargs={'slug': self.organization.slug}),
            {
                'source_type': 'group',
                'source_group': [str(self.source_group.id)],
                'dest_type': 'group',
                'dest_group': str(self.destination_group.id),
                'protocol': 'tcp',
                'port_min': '443',
                'port_max': '443',
                'description': 'Allow HTTPS from ingress to application',
            },
        )

        self.assertRedirects(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.organization.slug}),
        )
        rule = FirewallRule.objects.get(security_group=self.destination_group)
        self.assertIsNone(rule.node)
        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.port_min, 443)
        self.assertEqual(rule.port_max, 443)
        self.assertEqual(rule.description, 'Allow HTTPS from ingress to application')
        self.assertQuerySetEqual(rule.source_groups.all(), [self.source_group])
        self.assertFalse(rule.source_nodes.exists())
        self.assertEqual(rule.source_cidr, '')

    def test_member_cannot_create_source_to_destination_policy(self):
        self.client.force_login(self.member)

        response = self.client.post(
            reverse('security_groups_org:policy_create', kwargs={'slug': self.organization.slug}),
            {
                'source_type': 'group',
                'source_group': [str(self.source_group.id)],
                'dest_type': 'group',
                'dest_group': str(self.destination_group.id),
                'protocol': 'tcp',
                'port_min': '443',
            },
        )

        self.assertEqual(response.status_code, 403)
        self.assertFalse(FirewallRule.objects.exists())

    def test_invalid_source_edit_leaves_existing_rule_unchanged(self):
        self.client.force_login(self.owner)
        rule = FirewallRule.objects.create(
            security_group=self.destination_group,
            protocol='tcp',
            port_min=443,
            port_max=443,
            description='Original allow rule',
        )
        rule.source_groups.set([self.source_group])

        response = self.client.post(
            reverse('security_groups_org:policy_edit', kwargs={'slug': self.organization.slug, 'rule_id': rule.id}),
            {
                'source_type': 'host',
                'source_node': str(self.foreign_source_node.id),
                'dest_type': 'group',
                'dest_group': str(self.alternate_destination_group.id),
                'protocol': 'udp',
                'port_min': '53',
                'port_max': '53',
                'description': 'Attempted invalid edit',
            },
        )

        self.assertEqual(response.status_code, 200)
        rule.refresh_from_db()
        self.assertEqual(rule.security_group, self.destination_group)
        self.assertIsNone(rule.node)
        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.port_min, 443)
        self.assertEqual(rule.port_max, 443)
        self.assertEqual(rule.description, 'Original allow rule')
        self.assertQuerySetEqual(rule.source_groups.all(), [self.source_group])
        self.assertFalse(rule.source_nodes.exists())

    def test_mixed_same_org_and_foreign_source_groups_are_rejected(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('security_groups_org:policy_create', kwargs={'slug': self.organization.slug}),
            {
                'source_type': 'group',
                'source_group': [str(self.source_group.id), str(self.foreign_source_group.id)],
                'dest_type': 'group',
                'dest_group': str(self.destination_group.id),
                'protocol': 'tcp',
                'port_min': '443',
                'port_max': '443',
                'description': 'Mixed source groups',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Source group not found in this organization.')
        self.assertFalse(FirewallRule.objects.filter(description='Mixed source groups').exists())

    def test_policy_list_does_not_display_foreign_legacy_sources(self):
        rule = FirewallRule.objects.create(
            security_group=self.destination_group,
            protocol='tcp',
            port_min=443,
            port_max=443,
            description='Malformed legacy source policy',
        )
        rule.source_groups.set([self.source_group, self.foreign_source_group])
        rule.source_nodes.set([self.source_node, self.foreign_source_node])
        self.client.force_login(self.member)

        response = self.client.get(
            reverse('security_groups_org:policy_list', kwargs={'slug': self.organization.slug})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, self.source_group.name)
        self.assertContains(response, self.source_node.name)
        self.assertNotContains(response, self.foreign_source_group.name)
        self.assertNotContains(response, self.foreign_source_node.name)
        self.assertNotContains(response, self.foreign_source_node.nebula_ip)

    def test_member_detail_ui_hides_mutation_controls(self):
        rule = FirewallRule.objects.create(
            security_group=self.destination_group,
            protocol='tcp',
            port_min=443,
            port_max=443,
            description='Member visible rule',
        )
        rule.source_groups.set([self.source_group])
        self.destination_node.security_groups.add(self.destination_group)
        self.client.force_login(self.member)

        response = self.client.get(
            reverse('security_groups_org:detail', kwargs={'slug': self.organization.slug, 'pk': self.destination_group.id})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'All Policies')
        for hidden_text in (
            'Add Rule',
            'New Source Policy',
            'Assign Nodes',
            'Manage Assignments',
            'Edit Policy',
            'Delete Policy',
            'Delete this rule?',
            'Remove this node from the policy?',
        ):
            self.assertNotContains(response, hidden_text)

    def test_owner_can_create_host_to_host_policy(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('security_groups_org:policy_create', kwargs={'slug': self.organization.slug}),
            {
                'source_type': 'host',
                'source_node': str(self.source_node.id),
                'dest_type': 'host',
                'dest_node': str(self.destination_node.id),
                'protocol': 'udp',
                'port_min': '51820',
                'port_max': '51820',
                'description': 'Allow WireGuard host path',
            },
        )

        self.assertRedirects(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.organization.slug}),
        )
        rule = FirewallRule.objects.get(description='Allow WireGuard host path')
        self.assertIsNone(rule.security_group)
        self.assertEqual(rule.node, self.destination_node)
        self.assertEqual(rule.protocol, 'udp')
        self.assertEqual(rule.port_min, 51820)
        self.assertEqual(rule.port_max, 51820)
        self.assertFalse(rule.source_groups.exists())
        self.assertQuerySetEqual(rule.source_nodes.all(), [self.source_node])
