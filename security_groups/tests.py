from unittest import mock

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.test import Client, TestCase
from django.test.utils import CaptureQueriesContext
from django.urls import reverse
from django.utils.html import strip_tags

from certificates.models import CertificateAuthority
from nodes.models import Node
from organizations.models import Membership, NetworkRange, Organization
from security_groups.models import FirewallRule, SecurityGroup, Tag

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

        policy = Tag.objects.get(name='Ingress', organization=self.organization)

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

        policy = Tag.objects.get(name='Application', organization=self.organization)

        self.assertRedirects(
            response,
            reverse('security_groups_org:add_rule', kwargs={'slug': self.organization.slug, 'sg_id': policy.id}),
        )
        self.assertFalse(FirewallRule.objects.filter(security_group=policy).exists())


class GlobalSecurityGroupCreateTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(email='global-owner@example.com', password='testpass')
        self.member = User.objects.create_user(email='global-member@example.com', password='testpass')
        self.outsider = User.objects.create_user(email='global-outsider@example.com', password='testpass')
        self.organization = Organization.objects.create(name='Global Workflow Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.organization, role='owner')
        Membership.objects.create(user=self.member, organization=self.organization, role='member')

    def _post_create(self, user, name='Global Application', **overrides):
        self.client.force_login(user)
        data = {
            'name': name,
            'organization': str(self.organization.id),
            'description': 'Global legacy create path',
            'protocol': 'icmp',
            'port_min': '',
            'port_max': '',
            'source_cidr': '10.0.0.0/8',
            'rule_description': 'Allow ICMP from private networks',
        }
        data.update(overrides)
        return self.client.post(reverse('security_groups:create'), data)

    def test_create_with_initial_cidr_rule_sets_match_type_cidr(self):
        response = self._post_create(self.owner)

        policy = Tag.objects.get(name='Global Application', organization=self.organization)
        self.assertRedirects(response, reverse('security_groups:detail', kwargs={'pk': policy.id}))
        rule = FirewallRule.objects.get(security_group=policy)
        self.assertEqual(rule.source_cidr, '10.0.0.0/8')
        self.assertEqual(rule.match_type, 'cidr')
        self.assertQuerySetEqual(rule.target_groups.all(), [policy])

    def test_member_cannot_use_flat_create_for_org_policy(self):
        response = self._post_create(self.member, name='Member Created Policy')

        self.assertIn(response.status_code, (302, 403))
        self.assertFalse(Tag.objects.filter(name='Member Created Policy').exists())
        self.assertFalse(FirewallRule.objects.exists())

    def test_outsider_cannot_use_flat_create_with_known_org_id(self):
        response = self._post_create(self.outsider, name='Outsider Created Policy')

        self.assertIn(response.status_code, (302, 403))
        self.assertFalse(Tag.objects.filter(name='Outsider Created Policy').exists())
        self.assertFalse(FirewallRule.objects.exists())

    def test_invalid_initial_rule_rolls_back_created_tag(self):
        self.client.raise_request_exception = False

        response = self._post_create(
            self.owner,
            name='Invalid Rule Policy',
            protocol='tcp',
            port_min='9000',
            port_max='80',
            source_cidr='10.0.0.0/8',
        )

        self.assertGreaterEqual(response.status_code, 400)
        self.assertFalse(Tag.objects.filter(name='Invalid Rule Policy').exists())
        self.assertFalse(FirewallRule.objects.filter(description='Allow ICMP from private networks').exists())


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
        self.assertEqual(rule.match_type, 'groups')
        self.assertQuerySetEqual(rule.target_groups.all(), [self.destination_group])

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

    def test_policy_create_rejects_malformed_source_type_with_cidr_without_creating_rule(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse('security_groups_org:policy_create', kwargs={'slug': self.organization.slug}),
            {
                'source_type': 'bogus',
                'source_cidr': '10.0.0.0/8',
                'dest_type': 'group',
                'dest_group': str(self.destination_group.id),
                'protocol': 'tcp',
                'port_min': '443',
                'port_max': '443',
                'description': 'Malformed source type create',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Choose a valid source type.')
        self.assertFalse(FirewallRule.objects.filter(description='Malformed source type create').exists())

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

    def test_legacy_add_rejects_foreign_source_group_without_creating_rule(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse(
                'security_groups_org:add_rule',
                kwargs={'slug': self.organization.slug, 'sg_id': self.destination_group.id},
            ),
            {
                'source_type': 'group',
                'source_group': [str(self.foreign_source_group.id)],
                'protocol': 'tcp',
                'port': '443',
                'description': 'Foreign legacy add attempt',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Source group not found in this organization.')
        self.assertFalse(FirewallRule.objects.filter(description='Foreign legacy add attempt').exists())

    def test_legacy_add_rejects_malformed_source_type_with_cidr_without_creating_rule(self):
        self.client.force_login(self.owner)

        response = self.client.post(
            reverse(
                'security_groups_org:add_rule',
                kwargs={'slug': self.organization.slug, 'sg_id': self.destination_group.id},
            ),
            {
                'source_type': 'bogus',
                'source_cidr': '10.0.0.0/8',
                'protocol': 'tcp',
                'port': '443',
                'description': 'Malformed legacy add source',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Choose a valid source type.')
        self.assertFalse(FirewallRule.objects.filter(description='Malformed legacy add source').exists())

    def test_legacy_edit_rejects_foreign_source_node_without_mutating_rule(self):
        self.client.force_login(self.owner)
        rule = FirewallRule.objects.create(
            security_group=self.destination_group,
            protocol='tcp',
            port_min=443,
            port_max=443,
            description='Original legacy rule',
            match_type='groups',
        )
        rule.source_groups.set([self.source_group])

        response = self.client.post(
            reverse(
                'security_groups_org:edit_rule',
                kwargs={
                    'slug': self.organization.slug,
                    'sg_id': self.destination_group.id,
                    'rule_id': rule.id,
                },
            ),
            {
                'source_type': 'host',
                'source_node': str(self.foreign_source_node.id),
                'protocol': 'udp',
                'port_min': '53',
                'port_max': '53',
                'description': 'Invalid legacy edit',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Source host not found in this organization.')
        rule.refresh_from_db()
        self.assertEqual(rule.security_group, self.destination_group)
        self.assertIsNone(rule.node)
        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.port_min, 443)
        self.assertEqual(rule.port_max, 443)
        self.assertEqual(rule.description, 'Original legacy rule')
        self.assertEqual(rule.match_type, 'groups')
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
        self.assertEqual(rule.match_type, 'host')
        self.assertFalse(rule.target_groups.exists())

    def test_policy_edit_get_preserves_legacy_node_destination_form(self):
        self.client.force_login(self.owner)
        rule = FirewallRule.objects.create(
            node=self.destination_node,
            protocol='udp',
            port_min=51820,
            port_max=51820,
            description='Legacy host destination policy',
            match_type='host',
        )
        rule.source_nodes.set([self.source_node])

        response = self.client.get(
            reverse('security_groups_org:policy_edit', kwargs={'slug': self.organization.slug, 'rule_id': rule.id})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Edit Policy')
        self.assertContains(response, 'name="dest_type" value="host" checked')
        self.assertContains(response, f'value="{self.destination_node.id}" selected')
        self.assertContains(response, f'value="{self.source_node.id}" selected')
        self.assertContains(response, 'name="source_type" value="host" checked')

    def test_policy_edit_post_preserves_legacy_node_destination(self):
        self.client.force_login(self.owner)
        rule = FirewallRule.objects.create(
            node=self.destination_node,
            protocol='udp',
            port_min=51820,
            port_max=51820,
            description='Legacy host destination policy',
            match_type='host',
        )
        rule.source_nodes.set([self.source_node])

        response = self.client.post(
            reverse('security_groups_org:policy_edit', kwargs={'slug': self.organization.slug, 'rule_id': rule.id}),
            {
                'source_type': 'host',
                'source_node': str(self.source_node.id),
                'dest_type': 'host',
                'dest_node': str(self.destination_node.id),
                'protocol': 'tcp',
                'port_min': '8443',
                'port_max': '8443',
                'description': 'Updated host destination policy',
            },
        )

        self.assertRedirects(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.organization.slug}),
        )
        rule.refresh_from_db()
        self.assertEqual(rule.node, self.destination_node)
        self.assertIsNone(rule.security_group)
        self.assertFalse(rule.target_groups.exists())
        self.assertEqual(rule.match_type, 'host')
        self.assertQuerySetEqual(rule.source_nodes.all(), [self.source_node])
        self.assertFalse(rule.source_groups.exists())
        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.port_min, 8443)
        self.assertEqual(rule.port_max, 8443)
        self.assertEqual(rule.description, 'Updated host destination policy')

    def test_policy_edit_legacy_node_destination_rejects_malformed_source_type_with_cidr(self):
        self.client.force_login(self.owner)
        rule = FirewallRule.objects.create(
            node=self.destination_node,
            protocol='udp',
            port_min=51820,
            port_max=51820,
            description='Original node destination policy',
            match_type='host',
        )
        rule.source_nodes.set([self.source_node])

        response = self.client.post(
            reverse('security_groups_org:policy_edit', kwargs={'slug': self.organization.slug, 'rule_id': rule.id}),
            {
                'source_type': 'bogus',
                'source_cidr': '10.0.0.0/8',
                'dest_type': 'host',
                'dest_node': str(self.destination_node.id),
                'protocol': 'tcp',
                'port_min': '8443',
                'port_max': '8443',
                'description': 'Malformed node destination edit',
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Choose a valid source type.')
        rule.refresh_from_db()
        self.assertEqual(rule.node, self.destination_node)
        self.assertIsNone(rule.security_group)
        self.assertFalse(rule.target_groups.exists())
        self.assertEqual(rule.match_type, 'host')
        self.assertQuerySetEqual(rule.source_nodes.all(), [self.source_node])
        self.assertFalse(rule.source_groups.exists())
        self.assertEqual(rule.protocol, 'udp')
        self.assertEqual(rule.port_min, 51820)
        self.assertEqual(rule.port_max, 51820)
        self.assertEqual(rule.description, 'Original node destination policy')

    def test_list_scopes_to_org(self):
        FirewallRule.objects.create(
            security_group=self.destination_group,
            protocol='any',
            description='visible-local-policy',
        )
        other_org = Organization.objects.create(name='Other', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=other_org, role='owner')
        other_group = SecurityGroup.objects.create(name='other', organization=other_org)
        FirewallRule.objects.create(security_group=other_group, protocol='any', description='leak-check')

        self.client.force_login(self.owner)
        response = self.client.get(
            reverse('security_groups_org:policy_list', kwargs={'slug': self.organization.slug})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'visible-local-policy')
        self.assertNotContains(response, 'leak-check')

class AssignNodesPickerTests(TestCase):
    def setUp(self):
        self.client = Client()
        self.owner = User.objects.create_user(email='oss-picker-owner@example.com', password='testpass')
        self.org = Organization.objects.create(name='Picker Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(
            organization=self.org, cidr='10.60.0.0/24', description='picker range',
        )
        self.ca = CertificateAuthority.objects.create(
            name='Picker CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('picker-ca.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile('picker-ca.key', b'key-bytes'),
        )
        self.group = SecurityGroup.objects.create(name='app-servers', organization=self.org)
        self.lighthouse = Node.objects.create(
            name='core-lighthouse', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.60.0.1', is_lighthouse=True, created_by=self.owner,
        )
        self.web = Node.objects.create(
            name='web-01', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.60.0.10', created_by=self.owner,
        )
        self.db = Node.objects.create(
            name='db-01', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.60.0.11', created_by=self.owner,
        )
        self.group.nodes.add(self.web)
        self.client.force_login(self.owner)

    def _url(self):
        return reverse(
            'security_groups_org:assign_nodes',
            kwargs={'slug': self.org.slug, 'sg_id': self.group.id},
        )

    def test_get_renders_picker_toolbar(self):
        resp = self.client.get(self._url())
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Search nodes by name or IP')
        self.assertContains(resp, 'ui-node-picker-chip')
        self.assertContains(resp, "filter = 'all'")
        self.assertContains(resp, "filter = 'assigned'")
        self.assertContains(resp, "filter = 'lighthouse'")
        self.assertContains(resp, "filter = 'standard'")
        self.assertContains(resp, 'selectAll(true)')
        self.assertContains(resp, 'selectAll(false)')
        self.assertContains(resp, 'of 3 selected')
        self.assertContains(resp, 'value="%d"' % self.lighthouse.id)
        self.assertContains(resp, 'value="%d"' % self.web.id)
        self.assertContains(resp, 'value="%d"' % self.db.id)
        self.assertContains(resp, 'ui-node-picker')
        self.assertNotContains(resp, 'ui-selection-row')

    def test_get_prechecks_assigned_nodes(self):
        resp = self.client.get(self._url())
        self.assertContains(resp, 'value="%d" checked' % self.web.id)
        self.assertNotContains(resp, 'value="%d" checked' % self.db.id)

    def test_post_sets_membership_exactly(self):
        resp = self.client.post(self._url(), {'nodes': [self.lighthouse.id, self.db.id]})
        self.assertRedirects(
            resp,
            reverse('security_groups_org:detail', kwargs={'slug': self.org.slug, 'pk': self.group.id}),
        )
        self.assertEqual(
            set(self.group.nodes.values_list('id', flat=True)),
            {self.lighthouse.id, self.db.id},
        )


class BackfillTests(TestCase):
    def test_legacy_group_rule_backfills_target_and_match_type(self):
        from organizations.models import Organization
        from security_groups.models import Tag, FirewallRule
        owner = User.objects.create_user(email='bf@example.com', password='pw')
        org = Organization.objects.create(name='Backfill Org', created_by=owner)
        tag = Tag.objects.create(name='web', organization=org)
        src = Tag.objects.create(name='src', organization=org)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=80, port_max=80)
        rule.save()
        rule.source_groups.add(src)
        # Simulate the data migration's effect by calling its helper directly:
        from security_groups.migrations import _backfill_helpers as h  # created in Step 3
        h.backfill_rule(rule)
        rule.refresh_from_db()
        self.assertIn(tag, rule.target_groups.all())
        self.assertEqual(rule.match_type, 'groups')
        self.assertEqual(rule.direction, 'in')

    def test_legacy_node_rule_backfills_match_type_host(self):
        from organizations.models import Organization, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag, FirewallRule
        from security_groups.migrations import _backfill_helpers as h
        owner = User.objects.create_user(email='bf-node@example.com', password='pw')
        org = Organization.objects.create(name='BF Node Org', created_by=owner)
        NetworkRange.objects.create(organization=org, cidr='10.60.0.0/24', description='r')
        ca = CertificateAuthority.objects.create(
            name='CA', organization=org, created_by=owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        peer = Node.objects.create(name='peer', organization=org, certificate_authority=ca,
                                   nebula_ip='10.60.0.10', external_port=4242, created_by=owner)
        tag = Tag.objects.create(name='t', organization=org)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=80, port_max=80)
        rule.save()
        rule.source_nodes.add(peer)
        h.backfill_rule(rule)
        rule.refresh_from_db()
        self.assertIn(tag, rule.target_groups.all())
        self.assertEqual(rule.match_type, 'host')

    def test_legacy_cidr_rule_backfills_match_type_cidr(self):
        from organizations.models import Organization
        from security_groups.models import Tag, FirewallRule
        from security_groups.migrations import _backfill_helpers as h
        owner = User.objects.create_user(email='bf-cidr@example.com', password='pw')
        org = Organization.objects.create(name='BF Cidr Org', created_by=owner)
        tag = Tag.objects.create(name='t', organization=org)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=80, port_max=80,
                            source_cidr='10.0.0.0/8')
        rule.save()
        h.backfill_rule(rule)
        rule.refresh_from_db()
        self.assertIn(tag, rule.target_groups.all())
        self.assertEqual(rule.match_type, 'cidr')

    def test_legacy_sourceless_rule_backfills_match_type_any(self):
        from organizations.models import Organization
        from security_groups.models import Tag, FirewallRule
        from security_groups.migrations import _backfill_helpers as h
        owner = User.objects.create_user(email='bf-any@example.com', password='pw')
        org = Organization.objects.create(name='BF Any Org', created_by=owner)
        tag = Tag.objects.create(name='t', organization=org)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=80, port_max=80)
        rule.save()  # no source
        h.backfill_rule(rule)
        rule.refresh_from_db()
        self.assertEqual(rule.match_type, 'any')

    def test_backfill_is_idempotent(self):
        from organizations.models import Organization
        from security_groups.models import Tag, FirewallRule
        from security_groups.migrations import _backfill_helpers as h
        owner = User.objects.create_user(email='bf-idem@example.com', password='pw')
        org = Organization.objects.create(name='BF Idem Org', created_by=owner)
        tag = Tag.objects.create(name='t', organization=org)
        src = Tag.objects.create(name='src', organization=org)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=80, port_max=80)
        rule.save()
        rule.source_groups.add(src)
        h.backfill_rule(rule)
        h.backfill_rule(rule)  # second run must not duplicate or error
        rule.refresh_from_db()
        self.assertEqual(list(rule.target_groups.all()), [tag])
        self.assertEqual(rule.match_type, 'groups')


class FirewallRuleNewFieldsTests(TestCase):
    def setUp(self):
        from organizations.models import Organization
        self.owner = User.objects.create_user(email='fr-fields@example.com', password='pw')
        self.org = Organization.objects.create(name='FR Fields Org', created_by=self.owner)

    def test_rule_defaults_to_inbound(self):
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='web', organization=self.org)
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=443, port_max=443)
        rule.save()
        rule.target_groups.add(tag)
        self.assertEqual(rule.direction, 'in')
        self.assertIn(tag, rule.target_groups.all())

    def test_tag_has_color_field(self):
        from security_groups.models import Tag
        tag = Tag.objects.create(name='db', organization=self.org, color='#22c55e')
        self.assertEqual(tag.color, '#22c55e')

    def test_target_group_only_rule_has_stable_string(self):
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='api', organization=self.org)
        rule = FirewallRule(
            security_group=tag,
            protocol='tcp',
            port_min=8443,
            port_max=8443,
            match_type='any',
        )
        rule.save()
        rule.target_groups.add(tag)
        rule.security_group = None
        rule.save()

        self.assertIn('api', str(rule))
        self.assertIn('TCP port 8443', str(rule))


class NavLabelTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership
        self.client = Client()
        self.owner = User.objects.create_user(email='nav@example.com', password='pw')
        self.org = Organization.objects.create(name='Nav Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        self.client.force_login(self.owner)

    def _anchor_text_for(self, response, href):
        html = response.content.decode()
        href_marker = f'href="{href}"'
        href_index = html.index(href_marker)
        anchor_start = html.rfind('<a ', 0, href_index)
        anchor_end = html.index('</a>', href_index) + len('</a>')
        return ' '.join(strip_tags(html[anchor_start:anchor_end]).split())

    def test_sidebar_uses_tags_and_rules_labels(self):
        response = self.client.get(reverse('security_groups_org:list', kwargs={'slug': self.org.slug}))
        self.assertEqual(response.status_code, 200)
        tags_text = self._anchor_text_for(
            response,
            reverse('security_groups_org:list', kwargs={'slug': self.org.slug}),
        )
        rules_text = self._anchor_text_for(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.org.slug}),
        )
        self.assertEqual(tags_text, 'Tags')
        self.assertEqual(rules_text, 'Rules')
        self.assertNotEqual(tags_text, 'Groups')
        self.assertNotEqual(rules_text, 'Policies')


class SummarizeTagTests(TestCase):
    def setUp(self):
        from organizations.models import Organization
        self.owner = User.objects.create_user(email='sum@example.com', password='pw')
        self.org = Organization.objects.create(name='Sum Org', created_by=self.owner)

    def _tag(self, name):
        from security_groups.models import Tag
        return Tag.objects.create(name=name, organization=self.org)

    def _rule(self, target, *, direction='in', match_type='any', protocol='tcp',
              port=None, port_max=None, source_cidr='', source_groups=(), source_nodes=()):
        from security_groups.models import FirewallRule
        r = FirewallRule(security_group=target, direction=direction, match_type=match_type,
                         protocol=protocol, port_min=port, port_max=(port_max if port_max is not None else port),
                         source_cidr=source_cidr)
        r.save()
        r.target_groups.add(target)
        r.security_group = None
        r.save()
        for g in source_groups:
            r.source_groups.add(g)
        for n in source_nodes:
            r.source_nodes.add(n)
        return r

    def test_no_rules_returns_placeholder(self):
        from security_groups.summaries import summarize_tag
        self.assertEqual(summarize_tag(self._tag('empty')), 'No rules yet.')

    def test_inbound_ssh_from_a_tag(self):
        from security_groups.summaries import summarize_tag
        web = self._tag('web')
        admin = self._tag('admin')
        self._rule(web, match_type='groups', protocol='tcp', port=22, source_groups=[admin])
        self.assertEqual(summarize_tag(web), 'Accepts SSH from tag admin.')

    def test_inbound_https_from_anywhere(self):
        from security_groups.summaries import summarize_tag
        web = self._tag('web')
        self._rule(web, match_type='any', protocol='tcp', port=443)
        self.assertEqual(summarize_tag(web), 'Accepts HTTPS from anywhere.')

    def test_inbound_cidr_source_uses_well_known_name(self):
        from security_groups.summaries import summarize_tag
        db = self._tag('db')
        self._rule(db, match_type='cidr', protocol='tcp', port=5432, source_cidr='10.0.0.0/8')
        self.assertEqual(summarize_tag(db), 'Accepts PostgreSQL from 10.0.0.0/8.')

    def test_port_range_and_unknown_port_fall_back_to_proto_port(self):
        from security_groups.summaries import summarize_tag
        app = self._tag('app')
        self._rule(app, match_type='any', protocol='tcp', port=8000, port_max=8100)
        self.assertEqual(summarize_tag(app), 'Accepts TCP/8000-8100 from anywhere.')

    def test_outbound_rule_renders_sends(self):
        from security_groups.summaries import summarize_tag
        web = self._tag('web')
        self._rule(web, direction='out', match_type='cidr', protocol='tcp', port=443, source_cidr='10.0.0.0/8')
        self.assertEqual(summarize_tag(web), 'Sends HTTPS to 10.0.0.0/8.')

    def test_inbound_and_outbound_combined(self):
        from security_groups.summaries import summarize_tag
        web = self._tag('web')
        self._rule(web, match_type='any', protocol='tcp', port=443)
        self._rule(web, direction='out', match_type='any', protocol='any')
        self.assertEqual(summarize_tag(web), 'Accepts HTTPS from anywhere. Sends all traffic to anywhere.')


class TagListSummaryTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership
        from security_groups.models import Tag, FirewallRule
        self.client = Client()
        self.owner = User.objects.create_user(email='list-sum@example.com', password='pw')
        self.org = Organization.objects.create(name='List Sum Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        self.web = Tag.objects.create(name='web', organization=self.org)
        r = FirewallRule(security_group=self.web, direction='in', match_type='any', protocol='tcp', port_min=443, port_max=443)
        r.save(); r.target_groups.add(self.web); r.security_group = None; r.save()
        self.client.force_login(self.owner)

    def test_list_page_shows_tag_summary(self):
        response = self.client.get(reverse('security_groups_org:list', kwargs={'slug': self.org.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Accepts HTTPS from anywhere.')
        self.assertContains(response, '1 rules')

    def test_list_summaries_do_not_query_organization_per_tag(self):
        from security_groups.models import Tag, FirewallRule
        for index in range(3):
            tag = Tag.objects.create(name=f'web-{index}', organization=self.org)
            rule = FirewallRule(security_group=tag, direction='in', match_type='any', protocol='tcp', port_min=443, port_max=443)
            rule.save(); rule.target_groups.add(tag); rule.security_group = None; rule.save()

        with CaptureQueriesContext(connection) as queries:
            response = self.client.get(reverse('security_groups_org:list', kwargs={'slug': self.org.slug}))

        self.assertEqual(response.status_code, 200)
        organization_selects = [
            query['sql']
            for query in queries.captured_queries
            if 'FROM "organizations_organization"' in query['sql']
        ]
        self.assertLessEqual(len(organization_selects), 2, organization_selects)


class TagDetailSummaryTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership
        from security_groups.models import Tag, FirewallRule
        self.client = Client()
        self.owner = User.objects.create_user(email='detail-sum@example.com', password='pw')
        self.foreign_owner = User.objects.create_user(email='foreign-detail-sum@example.com', password='pw')
        self.org = Organization.objects.create(name='Detail Sum Org', created_by=self.owner)
        self.foreign_org = Organization.objects.create(name='Foreign Detail Sum Org', created_by=self.foreign_owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        self.admin_tag = Tag.objects.create(name='admin', organization=self.org)
        self.web = Tag.objects.create(name='web', organization=self.org)
        r = FirewallRule(security_group=self.web, direction='in', match_type='groups', protocol='tcp', port_min=22, port_max=22, description='ssh from admin')
        r.save(); r.target_groups.add(self.web); r.security_group = None; r.save()
        r.source_groups.add(self.admin_tag)
        self.rule = r
        self.client.force_login(self.owner)

    def test_detail_page_shows_tag_summary(self):
        response = self.client.get(reverse('security_groups_org:detail', kwargs={'slug': self.org.slug, 'pk': self.web.id}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Accepts SSH from tag admin.')
        self.assertContains(response, '1 rules')
        self.assertContains(response, 'ssh from admin')

    def test_target_group_only_rule_detail_actions_work(self):
        edit_url = reverse(
            'security_groups_org:edit_rule',
            kwargs={'slug': self.org.slug, 'sg_id': self.web.id, 'rule_id': self.rule.id},
        )
        delete_url = reverse(
            'security_groups_org:delete_rule',
            kwargs={'slug': self.org.slug, 'sg_id': self.web.id, 'rule_id': self.rule.id},
        )

        edit_response = self.client.get(edit_url)
        self.assertEqual(edit_response.status_code, 200)

        delete_response = self.client.post(delete_url)
        self.assertRedirects(
            delete_response,
            reverse('security_groups_org:detail', kwargs={'slug': self.org.slug, 'pk': self.web.id}),
        )
        self.assertFalse(FirewallRule.objects.filter(id=self.rule.id).exists())

    def test_rendered_summary_hides_foreign_source_names(self):
        local_host = self._node('local-node', self.org, self.owner, '10.70.0.10')
        foreign_host = self._node('foreign-node', self.foreign_org, self.foreign_owner, '10.71.0.10')
        foreign_tag = Tag.objects.create(name='foreign-src', organization=self.foreign_org)
        local_tag = Tag.objects.create(name='local-src', organization=self.org)

        group_rule = FirewallRule(security_group=self.web, direction='in', match_type='groups', protocol='tcp', port_min=443, port_max=443)
        group_rule.save(); group_rule.target_groups.add(self.web); group_rule.security_group = None; group_rule.save()
        group_rule.source_groups.add(local_tag, foreign_tag)

        host_rule = FirewallRule(security_group=self.web, direction='in', match_type='host', protocol='tcp', port_min=8443, port_max=8443)
        host_rule.save(); host_rule.target_groups.add(self.web); host_rule.security_group = None; host_rule.save()
        host_rule.source_nodes.add(local_host, foreign_host)

        response = self.client.get(reverse('security_groups_org:detail', kwargs={'slug': self.org.slug, 'pk': self.web.id}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'local-src')
        self.assertContains(response, 'local-node')
        self.assertNotContains(response, 'foreign-src')
        self.assertNotContains(response, 'foreign-node')

    def _node(self, name, org, owner, ip):
        NetworkRange.objects.get_or_create(
            organization=org,
            cidr=f"{'.'.join(ip.split('.')[:2])}.0.0/16",
            defaults={'description': f'{name} test range'},
        )
        ca = CertificateAuthority.objects.create(
            name=f'{name} CA',
            organization=org,
            created_by=owner,
            ca_cert=SimpleUploadedFile(f'{name}.crt', b'certificate-bytes'),
            ca_key=SimpleUploadedFile(f'{name}.key', b'key-bytes'),
        )
        return Node.objects.create(
            name=name,
            organization=org,
            certificate_authority=ca,
            nebula_ip=ip,
            created_by=owner,
        )


class NodeTagMatrixViewTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='matrix@example.com', password='pw')
        self.org = Organization.objects.create(name='Matrix Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.80.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.node1 = Node.objects.create(name='node-1', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.80.0.10', external_port=4242, created_by=self.owner)
        self.node2 = Node.objects.create(name='node-2', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.80.0.11', external_port=4242, created_by=self.owner)
        self.tagA = Tag.objects.create(name='alpha', organization=self.org)
        self.tagB = Tag.objects.create(name='bravo', organization=self.org)
        self.node1.tags.add(self.tagA)
        self.client.force_login(self.owner)

    def test_matrix_renders_nodes_tags_and_membership(self):
        response = self.client.get(reverse('security_groups_org:matrix', kwargs={'slug': self.org.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'node-1')
        self.assertContains(response, 'alpha')
        nodes_by_id = {n.id: n for n in response.context['nodes']}
        self.assertIn(self.tagA.id, nodes_by_id[self.node1.id].tag_id_set)
        self.assertNotIn(self.tagB.id, nodes_by_id[self.node1.id].tag_id_set)
        self.assertEqual(nodes_by_id[self.node2.id].tag_id_set, set())


class NodeTagMatrixApplyTests(TestCase):
    def setUp(self):
        import json
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.json = json
        self.client = Client()
        self.owner = User.objects.create_user(email='apply@example.com', password='pw')
        self.org = Organization.objects.create(name='Apply Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.81.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.node1 = Node.objects.create(name='n1', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.81.0.10', external_port=4242, created_by=self.owner)
        self.node2 = Node.objects.create(name='n2', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.81.0.11', external_port=4242, created_by=self.owner)
        self.tagA = Tag.objects.create(name='alpha', organization=self.org)
        self.tagB = Tag.objects.create(name='bravo', organization=self.org)
        self.node1.tags.add(self.tagA)
        # a foreign org's tag, to test org-scoping
        self.other_org = Organization.objects.create(name='Other', created_by=self.owner)
        self.foreign_tag = Tag.objects.create(name='foreign', organization=self.other_org)
        self.client.force_login(self.owner)
        self.url = reverse('security_groups_org:matrix_apply', kwargs={'slug': self.org.slug})

    def test_apply_adds_and_removes(self):
        changes = self.json.dumps([
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.tagA.id, 'op': 'remove'},
        ])
        response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 200)
        self.node1.refresh_from_db()
        ids = set(self.node1.tags.values_list('id', flat=True))
        self.assertIn(self.tagB.id, ids)
        self.assertNotIn(self.tagA.id, ids)

    def test_apply_rejects_non_list_json_without_mutating(self):
        self.client.raise_request_exception = False
        changes = self.json.dumps({'node': self.node1.id})
        response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.tagA.id, set(self.node1.tags.values_list('id', flat=True)))
        self.assertNotIn(self.tagB.id, set(self.node1.tags.values_list('id', flat=True)))

    def test_apply_rejects_non_object_item_without_mutating(self):
        self.client.raise_request_exception = False
        changes = self.json.dumps([42])
        response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 400)
        self.assertIn(self.tagA.id, set(self.node1.tags.values_list('id', flat=True)))
        self.assertNotIn(self.tagB.id, set(self.node1.tags.values_list('id', flat=True)))

    def test_apply_rejects_foreign_tag_without_mutating(self):
        changes = self.json.dumps([{'node': self.node1.id, 'tag': self.foreign_tag.id, 'op': 'add'}])
        response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(self.foreign_tag.id, set(self.node1.tags.values_list('id', flat=True)))

    def test_apply_rejects_mixed_invalid_batch_without_mutation_or_renewal(self):
        from unittest.mock import patch
        changes = self.json.dumps([
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.foreign_tag.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.tagA.id, 'op': 'toggle'},
        ])
        with patch('security_groups.views.renew_node_certificate') as mock_task:
            response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 400)
        self.assertFalse(mock_task.delay.called)
        ids = set(self.node1.tags.values_list('id', flat=True))
        self.assertIn(self.tagA.id, ids)
        self.assertNotIn(self.tagB.id, ids)

    def test_apply_no_net_changes_do_not_mutate_or_renew(self):
        from unittest.mock import patch
        changes = self.json.dumps([
            {'node': self.node1.id, 'tag': self.tagA.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'remove'},
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'remove'},
        ])
        with patch('security_groups.views.renew_node_certificate') as mock_task:
            response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 200)
        self.assertFalse(mock_task.delay.called)
        ids = set(self.node1.tags.values_list('id', flat=True))
        self.assertIn(self.tagA.id, ids)
        self.assertNotIn(self.tagB.id, ids)

    def test_apply_conflicting_changes_use_final_state_and_renew_only_changed_nodes(self):
        from unittest.mock import patch
        changes = self.json.dumps([
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'remove'},
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'},
            {'node': self.node2.id, 'tag': self.tagB.id, 'op': 'add'},
            {'node': self.node2.id, 'tag': self.tagB.id, 'op': 'remove'},
        ])
        with patch('security_groups.views.renew_node_certificate') as mock_task:
            response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 200)
        self.assertIn(self.tagB.id, set(self.node1.tags.values_list('id', flat=True)))
        self.assertNotIn(self.tagB.id, set(self.node2.tags.values_list('id', flat=True)))
        self.assertEqual(mock_task.delay.call_count, 1)
        self.assertEqual(mock_task.delay.call_args.args, (self.node1.id,))

    def test_apply_rejects_non_admin(self):
        # check_org_access raises PermissionDenied for an insufficient-role member → 403.
        viewer = User.objects.create_user(email='viewer@example.com', password='pw')
        from organizations.models import Membership
        Membership.objects.create(user=viewer, organization=self.org, role='viewer')
        self.client.force_login(viewer)
        changes = self.json.dumps([{'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'}])
        response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(self.tagB.id, set(self.node1.tags.values_list('id', flat=True)))

    def test_apply_rejects_non_member_idor(self):
        # A user with NO membership in this org must be denied access (IDOR guard).
        # check_org_access raises PermissionDenied for a non-member → 403.
        outsider = User.objects.create_user(email='outsider@example.com', password='pw')
        self.client.force_login(outsider)
        changes = self.json.dumps([{'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'}])
        response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 403)
        self.assertNotIn(self.tagB.id, set(self.node1.tags.values_list('id', flat=True)))

    def test_apply_bad_json_returns_400(self):
        # Malformed JSON in the changes field must return 400, not 200.
        response = self.client.post(self.url, {'changes': 'not-valid-json{'})
        self.assertEqual(response.status_code, 400)
        # No membership changes must have occurred.
        self.assertIn(self.tagA.id, set(self.node1.tags.values_list('id', flat=True)))


class NodeTagMatrixResignTests(TestCase):
    def setUp(self):
        import json
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.json = json
        self.client = Client()
        self.owner = User.objects.create_user(email='resign@example.com', password='pw')
        self.org = Organization.objects.create(name='Resign Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.82.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.node1 = Node.objects.create(name='n1', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.82.0.10', external_port=4242, created_by=self.owner)
        self.node2 = Node.objects.create(name='n2', organization=self.org, certificate_authority=self.ca,
            nebula_ip='10.82.0.11', external_port=4242, created_by=self.owner)
        self.tagA = Tag.objects.create(name='alpha', organization=self.org)
        self.tagB = Tag.objects.create(name='bravo', organization=self.org)
        self.client.force_login(self.owner)
        self.url = reverse('security_groups_org:matrix_apply', kwargs={'slug': self.org.slug})

    def test_one_resign_per_affected_node_deduped(self):
        from unittest.mock import patch
        changes = self.json.dumps([
            {'node': self.node1.id, 'tag': self.tagA.id, 'op': 'add'},
            {'node': self.node1.id, 'tag': self.tagB.id, 'op': 'add'},  # node1 affected twice
            {'node': self.node2.id, 'tag': self.tagA.id, 'op': 'add'},
        ])
        with patch('security_groups.views.renew_node_certificate') as mock_task:
            response = self.client.post(self.url, {'changes': changes})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(mock_task.delay.call_count, 2)
        called_ids = {c.args[0] for c in mock_task.delay.call_args_list}
        self.assertEqual(called_ids, {self.node1.id, self.node2.id})


class NodeTagMatrixStagingTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='stage@example.com', password='pw')
        self.org = Organization.objects.create(name='Stage Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.83.0.0/24', description='r')
        ca = CertificateAuthority.objects.create(name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        Node.objects.create(name='n1', organization=self.org, certificate_authority=ca,
            nebula_ip='10.83.0.10', external_port=4242, created_by=self.owner)
        Tag.objects.create(name='alpha', organization=self.org)
        self.client.force_login(self.owner)

    def test_matrix_renders_staging_scaffold(self):
        response = self.client.get(reverse('security_groups_org:matrix', kwargs={'slug': self.org.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'x-data')
        self.assertContains(response, 'changes pending')
        self.assertContains(response, reverse('security_groups_org:matrix_apply', kwargs={'slug': self.org.slug}))
        self.assertContains(response, 'csrfmiddlewaretoken')

    def test_matrix_reset_binding_is_on_swap_target(self):
        response = self.client.get(reverse('security_groups_org:matrix', kwargs={'slug': self.org.slug}))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'id="matrix-result" @htmx:after-swap.camel="reset()"')


class DirectionFirstRuleCreateTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='rc@example.com', password='pw')
        self.org = Organization.objects.create(name='RC Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.84.0.0/24', description='r')
        self.web = Tag.objects.create(name='web', organization=self.org)
        self.admin = Tag.objects.create(name='admin', organization=self.org)
        self.foreign_owner = User.objects.create_user(email='rc-foreign@example.com', password='pw')
        self.foreign_org = Organization.objects.create(name='RC Foreign Org', created_by=self.foreign_owner)
        NetworkRange.objects.create(organization=self.foreign_org, cidr='10.94.0.0/24', description='foreign')
        self.foreign_ca = CertificateAuthority.objects.create(
            name='Foreign CA',
            organization=self.foreign_org,
            created_by=self.foreign_owner,
            ca_cert=SimpleUploadedFile('foreign-ca.crt', b'c'),
            ca_key=SimpleUploadedFile('foreign-ca.key', b'k'),
        )
        self.foreign_admin = Tag.objects.create(name='foreign-admin', organization=self.foreign_org)
        self.foreign_node = Node.objects.create(
            name='foreign-node',
            organization=self.foreign_org,
            certificate_authority=self.foreign_ca,
            nebula_ip='10.94.0.10',
            external_port=4242,
            created_by=self.foreign_owner,
        )
        self.url = reverse('security_groups_org:rule_create', kwargs={'slug': self.org.slug})
        self.client.force_login(self.owner)

    def test_create_inbound_rule_with_target_and_tag_source(self):
        from security_groups.models import FirewallRule
        resp = self.client.post(self.url, {
            'direction': 'in', 'target_group': [str(self.web.id)],
            'source_type': 'group', 'source_group': [str(self.admin.id)],
            'protocol': 'tcp', 'port': '22',
        })
        self.assertIn(resp.status_code, (302, 200))
        rule = FirewallRule.objects.get(protocol='tcp', port_min=22)
        self.assertEqual(rule.direction, 'in')
        self.assertIsNone(rule.security_group)  # nulled after target_groups set
        self.assertEqual(set(rule.target_groups.values_list('id', flat=True)), {self.web.id})
        self.assertEqual(set(rule.source_groups.values_list('id', flat=True)), {self.admin.id})
        self.assertEqual(rule.match_type, 'groups')

    def test_create_outbound_cidr_rule(self):
        from security_groups.models import FirewallRule
        resp = self.client.post(self.url, {
            'direction': 'out', 'target_group': [str(self.web.id)],
            'source_type': 'cidr', 'source_cidr': '10.0.0.0/8',
            'protocol': 'tcp', 'port': '443',
        })
        rule = FirewallRule.objects.get(protocol='tcp', port_min=443)
        self.assertEqual(rule.direction, 'out')
        self.assertEqual(rule.source_cidr, '10.0.0.0/8')
        self.assertEqual(rule.match_type, 'cidr')
        self.assertEqual(set(rule.target_groups.values_list('id', flat=True)), {self.web.id})

    def test_create_requires_target(self):
        resp = self.client.post(self.url, {
            'direction': 'in', 'source_type': 'any', 'protocol': 'tcp', 'port': '22',
        })
        self.assertEqual(resp.status_code, 200)  # re-render with error
        self.assertContains(resp, 'tag')  # error mentions choosing a tag

    def test_create_rejects_foreign_host_source_without_persisting(self):
        from security_groups.models import FirewallRule
        before = FirewallRule.objects.count()

        resp = self.client.post(self.url, {
            'direction': 'in',
            'target_group': [str(self.web.id)],
            'source_type': 'host',
            'source_node': str(self.foreign_node.id),
            'protocol': 'tcp',
            'port': '22',
        })

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Source host not found in this organization.')
        self.assertEqual(FirewallRule.objects.count(), before)

    def test_create_rejects_unknown_or_foreign_source_group_without_persisting(self):
        from security_groups.models import FirewallRule
        before = FirewallRule.objects.count()

        resp = self.client.post(self.url, {
            'direction': 'in',
            'target_group': [str(self.web.id)],
            'source_type': 'group',
            'source_group': [str(self.foreign_admin.id), '999999'],
            'protocol': 'tcp',
            'port': '443',
        })

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Source tag not found in this organization.')
        self.assertEqual(FirewallRule.objects.count(), before)

    def test_create_rejects_unknown_source_type_without_persisting(self):
        from security_groups.models import FirewallRule
        before = FirewallRule.objects.count()

        resp = self.client.post(self.url, {
            'direction': 'in',
            'target_group': [str(self.web.id)],
            'source_type': 'bogus',
            'protocol': 'tcp',
            'port': '443',
        })

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Choose a valid source type.')
        self.assertEqual(FirewallRule.objects.count(), before)

    def test_create_requires_source_type_without_persisting(self):
        from security_groups.models import FirewallRule
        before = FirewallRule.objects.count()

        resp = self.client.post(self.url, {
            'direction': 'in',
            'target_group': [str(self.web.id)],
            'protocol': 'tcp',
            'port': '443',
        })

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Choose a valid source type.')
        self.assertEqual(FirewallRule.objects.count(), before)

    def test_get_renders_form_with_tags(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'web')
        self.assertContains(resp, 'Inbound')


class DirectionFirstRuleLifecycleTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='rfl@example.com', password='pw')
        self.org = Organization.objects.create(name='Rule Flow Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.86.0.0/24', description='r')
        self.ca = CertificateAuthority.objects.create(
            name='Rule Flow CA',
            organization=self.org,
            created_by=self.owner,
            ca_cert=SimpleUploadedFile('rule-flow-ca.crt', b'c'),
            ca_key=SimpleUploadedFile('rule-flow-ca.key', b'k'),
        )
        self.web = Tag.objects.create(name='web', organization=self.org)
        self.db = Tag.objects.create(name='db', organization=self.org)
        self.admin = Tag.objects.create(name='admin', organization=self.org)
        self.node = Node.objects.create(
            name='web-node',
            organization=self.org,
            certificate_authority=self.ca,
            nebula_ip='10.86.0.10',
            external_port=4242,
            created_by=self.owner,
        )
        self.node.tags.add(self.web)
        self.client.force_login(self.owner)

    def _target_only_rule(self, **kwargs):
        from security_groups.models import FirewallRule
        rule = FirewallRule(
            security_group=self.web,
            direction=kwargs.get('direction', 'in'),
            match_type=kwargs.get('match_type', 'any'),
            protocol=kwargs.get('protocol', 'any'),
            port_min=kwargs.get('port_min'),
            port_max=kwargs.get('port_max'),
            source_cidr=kwargs.get('source_cidr', ''),
        )
        rule.save()
        rule.target_groups.set(kwargs.get('target_groups', [self.web]))
        if kwargs.get('source_groups'):
            rule.source_groups.set(kwargs['source_groups'])
        rule.security_group = None
        rule.save()
        return rule

    def test_rule_created_through_direction_first_appears_in_policy_list(self):
        create_url = reverse('security_groups_org:rule_create', kwargs={'slug': self.org.slug})
        response = self.client.post(create_url, {
            'direction': 'in',
            'target_group': [str(self.web.id)],
            'source_type': 'any',
            'protocol': 'any',
        })
        self.assertRedirects(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.org.slug}),
        )

        response = self.client.get(reverse('security_groups_org:policy_list', kwargs={'slug': self.org.slug}))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Any')
        self.assertContains(response, 'web')
        self.assertNotContains(response, 'Unspecified')

    def test_target_group_any_rule_appears_on_group_detail(self):
        self._target_only_rule()

        response = self.client.get(
            reverse('security_groups_org:detail', kwargs={'slug': self.org.slug, 'pk': self.web.id})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Any')
        self.assertNotContains(response, 'Unspecified')

    def test_policy_edit_get_renders_direction_first_form_with_current_values(self):
        rule = self._target_only_rule(
            direction='out',
            match_type='cidr',
            protocol='tcp',
            port_min=443,
            port_max=443,
            source_cidr='10.0.0.0/8',
        )

        response = self.client.get(
            reverse('security_groups_org:policy_edit', kwargs={'slug': self.org.slug, 'rule_id': rule.id})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Edit Rule')
        self.assertContains(response, 'value="out" checked')
        self.assertContains(response, f'value="{self.web.id}" selected')
        self.assertContains(response, 'value="cidr" checked')
        self.assertContains(response, 'value="tcp" selected')
        self.assertContains(response, 'value="443"')
        self.assertContains(response, 'value="10.0.0.0/8"')

    def test_policy_edit_post_updates_direction_source_and_targets(self):
        rule = self._target_only_rule(
            direction='in',
            match_type='groups',
            protocol='tcp',
            port_min=22,
            port_max=22,
            source_groups=[self.admin],
        )

        response = self.client.post(
            reverse('security_groups_org:policy_edit', kwargs={'slug': self.org.slug, 'rule_id': rule.id}),
            {
                'direction': 'out',
                'target_group': [str(self.web.id), str(self.db.id)],
                'source_type': 'cidr',
                'source_cidr': '10.0.0.0/8',
                'protocol': 'tcp',
                'port': '443',
            },
        )

        self.assertRedirects(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.org.slug}),
        )
        rule.refresh_from_db()
        self.assertEqual(rule.direction, 'out')
        self.assertEqual(rule.match_type, 'cidr')
        self.assertEqual(rule.source_cidr, '10.0.0.0/8')
        self.assertFalse(rule.source_groups.exists())
        self.assertFalse(rule.source_nodes.exists())
        self.assertEqual(rule.protocol, 'tcp')
        self.assertEqual(rule.port_min, 443)
        self.assertEqual(rule.port_max, 443)
        self.assertIsNone(rule.security_group)
        self.assertEqual(set(rule.target_groups.values_list('id', flat=True)), {self.web.id, self.db.id})

    def test_policy_delete_can_delete_target_group_only_rule(self):
        from security_groups.models import FirewallRule
        rule = self._target_only_rule()

        response = self.client.post(
            reverse('security_groups_org:policy_delete', kwargs={'slug': self.org.slug, 'rule_id': rule.id})
        )

        self.assertRedirects(
            response,
            reverse('security_groups_org:policy_list', kwargs={'slug': self.org.slug}),
        )
        self.assertFalse(FirewallRule.objects.filter(id=rule.id).exists())


class RulePreviewTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership, NetworkRange
        from certificates.models import CertificateAuthority
        from django.core.files.uploadedfile import SimpleUploadedFile
        from nodes.models import Node
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='rp@example.com', password='pw')
        self.org = Organization.objects.create(name='RP Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        NetworkRange.objects.create(organization=self.org, cidr='10.85.0.0/24', description='r')
        ca = CertificateAuthority.objects.create(name='CA', organization=self.org, created_by=self.owner,
            ca_cert=SimpleUploadedFile('ca.crt', b'c'), ca_key=SimpleUploadedFile('ca.key', b'k'))
        self.web = Tag.objects.create(name='web', organization=self.org)
        self.admin = Tag.objects.create(name='admin', organization=self.org)
        self.n1 = Node.objects.create(name='n1', organization=self.org, certificate_authority=ca,
            nebula_ip='10.85.0.10', external_port=4242, created_by=self.owner)
        self.n1.tags.add(self.web)
        self.url = reverse('security_groups_org:rule_preview', kwargs={'slug': self.org.slug})
        self.client.force_login(self.owner)

    def test_preview_renders_entries_and_targets(self):
        resp = self.client.post(self.url, {
            'direction': 'in', 'target_group': [str(self.web.id)],
            'source_type': 'group', 'source_group': [str(self.admin.id)],
            'protocol': 'tcp', 'port': '22',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'admin')   # groups:[admin] in the rendered YAML
        self.assertContains(resp, '22')
        # web tag has 1 node -> Targets 1
        self.assertContains(resp, '1')

    def test_preview_does_not_persist(self):
        from security_groups.models import FirewallRule, FirewallRuleSourceGroup
        before_rules = FirewallRule.objects.count()
        before_source_groups = FirewallRuleSourceGroup.objects.count()
        self.client.post(self.url, {
            'direction': 'in', 'target_group': [str(self.web.id)],
            'source_type': 'any', 'protocol': 'tcp', 'port': '80',
        })
        self.assertEqual(FirewallRule.objects.count(), before_rules)  # rolled back

    def test_preview_does_not_persist_m2m_source_group(self):
        """A preview with source_type='group' must roll back the M2M join rows too."""
        from security_groups.models import FirewallRule, FirewallRuleSourceGroup
        before_rules = FirewallRule.objects.count()
        before_source_groups = FirewallRuleSourceGroup.objects.count()
        self.client.post(self.url, {
            'direction': 'in', 'target_group': [str(self.web.id)],
            'source_type': 'group', 'source_group': [str(self.admin.id)],
            'protocol': 'tcp', 'port': '443',
        })
        self.assertEqual(FirewallRule.objects.count(), before_rules)  # rules rolled back
        self.assertEqual(FirewallRuleSourceGroup.objects.count(), before_source_groups)  # M2M rolled back

    def test_preview_rejects_malformed_source_type_without_persisting(self):
        from security_groups.models import FirewallRule, FirewallRuleSourceGroup
        before_rules = FirewallRule.objects.count()
        before_source_groups = FirewallRuleSourceGroup.objects.count()

        resp = self.client.post(self.url, {
            'direction': 'in',
            'target_group': [str(self.web.id)],
            'source_type': 'bogus',
            'source_group': [str(self.admin.id)],
            'protocol': 'tcp',
            'port': '443',
        })

        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Choose a valid source type.')
        self.assertEqual(FirewallRule.objects.count(), before_rules)
        self.assertEqual(FirewallRuleSourceGroup.objects.count(), before_source_groups)

    def test_preview_flags_egress_lockout(self):
        # first OUTBOUND rule on a tag whose nodes have no existing outbound -> warning
        resp = self.client.post(self.url, {
            'direction': 'out', 'target_group': [str(self.web.id)],
            'source_type': 'any', 'protocol': 'any',
        })
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'egress')  # warning text mentions egress


class RuleFormPreviewWiringTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='rfw@example.com', password='pw')
        self.org = Organization.objects.create(name='RFW Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        Tag.objects.create(name='web', organization=self.org)
        self.client.force_login(self.owner)

    def test_form_wires_preview(self):
        resp = self.client.get(reverse('security_groups_org:rule_create', kwargs={'slug': self.org.slug}))
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, reverse('security_groups_org:rule_preview', kwargs={'slug': self.org.slug}))
        self.assertContains(resp, 'hx-post')
        self.assertContains(resp, 'rule-preview')


class RecipeFieldsTests(TestCase):
    def setUp(self):
        from organizations.models import Organization
        self.org = Organization.objects.create(name='Recipe Fields Org',
            created_by=User.objects.create_user(email='rf@example.com', password='pw'))

    def test_recipe_fields_exist_with_defaults(self):
        from security_groups.models import Tag, FirewallRule
        tag = Tag.objects.create(name='web', organization=self.org)
        self.assertEqual(tag.recipe, '')
        self.assertEqual(tag.recipe_answers, {})
        rule = FirewallRule(security_group=tag, protocol='tcp', port_min=80, port_max=80)
        rule.save()
        self.assertFalse(rule.managed_by_recipe)
        tag.recipe = 'web'; tag.recipe_answers = {'k': 'v'}; tag.save()
        tag.refresh_from_db()
        self.assertEqual(tag.recipe, 'web')
        self.assertEqual(tag.recipe_answers, {'k': 'v'})


class ApplyRecipeTests(TestCase):
    def setUp(self):
        from organizations.models import Organization
        from security_groups.models import Tag
        self.org = Organization.objects.create(name='Apply Recipe Org',
            created_by=User.objects.create_user(email='ar@example.com', password='pw'))
        self.web = Tag.objects.create(name='web', organization=self.org)
        self.db = Tag.objects.create(name='db', organization=self.org)

    def test_apply_web_recipe_creates_two_rules(self):
        from security_groups.recipes import apply_recipe
        from security_groups.models import FirewallRule
        created = apply_recipe(self.web, 'web', self.org)
        self.assertEqual(len(created), 2)
        ports = sorted(r.port_min for r in created)
        self.assertEqual(ports, [80, 443])
        for r in created:
            self.assertTrue(r.managed_by_recipe)
            self.assertEqual(set(r.target_groups.values_list('id', flat=True)), {self.web.id})
            self.assertIsNone(r.security_group)
        self.web.refresh_from_db()
        self.assertEqual(self.web.recipe, 'web')

    def test_db_recipe_sources_from_web_tag(self):
        from security_groups.recipes import apply_recipe
        created = apply_recipe(self.db, 'db', self.org)
        self.assertEqual(len(created), 1)
        rule = created[0]
        self.assertEqual(rule.port_min, 5432)
        self.assertEqual(set(rule.source_groups.values_list('name', flat=True)), {'web'})

    def test_apply_is_idempotent(self):
        from security_groups.recipes import apply_recipe
        from security_groups.models import FirewallRule
        apply_recipe(self.web, 'web', self.org)
        apply_recipe(self.web, 'web', self.org)  # re-apply
        self.assertEqual(FirewallRule.objects.filter(target_groups=self.web, managed_by_recipe=True).count(), 2)

    def test_apply_preserves_hand_added_rules(self):
        from security_groups.recipes import apply_recipe
        from security_groups.models import FirewallRule
        hand = FirewallRule(security_group=self.web, protocol='tcp', port_min=9000, port_max=9000)
        hand.save(); hand.target_groups.add(self.web); hand.security_group = None; hand.save()
        apply_recipe(self.web, 'web', self.org)
        apply_recipe(self.web, 'web', self.org)
        self.assertTrue(FirewallRule.objects.filter(id=hand.id).exists())  # hand-added survives
        self.assertEqual(FirewallRule.objects.filter(target_groups=self.web).count(), 3)  # 1 hand + 2 recipe

    def test_apply_locks_target_tag_inside_transaction(self):
        from django.db import transaction
        from security_groups import recipes
        from security_groups.recipes import apply_recipe
        from security_groups.models import Tag

        atomic_depth = 0
        real_atomic = transaction.atomic
        real_select_for_update = Tag.objects.select_for_update

        def recording_atomic(*args, **kwargs):
            real_context = real_atomic(*args, **kwargs)

            class RecordingAtomic:
                def __enter__(self):
                    nonlocal atomic_depth
                    result = real_context.__enter__()
                    atomic_depth += 1
                    return result

                def __exit__(self, exc_type, exc_value, traceback):
                    nonlocal atomic_depth
                    atomic_depth -= 1
                    return real_context.__exit__(exc_type, exc_value, traceback)

            return RecordingAtomic()

        def recording_select_for_update(*args, **kwargs):
            self.assertGreater(atomic_depth, 0)
            return real_select_for_update(*args, **kwargs)

        with mock.patch.object(recipes, 'transaction', create=True) as transaction_mock:
            transaction_mock.atomic.side_effect = recording_atomic
            with mock.patch.object(Tag.objects, 'select_for_update', side_effect=recording_select_for_update) as lock_mock:
                created = apply_recipe(self.web, 'web', self.org)

        transaction_mock.atomic.assert_called_once()
        lock_mock.assert_called_once()
        self.assertEqual(len(created), 2)

    def test_unknown_recipe_raises(self):
        from security_groups.recipes import apply_recipe
        with self.assertRaises(ValueError):
            apply_recipe(self.web, 'nope', self.org)


class RecipeWizardTests(TestCase):
    def setUp(self):
        from organizations.models import Organization, Membership
        from security_groups.models import Tag
        self.client = Client()
        self.owner = User.objects.create_user(email='rw@example.com', password='pw')
        self.org = Organization.objects.create(name='RW Org', created_by=self.owner)
        Membership.objects.create(user=self.owner, organization=self.org, role='owner')
        self.web = Tag.objects.create(name='web', organization=self.org)
        self.url = reverse('security_groups_org:recipes', kwargs={'slug': self.org.slug})
        self.client.force_login(self.owner)

    def test_get_lists_recipes(self):
        resp = self.client.get(self.url)
        self.assertEqual(resp.status_code, 200)
        self.assertContains(resp, 'Web tier')
        self.assertContains(resp, 'Database tier')

    def test_post_applies_recipe_to_tag(self):
        from security_groups.models import FirewallRule
        resp = self.client.post(self.url, {'recipe': 'web', 'tag': str(self.web.id)})
        self.assertIn(resp.status_code, (302, 200))
        self.assertEqual(FirewallRule.objects.filter(target_groups=self.web, managed_by_recipe=True).count(), 2)

    def test_post_requires_admin(self):
        from organizations.models import Membership
        viewer = User.objects.create_user(email='rwv@example.com', password='pw')
        Membership.objects.create(user=viewer, organization=self.org, role='viewer')
        self.client.force_login(viewer)
        resp = self.client.post(self.url, {'recipe': 'web', 'tag': str(self.web.id)})
        self.assertEqual(resp.status_code, 403)
