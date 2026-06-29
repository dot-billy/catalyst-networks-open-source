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
