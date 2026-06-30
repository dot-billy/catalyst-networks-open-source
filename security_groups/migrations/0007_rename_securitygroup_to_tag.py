# Generated for the Phase 0 security-groups -> tags rename.
#
# STATE-ONLY: this migration renames the Django model SecurityGroup -> Tag
# (and its simple-history shadow HistoricalSecurityGroup -> HistoricalTag) and
# repoints the FirewallRule FK/M2M to the new model NAME, WITHOUT touching the
# database. The existing table ``security_groups_securitygroup`` is kept and
# pinned via AlterModelTable, so no ``ALTER TABLE ... RENAME`` is ever emitted.
# All operations live inside SeparateDatabaseAndState(database_operations=[]).

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('organizations', '0008_alter_invitation_unique_together_and_more'),
        ('security_groups', '0006_alter_securitygroup_unique_together_and_more'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # No DDL: the table security_groups_securitygroup is unchanged.
            database_operations=[],
            state_operations=[
                migrations.RenameModel(
                    old_name='SecurityGroup',
                    new_name='Tag',
                ),
                migrations.RenameModel(
                    old_name='HistoricalSecurityGroup',
                    new_name='HistoricalTag',
                ),
                # Keep pointing the renamed model at the original table.
                migrations.AlterModelTable(
                    name='tag',
                    table='security_groups_securitygroup',
                ),
                # Keep the history shadow on its original table too — no data move.
                migrations.AlterModelTable(
                    name='historicaltag',
                    table='security_groups_historicalsecuritygroup',
                ),
                migrations.AlterModelOptions(
                    name='tag',
                    options={'verbose_name': 'Tag', 'verbose_name_plural': 'Tags'},
                ),
                # related_name on the organization FK changed
                # ('security_groups' -> 'tags'). Reverse-accessor metadata only,
                # no column/constraint change.
                migrations.AlterField(
                    model_name='tag',
                    name='organization',
                    field=models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='tags',
                        to='organizations.organization',
                    ),
                ),
                migrations.AlterModelOptions(
                    name='historicaltag',
                    options={
                        'get_latest_by': ('history_date', 'history_id'),
                        'ordering': ('-history_date', '-history_id'),
                        'verbose_name': 'historical Tag',
                        'verbose_name_plural': 'historical Tags',
                    },
                ),
                # Repoint FirewallRule references to the new model name. These are
                # metadata-only: the underlying column (security_group_id) and the
                # M2M through table are unchanged because the table name is kept.
                migrations.AlterField(
                    model_name='firewallrule',
                    name='security_group',
                    field=models.ForeignKey(
                        blank=True,
                        help_text='Security group this rule applies to (if not attached to a specific node)',
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name='firewall_rules',
                        to='security_groups.tag',
                    ),
                ),
                # Explicit through model for source_groups pins the existing join
                # table + columns (firewallrule_id, securitygroup_id) so the model
                # rename stays DDL-free. CreateModel is state-only (table exists).
                migrations.CreateModel(
                    name='FirewallRuleSourceGroup',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('firewallrule', models.ForeignKey(db_column='firewallrule_id', on_delete=django.db.models.deletion.CASCADE, to='security_groups.firewallrule')),
                        ('tag', models.ForeignKey(db_column='securitygroup_id', on_delete=django.db.models.deletion.CASCADE, to='security_groups.tag')),
                    ],
                    options={
                        'db_table': 'security_groups_firewallrule_source_groups',
                        'unique_together': {('firewallrule', 'tag')},
                    },
                ),
                migrations.AlterField(
                    model_name='firewallrule',
                    name='source_groups',
                    field=models.ManyToManyField(
                        blank=True,
                        help_text='Source security groups allowed by this rule',
                        related_name='rules_as_source',
                        through='security_groups.FirewallRuleSourceGroup',
                        to='security_groups.tag',
                    ),
                ),
                migrations.AlterField(
                    model_name='historicalfirewallrule',
                    name='security_group',
                    field=models.ForeignKey(
                        blank=True,
                        db_constraint=False,
                        help_text='Security group this rule applies to (if not attached to a specific node)',
                        null=True,
                        on_delete=django.db.models.deletion.DO_NOTHING,
                        related_name='+',
                        to='security_groups.tag',
                    ),
                ),
            ],
        ),
    ]
