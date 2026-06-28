# Generated for the Phase 0 security-groups -> tags rename.
#
# STATE-ONLY: renames the Node M2M ``security_groups`` -> ``tags`` and introduces
# an explicit through model (NodeTag) that reproduces the EXISTING join table
# (nodes_node_security_groups) and its EXISTING columns (node_id,
# securitygroup_id) exactly. Because the model SecurityGroup was renamed to Tag,
# the auto-derived reverse column would have become ``tag_id``; the explicit
# through with db_column='securitygroup_id' keeps it unchanged. No table or
# column is created/renamed/dropped: every operation lives inside
# SeparateDatabaseAndState(database_operations=[]).

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('nodes', '0016_historicalnode_assigned_user'),
        # Needs the renamed Tag model in the migration state.
        ('security_groups', '0007_rename_securitygroup_to_tag'),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            # No DDL: nodes_node_security_groups (and its columns) is untouched.
            database_operations=[],
            state_operations=[
                migrations.RemoveField(
                    model_name='node',
                    name='security_groups',
                ),
                migrations.CreateModel(
                    name='NodeTag',
                    fields=[
                        ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                        ('node', models.ForeignKey(db_column='node_id', on_delete=django.db.models.deletion.CASCADE, to='nodes.node')),
                        ('tag', models.ForeignKey(db_column='securitygroup_id', on_delete=django.db.models.deletion.CASCADE, to='security_groups.tag')),
                    ],
                    options={
                        'db_table': 'nodes_node_security_groups',
                        'unique_together': {('node', 'tag')},
                    },
                ),
                migrations.AddField(
                    model_name='node',
                    name='tags',
                    field=models.ManyToManyField(
                        blank=True,
                        help_text='Tags applied to this node (become Nebula cert groups).',
                        related_name='nodes',
                        through='nodes.NodeTag',
                        to='security_groups.tag',
                    ),
                ),
            ],
        ),
    ]
