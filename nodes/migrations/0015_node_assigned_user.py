from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("nodes", "0014_alter_node_cert_path_alter_node_key_path_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="node",
            name="assigned_user",
            field=models.ForeignKey(
                blank=True,
                help_text="The user this mobile node is assigned to",
                null=True,
                on_delete=models.SET_NULL,
                related_name="assigned_mobile_nodes",
                to=settings.AUTH_USER_MODEL,
            ),
        ),
    ]
