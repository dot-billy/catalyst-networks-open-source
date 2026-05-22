from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion

import notifications.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("organizations", "0008_alter_invitation_unique_together_and_more"),
    ]

    operations = [
        migrations.CreateModel(
            name="NotificationIntegration",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("slack", "Slack")], max_length=30)),
                ("secret_url", models.TextField(blank=True)),
                ("events", models.JSONField(default=notifications.models.default_notification_events)),
                ("active", models.BooleanField(default=False)),
                ("last_delivery_at", models.DateTimeField(blank=True, null=True)),
                ("last_delivery_status", models.IntegerField(blank=True, null=True)),
                ("last_delivery_error", models.TextField(blank=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notification_integrations",
                        to="organizations.organization",
                    ),
                ),
            ],
            options={
                "ordering": ["kind"],
            },
        ),
        migrations.CreateModel(
            name="NotificationPreference",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                (
                    "event_type",
                    models.CharField(
                        choices=[
                            ("node.registered", "Node Registered"),
                            ("node.created", "Node Created"),
                            ("node.revoked", "Node Revoked"),
                            ("cert.issued", "Certificate Issued"),
                            ("cert.renewed", "Certificate Renewed"),
                            ("cert.revoked", "Certificate Revoked"),
                            ("cert.expiring", "Certificate Expiring Soon"),
                            ("ip.allocated", "IP Allocated"),
                        ],
                        max_length=50,
                    ),
                ),
                ("enabled", models.BooleanField(default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "organization",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notification_preferences",
                        to="organizations.organization",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="notification_preferences",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "ordering": ["event_type"],
            },
        ),
        migrations.AddConstraint(
            model_name="notificationintegration",
            constraint=models.UniqueConstraint(
                fields=("organization", "kind"),
                name="unique_org_notification_kind",
            ),
        ),
        migrations.AddConstraint(
            model_name="notificationpreference",
            constraint=models.UniqueConstraint(
                fields=("user", "organization", "event_type"),
                name="unique_user_org_notification_preference",
            ),
        ),
    ]
