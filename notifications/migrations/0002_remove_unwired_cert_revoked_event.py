from django.db import migrations, models


def remove_cert_revoked(apps, schema_editor):
    NotificationIntegration = apps.get_model("notifications", "NotificationIntegration")
    NotificationPreference = apps.get_model("notifications", "NotificationPreference")

    NotificationPreference.objects.filter(event_type="cert.revoked").delete()
    for integration in NotificationIntegration.objects.all():
        events = integration.events or []
        filtered_events = [event for event in events if event != "cert.revoked"]
        if filtered_events != events:
            integration.events = filtered_events
            integration.save(update_fields=["events"])


class Migration(migrations.Migration):

    dependencies = [
        ("notifications", "0001_initial"),
    ]

    operations = [
        migrations.AlterField(
            model_name="notificationpreference",
            name="event_type",
            field=models.CharField(
                choices=[
                    ("node.registered", "Node Registered"),
                    ("node.created", "Node Created"),
                    ("node.revoked", "Node Revoked"),
                    ("cert.issued", "Certificate Issued"),
                    ("cert.renewed", "Certificate Renewed"),
                    ("cert.expiring", "Certificate Expiring Soon"),
                    ("ip.allocated", "IP Allocated"),
                ],
                max_length=50,
            ),
        ),
        migrations.RunPython(remove_cert_revoked, migrations.RunPython.noop),
    ]
