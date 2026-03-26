from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('webhooks', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='webhook',
            name='last_delivery',
            field=models.DateTimeField(null=True, blank=True),
        ),
        migrations.AddField(
            model_name='webhook',
            name='last_delivery_status',
            field=models.IntegerField(null=True, blank=True),
        ),
    ] 