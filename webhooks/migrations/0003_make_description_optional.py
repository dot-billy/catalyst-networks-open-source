from django.db import migrations, models

class Migration(migrations.Migration):

    dependencies = [
        ('webhooks', '0002_add_delivery_fields'),
    ]

    operations = [
        migrations.AlterField(
            model_name='webhook',
            name='description',
            field=models.TextField(blank=True, help_text='Optional description of the webhook'),
        ),
    ] 