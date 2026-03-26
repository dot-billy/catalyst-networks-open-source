# Generated manually for NodeQRCode model

from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('nodes', '0012_historicalnode_last_checkin_node_last_checkin'),
    ]

    operations = [
        migrations.CreateModel(
            name='NodeQRCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('qr_image', models.ImageField(help_text='Generated QR code image file', upload_to='nodes.node_qr_path')),
                ('enrollment_token', models.CharField(help_text='Secure token for enrollment URL', max_length=255, unique=True)),
                ('enrollment_url', models.URLField(help_text='Full enrollment URL encoded in QR code')),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(help_text='When this QR code expires and should be regenerated')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this QR code is still valid for use')),
                ('node', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='qr_code', to='nodes.node')),
            ],
            options={
                'ordering': ['-created_at'],
            },
        ),
    ]