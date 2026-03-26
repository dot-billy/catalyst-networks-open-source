from django.db import migrations, models
import django.db.models.deletion
import certificates.models


class Migration(migrations.Migration):

    dependencies = [
        ('certificates', '0002_alter_certificateauthority_ca_cert_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='CertificateAuthorityQRCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('qr_image', models.ImageField(help_text='Generated CA QR code image file', upload_to=certificates.models.ca_qr_path)),
                ('source', models.CharField(default='nebula_print', help_text='How this QR was generated', max_length=32)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('certificate_authority', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='qr_code', to='certificates.certificateauthority')),
            ],
            options={
                'ordering': ['-updated_at'],
            },
        ),
    ]
