from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import uuid


def generate_token():
    return str(uuid.uuid4())


class Migration(migrations.Migration):

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('organizations', '0004_historicalnetworkrange_networkrange'),
        ('nodes', '0005_alter_historicalnode_nebula_ip_alter_node_nebula_ip'),
    ]

    operations = [
        migrations.CreateModel(
            name='NodeRegistrationToken',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('token', models.CharField(default=generate_token, help_text='Unique token for node registration', max_length=255, unique=True)),
                ('description', models.CharField(help_text='Description or purpose of this token', max_length=255)),
                ('created_at', models.DateTimeField(auto_now_add=True)),
                ('expires_at', models.DateTimeField(help_text='Expiration date of the token')),
                ('is_active', models.BooleanField(default=True, help_text='Whether this token is currently active')),
                ('uses_allowed', models.IntegerField(default=-1, help_text='Number of times this token can be used (-1 for unlimited)')),
                ('uses_count', models.IntegerField(default=0, help_text='Number of times this token has been used')),
                ('created_by', models.ForeignKey(help_text='The user who created this token', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='created_tokens', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='registration_tokens', to='organizations.organization')),
            ],
            options={
                'verbose_name': 'Node Registration Token',
                'verbose_name_plural': 'Node Registration Tokens',
                'ordering': ['-created_at'],
            },
        ),
    ] 