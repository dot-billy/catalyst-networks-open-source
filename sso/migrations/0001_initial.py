from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone
import simple_history.models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('organizations', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='SSOConfiguration',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('is_enabled', models.BooleanField(default=False, help_text='Enable SAML SSO for this organization')),
                ('enforce_sso', models.BooleanField(default=False, help_text='When enabled, members must use SSO (password login disabled)')),
                ('idp_entity_id', models.CharField(help_text='IdP Entity ID (Issuer URL)', max_length=512)),
                ('idp_sso_url', models.URLField(help_text='IdP Single Sign-On URL', max_length=512)),
                ('idp_slo_url', models.URLField(blank=True, default='', help_text='IdP Single Logout URL (optional)', max_length=512)),
                ('idp_x509_cert', models.TextField(help_text='IdP X.509 certificate (PEM format, without header/footer)')),
                ('attribute_email', models.CharField(default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', help_text='SAML attribute for user email', max_length=255)),
                ('attribute_first_name', models.CharField(blank=True, default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', help_text='SAML attribute for first name', max_length=255)),
                ('attribute_last_name', models.CharField(blank=True, default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', help_text='SAML attribute for last name', max_length=255)),
                ('auto_create_users', models.BooleanField(default=True, help_text='Automatically create user accounts on first SSO login')),
                ('default_role', models.CharField(choices=[('member', 'Member'), ('admin', 'Admin')], default='member', help_text='Default role for auto-provisioned users', max_length=10)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(auto_now=True)),
                ('organization', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, related_name='sso_config', to='organizations.organization')),
            ],
            options={
                'verbose_name': 'SSO Configuration',
                'verbose_name_plural': 'SSO Configurations',
            },
        ),
        migrations.CreateModel(
            name='HistoricalSSOConfiguration',
            fields=[
                ('id', models.BigIntegerField(auto_created=True, blank=True, db_index=True, verbose_name='ID')),
                ('is_enabled', models.BooleanField(default=False, help_text='Enable SAML SSO for this organization')),
                ('enforce_sso', models.BooleanField(default=False, help_text='When enabled, members must use SSO (password login disabled)')),
                ('idp_entity_id', models.CharField(help_text='IdP Entity ID (Issuer URL)', max_length=512)),
                ('idp_sso_url', models.URLField(help_text='IdP Single Sign-On URL', max_length=512)),
                ('idp_slo_url', models.URLField(blank=True, default='', help_text='IdP Single Logout URL (optional)', max_length=512)),
                ('idp_x509_cert', models.TextField(help_text='IdP X.509 certificate (PEM format, without header/footer)')),
                ('attribute_email', models.CharField(default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', help_text='SAML attribute for user email', max_length=255)),
                ('attribute_first_name', models.CharField(blank=True, default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname', help_text='SAML attribute for first name', max_length=255)),
                ('attribute_last_name', models.CharField(blank=True, default='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname', help_text='SAML attribute for last name', max_length=255)),
                ('auto_create_users', models.BooleanField(default=True, help_text='Automatically create user accounts on first SSO login')),
                ('default_role', models.CharField(choices=[('member', 'Member'), ('admin', 'Admin')], default='member', help_text='Default role for auto-provisioned users', max_length=10)),
                ('created_at', models.DateTimeField(default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(blank=True, editable=False)),
                ('history_id', models.AutoField(primary_key=True, serialize=False)),
                ('history_date', models.DateTimeField(db_index=True)),
                ('history_change_reason', models.CharField(max_length=100, null=True)),
                ('history_type', models.CharField(choices=[('+', 'Created'), ('~', 'Changed'), ('-', 'Deleted')], max_length=1)),
                ('history_user', models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='+', to=settings.AUTH_USER_MODEL)),
                ('organization', models.ForeignKey(blank=True, db_constraint=False, null=True, on_delete=django.db.models.deletion.DO_NOTHING, related_name='+', to='organizations.organization')),
            ],
            options={
                'verbose_name': 'historical SSO Configuration',
                'verbose_name_plural': 'historical SSO Configurations',
                'ordering': ('-history_date', '-history_id'),
                'get_latest_by': ('history_date', 'history_id'),
            },
            bases=(simple_history.models.HistoricalChanges, models.Model),
        ),
    ]
