from django import forms
from .models import SSOConfiguration


class SSOConfigurationForm(forms.ModelForm):
    oidc_client_secret = forms.CharField(
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'catalyst-input',
            'autocomplete': 'new-password',
            'placeholder': 'Enter a new client secret',
        }, render_value=False),
        help_text='Leave blank to keep the existing client secret.',
    )

    class Meta:
        model = SSOConfiguration
        fields = [
            'provider_type',
            'oidc_mode',
            'oidc_display_name',
            'oidc_issuer_url',
            'oidc_client_id',
            'oidc_allowed_domain',
            'oidc_scopes',
            'oidc_email_claim',
            'oidc_first_name_claim',
            'oidc_last_name_claim',
            'oidc_subject_claim',
            'idp_entity_id',
            'idp_sso_url',
            'idp_slo_url',
            'idp_x509_cert',
            'attribute_email',
            'attribute_first_name',
            'attribute_last_name',
            'auto_create_users',
            'default_role',
            'enforce_sso',
        ]
        widgets = {
            'provider_type': forms.RadioSelect(attrs={'class': 'catalyst-radio'}),
            'oidc_mode': forms.RadioSelect(attrs={'class': 'catalyst-radio'}),
            'oidc_display_name': forms.TextInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'Google Workspace or Okta Workforce',
            }),
            'oidc_issuer_url': forms.URLInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'https://idp.example.com/oauth2/default',
            }),
            'oidc_client_id': forms.TextInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'OIDC client ID',
            }),
            'oidc_allowed_domain': forms.TextInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'example.com',
            }),
            'oidc_scopes': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'oidc_email_claim': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'oidc_first_name_claim': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'oidc_last_name_claim': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'oidc_subject_claim': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'idp_entity_id': forms.TextInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'https://idp.example.com/saml/metadata',
            }),
            'idp_sso_url': forms.URLInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'https://idp.example.com/saml/sso',
            }),
            'idp_slo_url': forms.URLInput(attrs={
                'class': 'catalyst-input',
                'placeholder': 'https://idp.example.com/saml/slo (optional)',
            }),
            'idp_x509_cert': forms.Textarea(attrs={
                'class': 'catalyst-input font-mono text-sm',
                'rows': 6,
                'placeholder': 'Paste the IdP X.509 certificate here (PEM format, without BEGIN/END headers)',
            }),
            'attribute_email': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'attribute_first_name': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'attribute_last_name': forms.TextInput(attrs={'class': 'catalyst-input'}),
            'default_role': forms.Select(attrs={'class': 'catalyst-input'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        provider_aware_fields = [
            'idp_entity_id',
            'idp_sso_url',
            'idp_x509_cert',
            'oidc_mode',
            'oidc_issuer_url',
            'oidc_client_id',
        ]
        for field_name in provider_aware_fields:
            self.fields[field_name].required = False

    def clean(self):
        cleaned_data = super().clean()
        provider_type = cleaned_data.get('provider_type')
        oidc_mode = cleaned_data.get('oidc_mode')

        if provider_type == SSOConfiguration.PROVIDER_SAML:
            for field_name in ('idp_entity_id', 'idp_sso_url', 'idp_x509_cert'):
                if not cleaned_data.get(field_name):
                    self.add_error(field_name, 'This field is required for SAML SSO.')

        if provider_type == SSOConfiguration.PROVIDER_OIDC:
            if not oidc_mode:
                self.add_error('oidc_mode', 'Choose an OIDC provider mode.')
            if not cleaned_data.get('oidc_client_id'):
                self.add_error('oidc_client_id', 'Client ID is required for OIDC SSO.')
            if not cleaned_data.get('oidc_client_secret') and not self.instance.oidc_client_secret_encrypted:
                self.add_error('oidc_client_secret', 'Client secret is required for OIDC SSO.')
            if oidc_mode == SSOConfiguration.OIDC_GOOGLE and not cleaned_data.get('oidc_allowed_domain'):
                self.add_error('oidc_allowed_domain', 'Google Workspace SSO requires an allowed email domain.')
            if oidc_mode == SSOConfiguration.OIDC_GENERIC and not cleaned_data.get('oidc_issuer_url'):
                self.add_error('oidc_issuer_url', 'Issuer URL is required for generic OIDC.')

        return cleaned_data

    def save(self, commit=True):
        instance = super().save(commit=False)
        oidc_client_secret = self.cleaned_data.get('oidc_client_secret')
        if oidc_client_secret:
            instance.set_oidc_client_secret(oidc_client_secret)
        if commit:
            instance.save()
            self.save_m2m()
        return instance
