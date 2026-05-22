from django import forms
from .models import SSOConfiguration


class SSOConfigurationForm(forms.ModelForm):
    class Meta:
        model = SSOConfiguration
        fields = [
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
