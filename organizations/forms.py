from django import forms
from .models import Organization, NetworkRange, Invitation
import ipaddress

class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ['name']
        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'})
        }

class NetworkRangeForm(forms.ModelForm):
    class Meta:
        model = NetworkRange
        fields = ['cidr']
        widgets = {
            'cidr': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g. 10.0.0.0/24'})
        }

    def clean_cidr(self):
        cidr = self.cleaned_data.get('cidr')
        try:
            # Validate CIDR notation
            ipaddress.ip_network(cidr)
        except ValueError:
            raise forms.ValidationError("Please enter a valid CIDR notation (e.g. 10.0.0.0/24)")
        return cidr

class InvitationForm(forms.ModelForm):
    """Form for creating organization invitations."""
    
    class Meta:
        model = Invitation
        fields = ['email', 'role']
        widgets = {
            'email': forms.EmailInput(attrs={'class': 'form-control'}),
            'role': forms.Select(attrs={'class': 'form-control'})
        }
    
    def clean_email(self):
        """Validate email format."""
        email = self.cleaned_data['email']
        if not email:
            raise forms.ValidationError("Email address is required.")
        return email.lower() 