from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm

User = get_user_model()

class UserLoginForm(forms.Form):
    """Form for user login"""
    email = forms.EmailField(
        widget=forms.EmailInput(attrs={'class': 'form-control'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'class': 'form-control'})
    )
    remember_me = forms.BooleanField(required=False)

class UserRegistrationForm(UserCreationForm):
    """Form for user registration"""
    class Meta:
        model = User
        fields = ('email', 'password1', 'password2')

    def __init__(self, *args, **kwargs):
        self.registration_mode = kwargs.pop('registration_mode', 'public')
        self.invitation = kwargs.pop('invitation', None)

        super().__init__(*args, **kwargs)

        if self.invitation:
            self.initial['email'] = self.invitation.email
            self.fields['email'].initial = self.invitation.email
            self.fields['email'].disabled = True
            self.fields['email'].widget.attrs['readonly'] = 'readonly'

        # Add form-control class to all fields
        for field_name, field in self.fields.items():
            field.widget.attrs['class'] = 'form-control'

    def clean_email(self):
        if self.invitation:
            return self.invitation.email
        return self.cleaned_data['email']

    def save(self, commit=True):
        user = super().save(commit=False)
        if self.invitation:
            user.email = self.invitation.email

        user.is_active = True
        user.is_staff = self.registration_mode == 'bootstrap'
        user.is_superuser = False

        if commit:
            user.save()
        return user
