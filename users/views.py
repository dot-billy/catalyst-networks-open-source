from django.shortcuts import render, redirect
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.urls import reverse
from django.utils.http import url_has_allowed_host_and_scheme
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework_simplejwt.views import TokenObtainPairView
from django.contrib.auth import get_user_model
from drf_spectacular.utils import extend_schema, OpenApiExample
from .serializers import (
    UserSerializer,
    UserRegistrationSerializer,
    CustomTokenObtainPairSerializer,
    UserCreateSerializer
)
from .forms import UserLoginForm, UserRegistrationForm
from open_cvpn.response_schemas import ERROR_RESPONSES, SUCCESS_EXAMPLES
from sso.policies import get_enforced_sso_config, get_password_login_block_message

User = get_user_model()

# API views
class UserRegistrationView(generics.GenericAPIView):
    """View for user registration - GET only to display registration info."""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def get(self, request, *args, **kwargs):
        """Return registration information - actual registration only via Web UI."""
        return Response({
            'message': 'User registration is only available via Web UI',
            'web_ui_url': '/register/',
            'note': 'Please use the web interface for user registration'
        }, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        """Block POST requests - registration only via Web UI."""
        return Response({
            'error': 'Method Not Allowed',
            'detail': 'User registration via API is disabled for security reasons. Please use the Web UI.',
            'web_ui_url': '/register/',
            'status_code': 405
        }, status=status.HTTP_405_METHOD_NOT_ALLOWED)

class UserDetailView(generics.RetrieveAPIView):
    """View for retrieving user details."""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    # Note: User profile updates and account deletion are only available via Web UI for security reasons

@extend_schema(
    summary='Obtain JWT Token',
    description='Authenticate user and return JWT access and refresh tokens along with user details.',
    request=CustomTokenObtainPairSerializer,
    responses={
        200: {
            'description': 'Authentication successful',
            'content': {
                'application/json': {
                    'examples': {
                        'success': SUCCESS_EXAMPLES['token_response']
                    }
                }
            }
        },
        **ERROR_RESPONSES
    },
    examples=[
        OpenApiExample(
            'Login Request',
            summary='Login Credentials',
            description='Provide email and password to authenticate',
            value={
                'email': 'user@example.com',
                'password': 'your_password'
            }
        )
    ]
)
class CustomTokenObtainPairView(TokenObtainPairView):
    """Custom token obtain view that includes user details."""
    serializer_class = CustomTokenObtainPairSerializer

class UserCreateAPIView(generics.CreateAPIView):
    """API view for user registration"""
    serializer_class = UserCreateSerializer
    permission_classes = [permissions.AllowAny]

# Web UI views
def login_view(request):
    """Handle user login via web UI"""
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    
    if request.method == 'POST':
        form = UserLoginForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data.get('email')
            password = form.cleaned_data.get('password')
            user = authenticate(request, email=email, password=password)
            
            if user is not None:
                enforced_sso_config = get_enforced_sso_config(user)
                if enforced_sso_config:
                    messages.error(request, get_password_login_block_message(enforced_sso_config))
                else:
                    login(request, user)
                    next_url = request.GET.get('next', '')
                    if not next_url or not url_has_allowed_host_and_scheme(
                        next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()
                    ):
                        next_url = 'dashboard:dashboard'
                    return redirect(next_url)
            else:
                messages.error(request, 'Invalid email or password.')
    else:
        form = UserLoginForm()
    
    return render(request, 'base/login.html', {'form': form})

def register_view(request):
    """Handle user registration via web UI"""
    if request.user.is_authenticated:
        return redirect('dashboard:dashboard')
    
    if request.method == 'POST':
        form = UserRegistrationForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            messages.success(request, 'Account created successfully!')
            return redirect('dashboard:dashboard')
    else:
        form = UserRegistrationForm()
    
    return render(request, 'base/register.html', {'form': form})

@login_required
def logout_view(request):
    """Handle user logout"""
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('login')

@login_required
def profile_view(request):
    """User profile view"""
    return render(request, 'base/profile.html')
