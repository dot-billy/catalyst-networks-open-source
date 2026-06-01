"""
URL configuration for open_cvpn project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from django.views.generic import RedirectView
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from rest_framework_simplejwt.views import TokenRefreshView
from drf_spectacular.views import SpectacularAPIView, SpectacularSwaggerView, SpectacularRedocView
from organizations.views_api import OrganizationViewSet
from users.views import (
    CustomTokenObtainPairView, 
    login_view, 
    register_view, 
    logout_view,
    profile_view
)
from .error_handlers import api_404_handler, api_500_handler, api_403_handler, api_400_handler, api_502_handler

urlpatterns = [
    # Admin Interface
    path('admin/', admin.site.urls),
    
    # Redirect root to dashboard
    path('', RedirectView.as_view(url='/dashboard/', permanent=False)),
    
    # Auth endpoints
    path('api/token/', CustomTokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),

    # Human admins use the web UI; the public API only exposes org discovery here.
    path('api/org/', OrganizationViewSet.as_view({'get': 'list'}), name='organization-list'),

    # Organization-scoped node runtime/provisioning API.
    path('api/org/<slug:slug>/', include([
        path('nodes/', include('nodes.urls_api')),
        path('', include('organizations.urls_api')),
    ])),

    # Health endpoint (to be implemented)
    path('health/', include('health.urls')),

    # API Documentation (restricted to staff users)
    path('api/schema/', staff_member_required(SpectacularAPIView.as_view()), name='schema'),
    path('api/docs/', staff_member_required(SpectacularSwaggerView.as_view(url_name='schema')), name='swagger-ui'),
    path('api/redoc/', staff_member_required(SpectacularRedocView.as_view(url_name='schema')), name='redoc'),

    # Dashboard and user management
    path('dashboard/', include('dashboard.urls')),
    path('login/', login_view, name='login'),
    path('register/', register_view, name='register'),
    path('logout/', logout_view, name='logout'),
    path('profile/', profile_view, name='profile'),

    # Password management
    path('password_change/', auth_views.PasswordChangeView.as_view(template_name='base/password_change.html'), name='password_change'),
    path('password_change/done/', auth_views.PasswordChangeDoneView.as_view(template_name='base/password_change_done.html'), name='password_change_done'),
    path('password_reset/', auth_views.PasswordResetView.as_view(template_name='base/password_reset.html'), name='password_reset'),
    path('password_reset/done/', auth_views.PasswordResetDoneView.as_view(template_name='base/password_reset_done.html'), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(template_name='base/password_reset_confirm.html'), name='password_reset_confirm'),
    path('reset/done/', auth_views.PasswordResetCompleteView.as_view(template_name='base/password_reset_complete.html'), name='password_reset_complete'),

    # Web views (non-API)
    path('organizations/', include(('organizations.urls', 'organizations'), namespace='organizations')),
    path('nodes/', include(('nodes.urls', 'nodes'), namespace='nodes')),
    path('certificates/', include(('certificates.urls', 'certificates'), namespace='certificates')),
    path('security-groups/', include(('security_groups.urls', 'security_groups'), namespace='security_groups')),
    path('webhooks/', include(('webhooks.urls', 'webhooks'), namespace='webhooks')),

    # Organization-specific web views
    path('organizations/<slug:slug>/nodes/', include(('nodes.urls_org', 'nodes_org'), namespace='nodes_org')),
    path('organizations/<slug:slug>/certificates/', include(('certificates.urls_org', 'certificates_org'), namespace='certificates_org')),
    path('organizations/<slug:slug>/security-groups/', include(('security_groups.urls_org', 'security_groups_org'), namespace='security_groups_org')),
    path('organizations/<slug:slug>/webhooks/', include(('webhooks.urls_org', 'webhooks_org'), namespace='webhooks_org')),
    path('organizations/<slug:slug>/notifications/', include(('notifications.urls_org', 'notifications_org'), namespace='notifications_org')),

    # Users URLs
    path('api/users/', include('users.urls')),

    # Docs URLs
    path('docs/', include('docs.urls')),  # Removed namespace temporarily to fix loading issues

    # SSO / SAML / OIDC
    path('sso/', include('sso.urls')),
    path('accounts/', include('sso.allauth_urls')),
]

# Serve media files in development
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

# Custom error handlers for API endpoints
handler404 = api_404_handler
handler500 = api_500_handler
handler403 = api_403_handler
handler400 = api_400_handler
handler502 = api_502_handler
