from django.urls import path
from . import views
from rest_framework.routers import DefaultRouter

app_name = 'nodes_api'

# Create router for viewsets
router = DefaultRouter()

# Define URL patterns
urlpatterns = [
    # Node registration
    path('register/', views.NodeRegistrationView.as_view(), name='register'),
    
    # Node listing and detail
    path('', views.OrgNodeViewSet.as_view({'get': 'list', 'post': 'create'}), name='node-list'),
    path('<int:pk>/', views.OrgNodeViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update'}), name='node-detail'),
    # Note: Node deletion is only available via Web UI for security reasons
    
    # Node certificate operations
    path('<int:pk>/download_config/', views.OrgNodeViewSet.as_view({'get': 'download_config'}), name='node-download-config'),
    path('<int:pk>/renew_cert/', views.OrgNodeViewSet.as_view({'post': 'renew_cert'}), name='node-renew-cert'),
    
    # Node check-in endpoint
    path('<int:pk>/checkin/', views.OrgNodeViewSet.as_view({'post': 'checkin'}), name='node-checkin'),
    
    # Security group operations (read-only)
    path('<int:pk>/security_groups/', views.OrgNodeViewSet.as_view({'get': 'security_groups'}), name='node-security-groups'),
    # Note: Security group assignment and removal are only available via Web UI for security reasons
    
    # Note: Debug and direct access endpoints removed for security reasons
    # These endpoints bypassed security checks and posed significant risks
    
    # Note: Registration token management is only available via Web UI for security reasons
    # Token creation, viewing, and revocation should be done through the organization dashboard
] 