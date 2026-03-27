from django.urls import path
from . import views

urlpatterns = [
    path('getting-started/', views.getting_started, name='getting_started'),
    path('network-setup/', views.network_setup, name='network_setup'),
    path('certificate-management/', views.certificate_management, name='certificate_management'),
    path('api-reference/', views.api_reference, name='api_reference'),
    path('security-policies/', views.security_policies, name='security_policies'),
    path('bulk-operations/', views.bulk_operations, name='bulk_operations'),
    path('node-mgmt-cli/', views.node_mgmt_cli, name='node_mgmt_cli'),
    path('troubleshooting/', views.troubleshooting, name='troubleshooting'),
]
