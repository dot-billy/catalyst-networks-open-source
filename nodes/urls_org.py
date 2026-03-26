from django.urls import path
from . import views

app_name = 'nodes_org'

urlpatterns = [
    # Organization-specific node views
    path('', views.org_node_list, name='list'),
    path('create/', views.org_node_create, name='create'),
    path('create-mobile/', views.org_node_create_mobile, name='create_mobile'),
    path('<int:pk>/', views.org_node_detail, name='detail'),
    path('<int:pk>/edit/', views.org_node_edit, name='edit'),
    path('<int:pk>/delete/', views.org_node_delete, name='delete'),
    path('<int:pk>/download-cert/', views.org_node_download_cert, name='download_cert'),
    path('<int:pk>/download-key/', views.org_node_download_key, name='download_key'),
    path('<int:pk>/download-config/', views.org_node_download_config, name='download_config'),
    path('<int:pk>/sign-mobile/', views.org_node_mobile_sign, name='mobile_sign'),
    path('<int:pk>/enroll/', views.org_node_enroll, name='enroll'),
    path('<int:pk>/renew-cert/', views.org_node_renew_cert, name='renew_cert'),
    path('<int:pk>/security-groups/', views.org_node_security_groups, name='assign_security_group'),
    
    # Node registration token management
    path('registration-tokens/', views.org_registration_token_list, name='token_list'),
    path('registration-tokens/create/', views.org_registration_token_create, name='token_create'),
    path('registration-tokens/<int:pk>/', views.org_registration_token_detail, name='token_detail'),
    path('registration-tokens/<int:pk>/revoke/', views.org_registration_token_revoke, name='token_revoke'),
] 