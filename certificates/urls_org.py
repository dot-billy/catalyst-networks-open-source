from django.urls import path
from . import views

app_name = 'certificates_org'

urlpatterns = [
    # Organization-specific certificate authority views
    path('', views.org_certificate_authority_list, name='list'),
    path('create/', views.org_certificate_authority_create, name='create'),
    path('<int:pk>/', views.org_certificate_authority_detail, name='detail'),
    path('<int:pk>/renew/', views.org_certificate_authority_renew, name='renew'),
    path('<int:pk>/revoke/', views.org_certificate_authority_revoke, name='revoke'),
] 