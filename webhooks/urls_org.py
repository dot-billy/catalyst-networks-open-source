from django.urls import path
from . import views

app_name = 'webhooks_org'

urlpatterns = [
    # Organization-specific webhook views
    path('', views.org_webhook_list, name='list'),
    path('create/', views.org_webhook_create, name='create'),
    path('<int:pk>/', views.org_webhook_detail, name='detail'),
    path('<int:pk>/edit/', views.org_webhook_edit, name='edit'),
    path('<int:pk>/delete/', views.org_webhook_delete, name='delete'),
    path('<int:pk>/test/', views.org_webhook_test, name='test'),
    path('logs/', views.org_webhook_logs, name='logs'),
] 