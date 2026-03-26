from django.urls import path
from . import views

app_name = 'security_groups'

urlpatterns = [
    # Security group administration is web-only; the node API exposes only the
    # runtime security-group read path under `nodes.urls_api`.
    path('', views.security_group_list, name='list'),
    path('create/', views.security_group_create, name='create'),
    path('<int:pk>/', views.security_group_detail, name='detail'),
]