from django.urls import path
from . import views

urlpatterns = [
    path('node-mgmt-cli/', views.node_mgmt_cli, name='node_mgmt_cli'),
] 