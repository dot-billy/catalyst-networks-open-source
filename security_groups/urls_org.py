from django.urls import path
from . import views

app_name = 'security_groups_org'

urlpatterns = [
    # Organization-specific security group views
    path('', views.org_security_group_list, name='list'),
    path('create/', views.org_security_group_create, name='create'),
    path('<int:pk>/', views.org_security_group_detail, name='detail'),
    path('<int:pk>/edit/', views.org_security_group_edit, name='edit'),
    path('<int:pk>/delete/', views.org_security_group_delete, name='delete'),
    
    # Rules
    path('<int:sg_id>/rules/add/', views.org_add_rule, name='add_rule'),
    path('<int:sg_id>/rules/<int:rule_id>/edit/', views.org_edit_rule, name='edit_rule'),
    path('<int:sg_id>/rules/<int:rule_id>/delete/', views.org_delete_rule, name='delete_rule'),
    
    # Node management
    path('<int:sg_id>/assign-nodes/', views.org_assign_nodes, name='assign_nodes'),
    path('<int:sg_id>/unassign-node/<int:node_id>/', views.org_unassign_node, name='unassign_node'),
] 