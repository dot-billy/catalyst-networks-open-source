from django.urls import path
from . import views

app_name = 'security_groups_org'

urlpatterns = [
    # Source-to-destination policy workflow
    path('policies/', views.org_policy_list, name='policy_list'),
    path('policies/create/', views.org_policy_create, name='policy_create'),
    path('policies/<int:rule_id>/edit/', views.org_policy_edit, name='policy_edit'),
    path('policies/<int:rule_id>/delete/', views.org_policy_delete, name='policy_delete'),

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

    # Node x Tag membership matrix
    path('matrix/', views.org_node_tag_matrix, name='matrix'),
    path('matrix/apply/', views.org_node_tag_matrix_apply, name='matrix_apply'),

    # Direction-first rule editor
    path('rules/new/', views.org_rule_create, name='rule_create'),
    path('rules/preview/', views.org_rule_preview, name='rule_preview'),

    # Recipe wizard
    path('recipes/', views.org_recipes, name='recipes'),
]
