from django.urls import path
from .views import (
    organization_list, 
    organization_create, 
    organization_detail,
    network_range_view,
    delete_network_range,
    delete_organization,
    organization_activity,
    invitation_list,
    invitation_create,
    invitation_accept,
    change_member_role,
    remove_member,
    resend_invitation,
    revoke_invitation,
    organization_members,
    add_member,
)

# Web view URLs
web_urlpatterns = [
    path('', organization_list, name='list'),
    path('create/', organization_create, name='create'),
    path('<slug:slug>/', organization_detail, name='detail'),
    path('<slug:slug>/delete/', delete_organization, name='delete'),
    path('<slug:slug>/network-range/', network_range_view, name='network_range'),
    path('<slug:slug>/network-range/delete/', delete_network_range, name='delete_network_range'),
    path('<slug:slug>/activity/', organization_activity, name='organization_activity'),
    
    # Invitation web views
    path('<slug:slug>/invitations/', invitation_list, name='invitation_list'),
    path('<slug:slug>/invitations/create/', invitation_create, name='invitation_create'),
    path('invitations/accept/<str:token>/', invitation_accept, name='invitation_accept'),
    
    # Member management
    path('<slug:slug>/members/', organization_members, name='members'),
    path('<slug:slug>/members/<int:membership_id>/change-role/', 
         change_member_role, 
         name='change_member_role'),
    path('<slug:slug>/members/<int:membership_id>/remove/', 
         remove_member, 
         name='remove_member'),
    path('<slug:slug>/members/add/', add_member, name='add_member'),
    
    # Invitation management
    path('<slug:slug>/invitations/<int:invitation_id>/resend/',
         resend_invitation,
         name='resend_invitation'),
    path('<slug:slug>/invitations/<int:invitation_id>/revoke/',
         revoke_invitation,
         name='revoke_invitation'),
]

# API URLs intentionally omitted here.
# Organization administration, memberships, and invitations are managed in the
# web UI. The only live organization API surface is the top-level org list in
# `open_cvpn.urls`, while node provisioning/runtime stays under `nodes.urls_api`.
api_urlpatterns = [
]

app_name = 'organizations'

# Combine web and API URLs
urlpatterns = web_urlpatterns + api_urlpatterns 