from django.urls import path
from . import views

app_name = 'sso'

urlpatterns = [
    path('<slug:slug>/login/', views.sso_login, name='login'),
    path('<slug:slug>/oidc/login/', views.oidc_login, name='oidc_login'),
    path('<slug:slug>/acs/', views.sso_acs, name='acs'),
    path('<slug:slug>/metadata/', views.sso_metadata, name='metadata'),
    path('<slug:slug>/configure/', views.sso_configure, name='configure'),
    path('<slug:slug>/toggle/', views.sso_toggle, name='toggle'),
]
