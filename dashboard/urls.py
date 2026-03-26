from django.urls import path
from . import views

app_name = 'dashboard'

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('recent-activity/', views.recent_activity, name='recent_activity'),
    path('certificate-warnings/', views.certificate_warnings, name='certificate_warnings'),
] 