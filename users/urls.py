from django.urls import path
from .views import (
    UserDetailView
)

app_name = 'users'

urlpatterns = [
    # Note: User registration is only available via Web UI for security reasons
    # Registration endpoint removed from API to prevent confusion
    path('me/', UserDetailView.as_view(), name='user_detail'),
] 