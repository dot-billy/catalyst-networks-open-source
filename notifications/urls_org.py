from django.urls import path

from . import views

app_name = "notifications_org"

urlpatterns = [
    path("", views.org_notification_preferences, name="preferences"),
    path("slack/", views.org_slack_integration, name="slack"),
]
