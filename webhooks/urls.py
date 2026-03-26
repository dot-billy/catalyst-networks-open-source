from django.urls import path
from . import views

app_name = 'webhooks'

urlpatterns = [
    # Webhook administration is handled in the web UI; no public webhook DRF
    # routes are exposed for customer administration workflows.
    path('', views.webhook_list, name='list'),
    path('create/', views.webhook_create, name='create'),
    path('<int:pk>/', views.webhook_detail, name='detail'),
]