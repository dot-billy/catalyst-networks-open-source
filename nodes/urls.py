from django.urls import path, include
# from rest_framework.routers import DefaultRouter
from . import views

# router = DefaultRouter()
# router.register(r'', views.NodeViewSet, basename='node')

app_name = 'nodes'

urlpatterns = [
    # API endpoints
    # path('api/', include(router.urls)),
    
    # Web views
    path('', views.node_list, name='list'),
    path('create/', views.node_create, name='create'),
    path('<int:pk>/', views.node_detail, name='detail'),
] 