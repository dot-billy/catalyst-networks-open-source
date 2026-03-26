from django.urls import path
from . import views

app_name = 'certificates'

urlpatterns = [
    # Certificate authority administration remains web-only; node enrollment and
    # config retrieval stay in the node API.
    path('', views.certificate_authority_list, name='list'),
    path('create/', views.certificate_authority_create, name='create'),
    path('<int:pk>/', views.certificate_authority_detail, name='detail'),
]