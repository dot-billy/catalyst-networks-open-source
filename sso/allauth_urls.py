from django.urls import include, path
from allauth.socialaccount import views as socialaccount_views
from allauth.socialaccount.providers.google import views as google_views

urlpatterns = [
    path('3rdparty/', socialaccount_views.ConnectionsView.as_view(), name='socialaccount_connections'),
    path(
        '3rdparty/login/cancelled/',
        socialaccount_views.LoginCancelledView.as_view(),
        name='socialaccount_login_cancelled',
    ),
    path(
        '3rdparty/login/error/',
        socialaccount_views.LoginErrorView.as_view(),
        name='socialaccount_login_error',
    ),
    path('google/login/', google_views.oauth2_login, name='google_login'),
    path('google/login/callback/', google_views.oauth2_callback, name='google_callback'),
    path('', include('allauth.socialaccount.providers.openid_connect.urls')),
]
