from django.urls import path
from .views import LoginView, RefreshTokenView, LogoutView, MeView

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('refresh', RefreshTokenView.as_view(), name='refresh'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('me', MeView.as_view(), name='me'),
]