from django.urls import path
from .views import LoginView, RefreshTokenView, LogoutView, MeView, RequestPasswordResetView, ResetPasswordView

urlpatterns = [
    path('login', LoginView.as_view(), name='login'),
    path('refresh', RefreshTokenView.as_view(), name='refresh'),
    path('logout', LogoutView.as_view(), name='logout'),
    path('me', MeView.as_view(), name='me'),
    path('password/reset', RequestPasswordResetView.as_view(), name='password-reset-request'),
    path('password/reset/confirm', ResetPasswordView.as_view(), name='password-reset-confirm'),
]