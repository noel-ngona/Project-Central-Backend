from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate, get_user_model
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, AllowAny
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
import time
import os
from django.utils.http import urlsafe_base64_decode
from django.utils.encoding import force_str, force_bytes
from django.utils.http import urlsafe_base64_encode

class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        time.sleep(3)  # Simulate a delay for demonstration purposes
        if user is not None:
            refresh = RefreshToken.for_user(user)
            response = Response({
                'access': str(refresh.access_token),
                'user' : {
                    'username': user.username,
                    'email': user.email,
                }
            }, status=status.HTTP_200_OK)
            response.set_cookie('refresh', str(refresh), httponly=True)
            return response
        return Response({'error': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

class RefreshTokenView(APIView):
    def post(self, request):
        try:
            refresh = request.COOKIES.get('refresh')
            if not refresh:
                return Response({'error': 'Refresh token not found'}, status=status.HTTP_401_UNAUTHORIZED)
            token = RefreshToken(refresh)
            access = str(token.access_token)
            response = Response({
                'access': access,
            }, status=status.HTTP_200_OK)
            response.set_cookie('refresh', str(token), httponly=True)
            return response
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request):
        response = Response(status=status.HTTP_205_RESET_CONTENT)
        token = RefreshToken(request.COOKIES.get('refresh'))
        token.blacklist()
        response.delete_cookie('refresh')
        return response

class MeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response({
            'username': request.user.username,
            'email': request.user.email,
        })

class RequestPasswordResetView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):
        email = request.data.get('email')
        User = get_user_model()
        user = User.objects.filter(email=email).first()
        
        if user:
            token_generator = PasswordResetTokenGenerator()
            reset_token = token_generator.make_token(user)
            
           
            email_b64 = urlsafe_base64_encode(force_bytes(email))
            
            # In production, this should be your frontend URL
            reset_url = f"{os.environ.get('FRONTEND_URL')}/reset-password/{email_b64}/{reset_token}"
            
            # Send email with reset link using template
            html_message = render_to_string('emails/password_reset.html', {
                'name': user.username,
                'reset_link': reset_url
            })
            
            send_mail(
                'Password Reset Request',
                '', # Empty string for plain text version
                settings.DEFAULT_FROM_EMAIL,
                [email],
                fail_silently=False,
                html_message=html_message
            )
            
            return Response(
                {'message': 'Password reset link has been sent to your email'},
                status=status.HTTP_200_OK
            )

        return Response(
            {"error" : "The email provided does not have an account"},
            status=status.HTTP_404_NOT_FOUND
        )

class ResetPasswordView(APIView):
    permission_classes = [AllowAny]
    
    def post(self, request):    
        email_b64 = request.data.get('email_b64')
        token = request.data.get('token')
        new_password = request.data.get('new_password')
        
        if not all([email_b64, token, new_password]):
            return Response(
                {'error': 'Missing required fields'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        try:
            # Decode the base64 email
            email = force_str(urlsafe_base64_decode(email_b64))
            User = get_user_model()
            user = User.objects.get(email=email)
            token_generator = PasswordResetTokenGenerator()
            
            if token_generator.check_token(user, token):
                user.set_password(new_password)
                user.save()
                return Response(
                    {'message': 'Password has been reset successfully'},
                    status=status.HTTP_200_OK
                )
            else:
                return Response(
                    {'error': 'Invalid or expired token'},
                    status=status.HTTP_400_BAD_REQUEST
                )
                
        except (TypeError, ValueError, User.DoesNotExist):
            return Response(
                {'error': 'Invalid reset link'},
                status=status.HTTP_400_BAD_REQUEST
            )

    