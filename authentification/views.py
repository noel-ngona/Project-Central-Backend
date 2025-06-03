from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.contrib.auth import authenticate
from rest_framework import status
from rest_framework.permissions import IsAuthenticated


class LoginView(APIView):
    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(username=username, password=password)
        if user is not None:
            refresh = RefreshToken.for_user(user)
            response = Response({
                'access': str(refresh.access_token),
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
        response.delete_cookie('refresh')
        return response

class MeView(APIView):
    permission_classes = [IsAuthenticated]
    def get(self, request):
        return Response({
            'username': request.user.username,
            'email': request.user.email,
        })

    