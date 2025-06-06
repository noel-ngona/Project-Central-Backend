from django.test import TestCase
from django.contrib.auth.models import User
from django.urls import reverse
from rest_framework.test import APITestCase
from rest_framework import status

class AuthenticationTests(APITestCase):
    def setUp(self):
        # Create a test user
        self.username = "testuser"
        self.password = "testpass123"
        self.user = User.objects.create_user(
            username=self.username,
            password=self.password,
            email="test@example.com"
        )
        self.login_url = reverse('login')
        self.logout_url = reverse('logout')
        self.me_url = reverse('me')

    def test_login_successful(self):
        """Test successful login with valid credentials"""
        data = {
            'username': self.username,
            'password': self.password
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('access', response.data)
        self.assertIn('refresh', response.cookies)

    def test_login_invalid_credentials(self):
        """Test login with invalid credentials"""
        data = {
            'username': self.username,
            'password': 'wrongpassword'
        }
        response = self.client.post(self.login_url, data, format='json')
        
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
        self.assertIn('error', response.data)

    def test_login_missing_fields(self):
        """Test login with missing fields"""
        # Test with missing password
        response = self.client.post(self.login_url, {'username': self.username}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

        # Test with missing username
        response = self.client.post(self.login_url, {'password': self.password}, format='json')
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout(self):
        """Test logout functionality"""
        # First login to get the token
        login_data = {
            'username': self.username,
            'password': self.password
        }
        login_response = self.client.post(self.login_url, login_data, format='json')
        token = login_response.data['access']
        
        # Set the token in the authorization header
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        
        # Test logout
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_205_RESET_CONTENT)
        
        # Verify the refresh token cookie is invalidated
        self.assertIn('refresh', response.cookies)
        self.assertEqual('', response.cookies['refresh'].value)
        self.assertEqual(0, response.cookies['refresh']['max-age'])

        # Verify we can't access protected endpoints anymore
        # me_response = self.client.get(self.me_url)
        # self.assertEqual(me_response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_unauthorized_logout(self):
        """Test logout without authentication"""
        response = self.client.post(self.logout_url)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)
