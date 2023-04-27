from django.shortcuts import render
from rest_framework.response import Response
from rest_framework import status
from rest_framework.views import APIView
from .serializers import *
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import IsAuthenticated

# Generate token manually
def get_tokens_for_user(user):
    refresh = RefreshToken.for_user(user)

    return {
        'refresh': str(refresh),
        'access': str(refresh.access_token),
    }


class UserRegistrationView(APIView):
    def post(self, request, format = None):
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.save()
            token = get_tokens_for_user(user)
            return Response({
                'message':'Registration successful & token Generated',
                'token':token,
                'data':serializer.data,
                'status':status.HTTP_201_CREATED
        })
        return Response({
            'message':'Something Went Wrong',
            'errors':serializer.errors,
            'status':status.HTTP_400_BAD_REQUEST
        })
        
        
class UserLoginView(APIView):
    def post(self, request, format=None):
        serializer = UserLoginSerializers(data=request.data)
        if serializer.is_valid(raise_exception=True):
            email = serializer.data.get('email')
            password = serializer.data.get('password')
            user=authenticate(email=email, password=password)
            if user is not None:
                token = get_tokens_for_user(user)
                return Response({
                    'message':'Login successful & token Generated',
                    'token':token,
                    'data':serializer.data,
                    'status':status.HTTP_200_OK
                    })
            return Response({
                'message':'Something Went Wrong',
                'errors':{'non_field_errors':['Email or Password is not valid']},
                'status':status.HTTP_404_NOT_FOUND
                })
                

class UserProfileView(APIView):
        permission_classes = [IsAuthenticated]
        def get(self, request):
            serializer = UserProfileSerializer(request.user)
            return Response({
                    'message':'Your data is here',
                    'data':serializer.data,
                    'status':status.HTTP_200_OK
                    })
            
            
class UserChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]
    def post(self, request, formate=None):
        serializer = UserChangePasswordSerializer(data=request.data,
        context = {
            'user':request.user
        })
        if serializer.is_valid(raise_exception=True):
            return Response({
                'message':'Password changed successfully',
                'data':serializer.data,
                'status':status.HTTP_200_OK
                })
        return Response({
                'message':'Something Went Wrong',
                'errors':serializer.errors,
                'status':status.HTTP_404_NOT_FOUND
            })
                

class SendPasswordResetEmailView(APIView):
    def post(self, request):
        serializer = SendPasswordResetEmailSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            return Response({
                'message':'Email Reset link send, please check your email',
                'data':serializer.data,
                'status':status.HTTP_200_OK
                })
        return Response({
                'message':'Something Went Wrong',
                'errors':serializer.errors,
                'status':status.HTTP_404_NOT_FOUND
                })
                
                
class UserPasswordResetView(APIView):
    def post(self, request, uid, token, format=None):
        serializer = UserPasswordResetSerializer(data=request.data, context={
            'uid':uid,
            'token':token,
        })
        if serializer.is_valid(raise_exception=True):
            return Response({
                'message':'Your password has been changed, please login again',
                'data':serializer.data,
                'status':status.HTTP_200_OK
                })
        return Response({
                'message':'Something Went Wrong',
                'errors':serializer.errors,
                'status':status.HTTP_404_NOT_FOUND
                })