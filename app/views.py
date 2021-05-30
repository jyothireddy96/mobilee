from rest_framework import permissions, generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from django.contrib.auth import login
# from app.auth import TokenAuthentication
# from .views import LoginView as KnoxLoginView
# from blissedmaths.utils import phone_validator, password_generator, otp_generator
from .serializers import (CreateUserSerializer, ChangePasswordSerializer,UserrSerializer,
                          UserSerializer, LoginUserSerializer, ForgetPasswordSerializer)
from .models import User, PhoneOTP
from django.shortcuts import get_object_or_404
from django.db.models import Q
import requests
from rest_framework.views import APIView
class LoginAPIView(APIView):
    permission_classes = (permissions.AllowAny,)
    def post(self, request, format=None):
        serializer = LoginUserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']
        if user.last_login is None :
            user.first_login = True
            user.save()
        elif user.first_login:
            user.first_login = False
            user.save()
        login(request, user)
        return super().post(request, format=None)
class UserAPIView(generics.RetrieveAPIView):
    permission_classes = [permissions.IsAuthenticated, ]
    serializer_class = UserSerializer
    def get_object(self):
        return self.request.user
class ChangePasswordAPIView(generics.UpdateAPIView):
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated, ]
    def get_object(self, queryset=None):
        obj = self.request.user
        return obj
    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            if not self.object.check_password(serializer.data.get('password_1')):
                return Response({
                    'status': False,
                    'current_password': 'Does not match with our data',
                }, status=status.HTTP_400_BAD_REQUEST)

            self.object.set_password(serializer.data.get('password_2'))
            self.object.password_changed = True
            self.object.save()
            return Response({
                "status": True,
                "detail": "Password has been successfully changed.",
            })
        return Response(serializer.error, status=status.HTTP_400_BAD_REQUEST)
def send_otp(phone):
    if phone:
        key = otp_generator()
        phone = str(phone)
        otp_key = str(key)
        return otp_key
    else:
        return False
def send_otp_forgot(phone):
    if phone:
        key = otp_generator()
        phone = str(phone)
        otp_key = str(key)
        user = get_object_or_404(User, phone__iexact = phone)
        if user.name:
            name = user.name
        else:
            name = phone
      
        return otp_key
    else:
        return False
class ValidatePhoneSendOTPView(APIView):
    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact = phone)
            if user.exists():
                return Response({'status': False, 'detail': 'Phone Number already exists'})
            else:
                otp = send_otp(phone)
                print(phone, otp)
                if otp:
                    otp = str(otp)
                    count = 0
                    old = PhoneOTP.objects.filter(phone__iexact = phone)
                    if old.exists():
                        count = old.first().count
                        old.first().count = count + 1
                        old.first().save()
                    else:
                        count = count + 1
                        PhoneOTP.objects.create(
                             phone =  phone, 
                             otp =   otp,
                             count = count
                             )
                    if count > 7:
                        return Response({
                            'status' : False, 
                             'detail' : 'Maximum otp limits reached. Kindly support our customer care or try with different number'
                        })
                else:
                    return Response({
                                'status': 'False', 'detail' : "OTP sending error. Please try after some time."
                            })

                return Response({
                    'status': True, 'detail': 'Otp has been sent successfully.'
                })
        else:
            return Response({
                'status': 'False', 'detail' : "I haven't received any phone number. Please do a POST request."
            })
class ValidateOTPView(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp_sent   = request.data.get('otp', False)
        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact = phone)
            if old.exists():
                old = old.first()
                otp = old.otp
                if str(otp) == str(otp_sent):
                    old.logged = True
                    old.save()

                    return Response({
                        'status' : True, 
                        'detail' : 'OTP matched, kindly proceed to save password'
                    })
                else:
                    return Response({
                        'status' : False, 
                        'detail' : 'OTP incorrect, please try again'
                    })
            else:
                return Response({
                    'status' : False,
                    'detail' : 'Phone not recognised. Kindly request a new otp with this number'
                })
        else:
            return Response({
                'status' : 'False',
                'detail' : 'Either phone or otp was not recieved in Post request'
            })
class RegisterView(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        password = request.data.get('password', False)
        if phone and password:
            phone = str(phone)
            user = User.objects.filter(phone__iexact = phone)
            if user.exists():
                return Response({'status': False, 'detail': 'Phone Number already have account associated. Kindly try forgot password'})
            else:
                old = PhoneOTP.objects.filter(phone__iexact = phone)
                if old.exists():
                    old = old.first()
                    if old.logged:
                        Temp_data = {'phone': phone, 'password': password }

                        serializer = CreateUserSerializer(data=Temp_data)
                        serializer.is_valid(raise_exception=True)
                        user = serializer.save()
                        user.save()

                        old.delete()
                        return Response({
                            'status' : True, 
                            'detail' : 'Congrts, user has been created successfully.'
                        })

                    else:
                        return Response({
                            'status': False,
                            'detail': 'Your otp was not verified earlier. Please go back and verify otp'

                        })
                else:
                    return Response({
                    'status' : False,
                    'detail' : 'Phone number not recognised. Kindly request a new otp with this number'
                })

        else:
            return Response({
                'status' : 'False',
                'detail' : 'Either phone or password was not recieved in Post request'
            })

class ValidatePhoneForgotView(APIView):
    def post(self, request, *args, **kwargs):
        phone_number = request.data.get('phone')
        if phone_number:
            phone = str(phone_number)
            user = User.objects.filter(phone__iexact = phone)
            if user.exists():
                otp = send_otp_forgot(phone)
                print(phone, otp)
                if otp:
                    otp = str(otp)
                    count = 0
                    old = PhoneOTP.objects.filter(phone__iexact = phone)
                    if old.exists():
                        old = old.first()
                        k = old.count
                        if k > 10:
                            return Response({
                                'status' : False, 
                                'detail' : 'Maximum otp limits reached. Kindly support our customer care or try with different number'
                            })
                        old.count = k + 1
                        old.save()

                        return Response({'status': True, 'detail': 'OTP has been sent for password reset. Limits about to reach.'})
                    
                    else:
                        count = count + 1
               
                        PhoneOTP.objects.create(
                             phone =  phone, 
                             otp =   otp,
                             count = count,
                             forgot = True, 
        
                             )
                        return Response({'status': True, 'detail': 'OTP has been sent for password reset'})
                    
                else:
                    return Response({
                                    'status': 'False', 'detail' : "OTP sending error. Please try after some time."
                                })
            else:
                return Response({
                    'status' : False,
                    'detail' : 'Phone number not recognised. Kindly try a new account for this number'
                })
class ForgotValidateOTPView(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp_sent   = request.data.get('otp', False)

        if phone and otp_sent:
            old = PhoneOTP.objects.filter(phone__iexact = phone)
            if old.exists():
                old = old.first()
                if old.forgot == False:
                    return Response({
                        'status' : False, 
                        'detail' : 'This phone havenot send valid otp for forgot password. Request a new otp or contact help centre.'
                     })
                    
                otp = old.otp
                if str(otp) == str(otp_sent):
                    old.forgot_logged = True
                    old.save()

                    return Response({
                        'status' : True, 
                        'detail' : 'OTP matched, kindly proceed to create new password'
                    })
                else:
                    return Response({
                        'status' : False, 
                        'detail' : 'OTP incorrect, please try again'
                    })
            else:
                return Response({
                    'status' : False,
                    'detail' : 'Phone not recognised. Kindly request a new otp with this number'
                })
        else:
            return Response({
                'status' : 'False',
                'detail' : 'Either phone or otp was not recieved in Post request'
            })
class ForgetPasswordChangeView(APIView):
    def post(self, request, *args, **kwargs):
        phone = request.data.get('phone', False)
        otp   = request.data.get("otp", False)
        password = request.data.get('password', False)
        if phone and otp and password:
            old = PhoneOTP.objects.filter(Q(phone__iexact = phone) & Q(otp__iexact = otp))
            if old.exists():
                old = old.first()
                if old.forgot_logged:
                    post_data = {
                        'phone' : phone,
                        'password' : password
                    }
                    user_obj = get_object_or_404(User, phone__iexact=phone)
                    serializer = ForgetPasswordSerializer(data = post_data)
                    serializer.is_valid(raise_exception = True)
                    if user_obj:
                        user_obj.set_password(serializer.data.get('password'))
                        user_obj.active = True
                        user_obj.save()
                        old.delete()
                        return Response({
                            'status' : True,
                            'detail' : 'Password changed successfully. Please Login'
                        })

                else:
                    return Response({
                'status' : False,
                'detail' : 'OTP Verification failed. Please try again in previous step'
                                 })

            else:
                return Response({
                'status' : False,
                'detail' : 'Phone and otp are not matching or a new phone has entered. Request a new otp in forgot password'
            })

        else:
            return Response({
                'status' : False,
                'detail' : 'Post request have parameters mising.'
            })

from rest_framework import viewsets

class UserViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('id')
    serializer_class = UserSerializer

class UserrViewSet(viewsets.ModelViewSet):
    queryset = User.objects.all().order_by('id')
    serializer_class = UserSerializer

from django.views.decorators.csrf import csrf_exempt
class TodoList(APIView):
    """
    List all snippets, or create a new snippet.
    """
    def get(self, request, format=None):
        snippets = User.objects.all().order_by('id')
        serializer = UserSerializer(snippets, many=True)
        return Response(serializer.data)

    def post(self, request, format=None):
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class UserDetail(APIView):
    @csrf_exempt
    def get_object(self, pk):
        try:
            return Todo.objects.get(pk=pk)
        except Snippet.DoesNotExist:
            raise Http404
    @csrf_exempt
    def get(self, request, pk, format=None):
        snippet = self.get_object(pk)
        serializer = UserSerializer(snippet)
        return Response(serializer.data)

class TodoDetail(APIView):
    @csrf_exempt
    def get_object(self, pk):
        try:
            return User.objects.get(pk=pk)
        except Snippet.DoesNotExist:
            raise Http404
    
    @csrf_exempt
    def get(self, request, pk, format=None):
        snippet = self.get_object(pk)
        serializer = UserSerializer(snippet)
        return Response(serializer.data)
    @csrf_exempt
    def patch(self, request, pk, format=None):
        snippet = self.get_object(pk)
        serializer = TodoSerializer(snippet, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    # by default ZingGrid will send a /url/:id to delete     
    @csrf_exempt
    def delete(self, request, pk, format=None):
        snippet = self.get_object(pk)
        snippet.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
import pyotp
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
import base64


class generateKey:
    @staticmethod
    def returnValue(phone):
        return str(phone) + str(datetime.date(datetime.now())) + "Some Random Secret Key"


class getPhoneNumberRegistered(APIView):
    @staticmethod
    def get(request, phone):
        try:
            phone = User.objects.get(phone=phone)  
        except ObjectDoesNotExist:
            User.objects.create(
                phone=phone,
            )
            phone = User.objects.get(phone=phone)  
        phone.counter += 1  
        phone.save() 
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone).encode())  
        OTP = pyotp.HOTP(key)  
        print(OTP.at(phone.counter))
        return Response({"OTP": OTP.at(phone.counter)}, status=200)  # Just for demonstration

    @staticmethod
    def post(request, phone):
        try:
            phone = User.objects.get(phone=phone)
        except ObjectDoesNotExist:
            return Response("User does not exist", status=404)  # False Call

        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone).encode())  
        OTP = pyotp.HOTP(key)  
        if OTP.verify(request.data["otp"], phone.counter): 
            phone.isVerified = True
            phone.save()
            return Response("You are authorised", status=200)
        return Response("OTP is wrong", status=400)

EXPIRY_TIME = 50 

class getPhoneNumberRegistered_TimeBased(APIView):
    @staticmethod
    def get(request, phone):
        try:
            phone = User.objects.get(phone=phone)  
        except ObjectDoesNotExist:
            User.objects.create(
                phone=phone,
            )
            phone = User.objects.get(phone=phone)  
        phone.save()  
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone).encode())  
        OTP = pyotp.TOTP(key,interval = EXPIRY_TIME) 
        print(OTP.now())
        return Response({"OTP": OTP.now()}, status=200)  

    
    @staticmethod
    def post(request, phone):
        try:
            phone = User.objects.get(phone=phone)
        except ObjectDoesNotExist:
            return Response("User does not exist", status=404) 

        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone).encode())  
        OTP = pyotp.TOTP(key,interval = EXPIRY_TIME) 
        if OTP.verify(request.data["otp"]):  
            phone.isVerified = True
            phone.save()
            return Response("You are authorised", status=200)
        return Response("OTP is wrong/expired", status=400)
