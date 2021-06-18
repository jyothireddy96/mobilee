from rest_framework import permissions, generics, status
from rest_framework.response import Response
from rest_framework.decorators import api_view
from datetime import datetime
from django.core.exceptions import ObjectDoesNotExist
import pyotp
from rest_framework.response import Response
from rest_framework.views import APIView
from .models import User
import base64
from .serializers import *
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


class generateKey:
    @staticmethod
    def returnValue(phone):
        return str(phone) + str(datetime.date(datetime.now())) + "Some Random Secret Key"


class getPhoneNumberRegistered(APIView):
    @staticmethod
    def get(request, email):
        try:
            email = User.objects.get(email=email)  
        except ObjectDoesNotExist:
            User.objects.create(
                email=email,
            )
            email = User.objects.get(email=email)  
        email.counter += 1  
        email.save() 
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone).encode())  
        OTP = pyotp.HOTP(key)  
        print(OTP.at(email.counter))
        return Response({"OTP": OTP.at(email.counter)}, status=200)  # Just for demonstration

    @staticmethod
    def post(request, phone):
        try:
            phone = User.objects.get(phone=phone)
        except ObjectDoesNotExist:
            return Response("User does not exist", status=404)  # False Call

        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(email).encode())  
        OTP = pyotp.HOTP(key)  
        if OTP.verify(request.data["otp"],email.counter): 
            email.isVerified = True
            email.save()
            return Response("You are authorised", status=200)
        return Response("OTP is wrong", status=400)

EXPIRY_TIME = 50 

class getPhoneNumberRegistered_TimeBased(APIView):
    @staticmethod
    def get(request, phone):
        try:
            email = User.objects.get(email=email)  
        except ObjectDoesNotExist:
            User.objects.create(
                email=email,
            )
            email = User.objects.get(email=email)  
        email.save()  
        keygen = generateKey()
        key = base64.b32encode(keygen.returnValue(phone).encode())  
        OTP = pyotp.TOTP(key,interval = EXPIRY_TIME) 
        print(OTP.now())
        return Response({"OTP": OTP.now()}, status=200)  

    
    @staticmethod
    def post(request, phone):
        try:
            email = User.objects.get(email=email)
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

from datetime import datetime, date
from django.shortcuts import render, redirect
from django.http import HttpResponse, HttpResponseRedirect
from django.views import generic
from django.utils.safestring import mark_safe
from datetime import timedelta
import calendar
from .models import *
from .forms import ApointmentForm, AddMemberForm
from django.shortcuts import get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.urls import reverse_lazy
def get_date(req_day):
    if req_day:
        year, month = (int(x) for x in req_day.split('-'))
        return date(year, month, day=1)
    return datetime.today()

def prev_month(d):
    first = d.replace(day=1)
    prev_month = first - timedelta(days=1)
    month = 'month=' + str(prev_month.year) + '-' + str(prev_month.month)
    return month

def next_month(d):
    days_in_month = calendar.monthrange(d.year, d.month)[1]
    last = d.replace(day=days_in_month)
    next_month = last + timedelta(days=1)
    month = 'month=' + str(next_month.year) + '-' + str(next_month.month)
    return month

class CalendarView(LoginRequiredMixin, generic.ListView):
    login_url = 'signup'
    model = Apointment
    template_name = 'calendar.html'

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        d = get_date(self.request.GET.get('month', None))
        cal = Calendar(d.year, d.month)
        html_cal = cal.formatmonth(withyear=True)
        context['calendar'] = mark_safe(html_cal)
        context['prev_month'] = prev_month(d)
        context['next_month'] = next_month(d)
        return context

@login_required(login_url='signup')
def create_event(request):    
    form = EventForm(request.POST or None)
    if request.POST and form.is_valid():
        title = form.cleaned_data['title']
        description = form.cleaned_data['description']
        start_time = form.cleaned_data['start_time']
        end_time = form.cleaned_data['end_time']
        Event.objects.get_or_create(
            user=request.user,
            title=title,
            description=description,
            start_time=start_time,
            end_time=end_time
        )
        return HttpResponseRedirect(reverse('calendarapp:calendar'))
    return render(request, 'event.html', {'form': form})

class EventEdit(generic.UpdateView):
    model = Apointment
    fields = ['title', 'description', 'start_time', 'end_time']
    template_name = 'event.html'

@login_required(login_url='signup')
def event_details(request, event_id):
    event = Event.objects.get(id=event_id)
    eventmember = EventMember.objects.filter(event=event)
    context = {
        'event': event,
        'eventmember': eventmember
    }
    return render(request, 'event-details.html', context)


def add_eventmember(request, event_id):
    forms = AddMemberForm()
    if request.method == 'POST':
        forms = AddMemberForm(request.POST)
        if forms.is_valid():
            member = EventMember.objects.filter(event=event_id)
            event = Event.objects.get(id=event_id)
            if member.count() <= 9:
                user = forms.cleaned_data['user']
                EventMember.objects.create(
                    event=event,
                    user=user
                )
                return redirect('calendarapp:calendar')
            else:
                print('--------------User limit exceed!-----------------')
    context = {
        'form': forms
    }
    return render(request, 'add_member.html', context)

@login_required(login_url='signup')
def index(request):
    return HttpResponse('hello')
class EventMemberDeleteView(generic.DeleteView):
    model = ApointmentMember
    template_name = 'event_delete.html'
    success_url = reverse_lazy('calendarapp:calendar')
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
from .forms import *

def signup(request):
    forms = SignupForm()
    if request.method == 'POST':
        forms = SignupForm(request.POST)
        if forms.is_valid():
            username = forms.cleaned_data['username']
            password = forms.cleaned_data['password']
            user = authenticate(username=username, password=password)
            if user:
                login(request, user)
                return redirect('calendarapp:calendar')
    context = {'form': forms}
    return render(request, 'app/signup.html', context)

def user_logout(request):
    logout(request)
    return redirect('signup')