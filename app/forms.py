from django import forms
from django.contrib.auth.forms import ReadOnlyPasswordHashField
from .models import User 
class LoginForm(forms.Form):
    phone = forms.IntegerField(label = 'Your Phone Number')
    password = forms.CharField(widget = forms.PasswordInput)

class VerifyForm(forms.Form):
    key = forms.IntegerField(label = 'Please Enter OTP here')
    
class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    password2 = forms.CharField(label='Confirm password', widget=forms.PasswordInput)
    class Meta:
        model = User
        fields = ('phone',)
    def clean_phone(self):
        phone = self.cleaned_data.get('phone')
        qs = User.objects.filter(phone=phone)
        if qs.exists():
            raise forms.ValidationError("phone is taken")
        return phone
    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2
class TempRegisterForm(forms.Form):
    phone = forms.IntegerField()
    otp = forms.IntegerField()
  

class SetPasswordForm(forms.Form):

    password = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(
        label='Password confirmation', widget=forms.PasswordInput)

class UserAdminCreationForm(forms.ModelForm):
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput)
    password2 = forms.CharField(label='Password confirmation', widget=forms.PasswordInput)
    class Meta:
        model = User
        fields = ('phone',)

    def clean_password2(self):
        password1 = self.cleaned_data.get("password1")
        password2 = self.cleaned_data.get("password2")
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError("Passwords don't match")
        return password2

    def save(self, commit=True):
        user = super(UserAdminCreationForm, self).save(commit=False)
        user.set_password(self.cleaned_data["password1"])
        if commit:
            user.save()
        return user
class UserAdminChangeForm(forms.ModelForm):
    password = ReadOnlyPasswordHashField()
    class Meta:
        model = User
        fields = ('phone', 'password', 'active', 'admin')
    def clean_password(self):
         return self.initial["password"]


from django.forms import ModelForm, DateInput
from .models import *
from django import forms

class ApointmentForm(ModelForm):
  class Meta:
    model = Apointment
    # datetime-local is a HTML5 input type, format to make date time show on fields
    widgets = {
      'start_time': DateInput(attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
      'end_time': DateInput(attrs={'type': 'datetime-local'}, format='%Y-%m-%dT%H:%M'),
    }
    exclude = ['user']

  def __init__(self, *args, **kwargs):
    super(EventForm, self).__init__(*args, **kwargs)
    # input_formats to parse HTML5 datetime-local input to datetime field
    self.fields['start_time'].input_formats = ('%Y-%m-%dT%H:%M',)
    self.fields['end_time'].input_formats = ('%Y-%m-%dT%H:%M',)


class SignupForm(forms.Form):
  username = forms.CharField(widget=forms.
  TextInput(attrs={'class': 'form-control', 'placeholder': 
  'Username'}))
  password = forms.CharField(widget=forms.PasswordInput(attrs={'class': 'form-control', 'placeholder': 'Password'}))


class AddMemberForm(forms.ModelForm):
  class Meta:
    model = ApointmentMember
    fields = ['user']
















