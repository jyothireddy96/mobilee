from django.urls import path, include, re_path
from django.contrib import admin
from django.conf import settings
from django.conf.urls.static import static
admin.site.site_header = 'RestApi Phone number and password'
admin.site.site_title = 'Mobile OTP Pasword Login'
admin.site.index_title = 'Managed by Jyoti'
from rest_framework import routers
from . import views
router = routers.DefaultRouter()
router.register('', views.UserViewSet)
router.register('register', views.UserrViewSet)
from app import views
urlpatterns = [
    path('', include(router.urls)),
    re_path(r'^admin/', admin.site.urls),
    path('create', views.TodoList.as_view()),
    path('del/<int:pk>', views.TodoDetail.as_view()),
    path('Usr/<int:pk>', views.UserDetail.as_view()),
    path('registerr',views.RegisterView.as_view()),
    path('LoginAPI',views.LoginAPIView.as_view()),
    path('ValidatePhoneForgot',views.ValidatePhoneForgotView.as_view()),
    path('ValidatePhoneSendOTP',views.ValidatePhoneSendOTPView.as_view()),
    path('ForgotValidateOTP',views.ForgotValidateOTPView.as_view()),
    path("<phone>/", views.getPhoneNumberRegistered.as_view(), name="OTP Gen"),
    path("time_based/<phone>/", views.getPhoneNumberRegistered_TimeBased.as_view(), name="OTP Gen Time Based"),
]

