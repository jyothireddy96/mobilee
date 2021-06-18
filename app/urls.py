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
    path('registerr',views.RegisterView.as_view()),
    path('LoginAPI',views.LoginAPIView.as_view()),
    path("<phone>/", views.getPhoneNumberRegistered.as_view(), name="OTP Gen"),
    
    # path('index', views.index, name='index'),
    path('', views.CalendarView.as_view(), name='calendar'),
    path('event/new/', views.create_event, name='event_new'),
    path('event/edit/<int:pk>/', views.EventEdit.as_view(), name='event_edit'),
    path('event/<int:event_id>/details/', views.event_details, name='event-detail'),
    path('add_eventmember/<int:event_id>', views.add_eventmember, name='add_eventmember'),
    path('event/<int:pk>/remove', views.EventMemberDeleteView.as_view(), name="remove_event"),
   


   

]