from __future__ import unicode_literals
from django.contrib.auth import get_user_model
from django.contrib import admin
User = get_user_model()
from django.contrib.auth.models import Group
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .forms import UserAdminCreationForm, UserAdminChangeForm
from .models import Profile, PhoneOTP
admin.site.register(PhoneOTP)

from .models import *

class ApointmentMemberAdmin(admin.ModelAdmin):
    model =ApointmentMember
    list_display = ['event', 'user']

admin.site.register(Apointment)
admin.site.register(ApointmentMember, ApointmentMemberAdmin)
class ProfileInline(admin.StackedInline):
    model = Profile
    can_delete = False
    verbose_name_plural = 'Profile'
    fk_name = 'user'
class UserAdmin(BaseUserAdmin):
    form = UserAdminChangeForm
    add_form = UserAdminCreationForm
    list_display = ( 'phone',  'standard',  'admin',)
    list_filter = ('standard','staff','active' ,'admin', )
    fieldsets = (
        (None, {'fields': ('phone', 'password')}),
        ('Personal info', {'fields': ( 'standard','score',)}),
        ('Permissions', {'fields': ('admin','staff','active')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('phone', 'password1', 'password2')}
        ),
    )
    search_fields = ['phone']
    ordering = ['phone']
    filter_horizontal = ()
    inlines = (ProfileInline, )
    def get_inline_instances(self, request, obj=None):
        if not obj:
            return list()
        return super(UserAdmin, self).get_inline_instances(request, obj)

admin.site.register(User, UserAdmin)
admin.site.unregister(Group)





