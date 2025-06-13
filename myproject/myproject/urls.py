"""myproject URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, re_path
from app import views, forms
import django.contrib.auth.views
from django.contrib.auth.views import LoginView, LogoutView
from datetime import datetime
admin.autodiscover()

urlpatterns = [
    path('admin/', admin.site.urls),
    re_path(r'^$', views.home, name='home'), #check if the user has log in
    re_path(r'^contact$', views.contact, name='contact'),
    re_path(r'^about$', views.about, name='about'),
    re_path(r'^registration$', views.registration, name='registration'),
    re_path(r'^assignment$', views.assignment, name='assignment'),
    re_path(r'^forgotPassword$', views.forgotPassword, name='forgotPassword'),
    re_path(r'^tokenValidation$', views.tokenValidation, name='tokenValidation'),
    re_path(r'^changePassword$', views.changePassword, name='changePassword'),
    re_path(r'^grading$', views.grading, name='grading'),
    re_path(r'^upload$', views.upload, name='upload'),
    path('register_validation/', views.register_validation, name='register_validation'),
    path('assignment_validation/', views.assignment_validation, name='assignment_validation'),
    path('login_validation/', views.login_validation, name='login_validation'),
    path('forgot_password_validation/', views.forgot_password_validation, name='forgot_password_validation'),
    path('validate_token/', views.validate_token, name='validate_token'),
    path('change_password_validation/', views.change_password_validation, name='change_password_validation'),
    path('handle_file_upload/', views.handle_file_upload, name='chandle_file_upload'),
    path('clear_grades/', views.clear_grades, name='clear_grades'),
    re_path(r'^login/$', views.login, name= 'login'),
    re_path(r'^menu$', views.menu, name='menu'),

]
