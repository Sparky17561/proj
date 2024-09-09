from django.contrib import admin
from django.urls import path
from app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.upload_email, name='upload_email'),  
    path('display/', views.display_email, name='display_email'),
    path('success/', views.success, name='success_page'),
    path('url-report/', views.url_report_view, name='url_report'),
]
