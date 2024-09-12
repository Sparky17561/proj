from django.contrib import admin
from django.urls import path
from app import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('email/', views.upload_email, name='upload_email'),  
    path('display/', views.display_email, name='display_email'),
    path('success/', views.success, name='success_page'),
    path('url-report/', views.url_report_view, name='url_report'),
    path('', views.index, name='index'),  # Home page view
    path('blog-details/', views.blog_details, name='blog-details'),  # Blog details page
    path('blog/', views.blog, name='blog'),  # Blog listing page
    path('portfolio-details/', views.portfolio_details, name='portfolio-details'),  # Portfolio details page
    path('service-details/', views.service_details, name='service-details'),  # Service details page
    path('starter-page/', views.starter_page, name='starter-page'),  # Starter page
]
