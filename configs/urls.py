from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from core import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('FA/', views.register2, name='FA'),
    path('dash/', views.dash, name='dashboard'),
]

# ✅ add this *outside* the list
if settings.DEBUG:  # only serve static this way in debug/dev
    urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)