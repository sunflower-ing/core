from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.urls import include, path

from core import views

urlpatterns = [
    path('', views.index, name="index"),
    path('login/', views.login_view, name="login_view"),
    path('logout/', views.logout_view, name="logout_view"),
    path('x509/', include('x509.urls')),
    path('admin/', admin.site.urls),
] + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
