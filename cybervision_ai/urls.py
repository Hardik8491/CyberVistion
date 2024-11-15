# cybervision_ai/urls.py
from django.contrib import admin
from django.urls import path, include

from core.views import welcome


handler404 = 'core.views.custom_404'
urlpatterns = [
    # Admin interface
  
    path('admin/', admin.site.urls),
    
    # Include URLs from the 'core' app
    path('api/', include('core.urls')),  # All API endpoints from core app will be prefixed with 'api/'
    path('', welcome, name='welcome'),
]


