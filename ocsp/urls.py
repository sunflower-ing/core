from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r"sources", views.SourceViewSet)
router.register(r"logs", views.RequestLogViewSet)
