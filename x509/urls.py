from rest_framework import routers

from . import views

router = routers.DefaultRouter()
router.register(r"keys", views.KeyViewSet)
router.register(r"csrs", views.CSRViewSet)
router.register(r"certs", views.CertificateViewSet)
