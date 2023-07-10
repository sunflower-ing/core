from django.urls import include, path

from x509.urls import router as x509_router
from x509.views import crl
from ocsp.views import ocsp_view

urlpatterns = [
    path(
        "v1/api-auth/",
        include("rest_framework.urls", namespace="restframework"),
    ),
    path("v1/api/x509/", include(x509_router.urls)),
    path("crl/<str:ca_slug>.<str:format>", crl, name="crl"),
    path("ocsp/", ocsp_view, name="ocsp"),
]
