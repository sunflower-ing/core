from django.urls import include, path
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from ocsp.urls import router as ocsp_router
from ocsp.views import ocsp_view
from x509.urls import router as x509_router
from x509.views import crl_view

urlpatterns = [
    path("api-auth/", include("rest_framework.urls")),
    path(
        "v1/api/token/",
        TokenObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "v1/api/token/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "v1/api/token/verify/", TokenVerifyView.as_view(), name="token_verify"
    ),
    path("v1/api/x509/", include(x509_router.urls)),
    path("v1/api/ocsp/", include(ocsp_router.urls)),
    path("crl/<str:ca_slug>.<str:format>", crl_view, name="crl"),
    path("ocsp/", ocsp_view, name="ocsp"),
]
