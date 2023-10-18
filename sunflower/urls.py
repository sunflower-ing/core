from django.urls import include, path
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
    TokenVerifyView,
)

from core.views import (
    SystemGroupViewSet,
    SystemLogEntryViewSet,
    SystemPermissionViewSet,
    SystemUserViewSet,
    UserView,
    index,
)
from ocsp.views import RequestLogViewSet, SourceViewSet, ocsp_view
from x509.views import CertificateViewSet, CSRViewSet, KeyViewSet, crl_view

router = routers.DefaultRouter()
router.register(r"x509/keys", KeyViewSet)
router.register(r"x509/csrs", CSRViewSet)
router.register(r"x509/certs", CertificateViewSet)
router.register(r"ocsp/sources", SourceViewSet)
router.register(r"ocsp/logs", RequestLogViewSet)
router.register(r"system/users", SystemUserViewSet)
router.register(r"system/groups", SystemGroupViewSet)
router.register(r"system/permissions", SystemPermissionViewSet)
router.register(r"system/logs", SystemLogEntryViewSet)


urlpatterns = [
    path("", index, name="index"),
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
    path("v1/api/me/", UserView.as_view(), name="user_profile"),
    path("v1/api/", include(router.urls)),
    path("crl/<str:ca_slug>.<str:format>", crl_view, name="crl"),
    path("ocsp/", ocsp_view, name="ocsp"),
]
