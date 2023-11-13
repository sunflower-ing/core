from django.urls import include, path
from drf_spectacular.views import (
    SpectacularAPIView,
    SpectacularRedocView,
    SpectacularSwaggerView,
)
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
from x509.views import (
    CertificateExportView,
    CertificateImportView,
    CertificateViewSet,
    CSRViewSet,
    KeyExportView,
    KeyImportView,
    KeyViewSet,
    crl_view,
)

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
    # root/healthcheck view
    path("", index, name="index"),
    # Auth views
    path("api-auth/", include("rest_framework.urls")),
    # API views
    path(
        "api/v1/token/",
        TokenObtainPairView.as_view(),
        name="token_obtain_pair",
    ),
    path(
        "api/v1/token/refresh/",
        TokenRefreshView.as_view(),
        name="token_refresh",
    ),
    path(
        "api/v1/token/verify/", TokenVerifyView.as_view(), name="token_verify"
    ),
    path("api/v1/me/", UserView.as_view(), name="user_profile"),
    path("api/v1/", include(router.urls)),
    path(
        "api/v1/import/key/", KeyImportView.as_view(), name="key_import_view"
    ),
    path(
        "api/v1/import/certificate/",
        CertificateImportView.as_view(),
        name="certificate_import_view",
    ),
    path(
        "api/v1/export/key/<int:key_id>/",
        KeyExportView.as_view(),
        name="key_export_view",
    ),
    path(
        "api/v1/export/certificate/<int:cert_id>/",
        CertificateExportView.as_view(),
        name="certificate_export_view",
    ),
    # API doc views
    path("schema/", SpectacularAPIView.as_view(), name="schema"),
    path(
        "schema/swagger-ui/",
        SpectacularSwaggerView.as_view(
            url_name="schema", template_name="core/swagger-ui.html"
        ),
        name="swagger-ui",
    ),
    path(
        "schema/redoc/",
        SpectacularRedocView.as_view(
            url_name="schema", template_name="core/redoc.html"
        ),
        name="redoc",
    ),
    # Non versioned views
    path("crl/<str:ca_slug>.<str:format>", crl_view, name="crl"),
    path("ocsp/", ocsp_view, name="ocsp"),
]
