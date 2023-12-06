import uuid

from cryptography.hazmat.primitives.asymmetric import dsa, rsa
from django.http import HttpResponse
from django_filters import rest_framework
from drf_spectacular.types import OpenApiTypes
from drf_spectacular.utils import OpenApiParameter, extend_schema
from rest_framework import (
    authentication,
    filters,
    generics,
    permissions,
    status,
    viewsets,
)
from rest_framework.response import Response

from core.models import Actions, Modules, log
from utils.crypto import (
    cert_from_pem,
    cert_to_der,
    cert_to_pem,
    get_cert_issuer_fingerprint,
    get_key_fingerprint,
    key_from_pem,
    key_to_der,
    key_to_pem,
)

from .models import CRL, CSR, Certificate, Key
from .serializers import CertificateSerialiser, CSRSerializer, KeySerializer

CTYPE = {
    "pem": "application/x-pem-file",
    "der": "application/pkcs8",
    "der_ca": "application/x-x509-ca-cert",
    "der_enduser": "application/x-x509-user-cert",
    "pkcs12": "application/x-pkcs12",
}


class KeyFilterSet(rest_framework.FilterSet):
    created_at = rest_framework.DateFromToRangeFilter()

    class Meta:
        model = Key
        fields = ["algo", "length", "used", "fingerprint", "created_at"]


class KeyViewSet(viewsets.ModelViewSet):
    queryset = Key.objects.all()
    serializer_class = KeySerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [
        rest_framework.DjangoFilterBackend,
        filters.SearchFilter,
    ]
    filterset_class = KeyFilterSet
    search_fields = ["name", "fingerprint"]

    def create(self, request, *args, **kwargs):
        instance = None
        if not request.data.get("name"):
            request.data.update({"name": str(uuid.uuid4())})
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            instance = serializer.instance

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.CREATE,
            entity="KEY",
            object_id=instance.pk,
        )
        return super().create(request, *args, **kwargs)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.used:
            return Response(
                data={"detail": "Method not allowed for Key in use"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.UPDATE,
            entity="KEY",
            object_id=instance.pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.used:
            return Response(
                data={"detail": "Method not allowed for Key in use"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.DESTROY,
            entity="KEY",
            object_id=instance.pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.RETRIEVE,
            entity="KEY",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="used",
                description="Filter by is key already used.Can be either true or false",  # noqa
                required=False,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="algo",
                description="Filter by algorithm. Can be either RSA or DSA",
                required=False,
                type=OpenApiTypes.STR,
            ),
            OpenApiParameter(
                name="length",
                description="Filter by key length. Can be 1024, 2048, 3072, 4096 or 8192",  # noqa
                required=False,
                type=OpenApiTypes.INT,
            ),
            OpenApiParameter(
                name="fingerprint",
                description="Filter by fingerprint",
                required=False,
                type=OpenApiTypes.STR,
            ),
            OpenApiParameter(
                name="search",
                description="Search by name",
                required=False,
                type=OpenApiTypes.STR,
            ),
        ]
    )
    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.LIST,
            entity="KEY",
        )
        return super().list(request, *args, **kwargs)


class CSRFilterSet(rest_framework.FilterSet):
    created_at = rest_framework.DateFromToRangeFilter()

    class Meta:
        model = CSR
        fields = ["name", "signed", "ca", "path_length", "created_at"]


class CSRViewSet(viewsets.ModelViewSet):
    queryset = CSR.objects.all()
    serializer_class = CSRSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [
        rest_framework.DjangoFilterBackend,
        filters.SearchFilter,
    ]
    filterset_class = CSRFilterSet
    search_fields = ["name"]

    def create(self, request, *args, **kwargs):
        instance = None
        if not request.data.get("key"):
            key = Key.objects.create(name=str(uuid.uuid4()))
            request.data.update({"key": key.pk})
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid(raise_exception=True):
            self.perform_create(serializer)
            instance = serializer.instance

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.CREATE,
            entity="CSR",
            object_id=instance.pk,
        )
        return Response(data=serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.signed:
            return Response(
                data={"detail": "Method not allowed for signed CSR"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.UPDATE,
            entity="CSR",
            object_id=instance.pk,
        )
        return super().update(request, *args, **kwargs)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.signed:
            return Response(
                data={"detail": "Method not allowed for signed CSR"},
                status=status.HTTP_406_NOT_ACCEPTABLE,
            )
        else:
            instance.key.used = False
            instance.key.save()  # Free the Key for later use

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.DESTROY,
            entity="CSR",
            object_id=instance.pk,
        )
        return super().destroy(request, *args, **kwargs)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.RETRIEVE,
            entity="CSR",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="signed",
                description="Filter by is CSR already signed. Can be either true or false",  # noqa
                required=False,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="ca",
                description="Filter by is CSR is CA. Can be either true or false",  # noqa
                required=False,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="path_length",
                description="Filter by path length. Integer from 0 to N",
                required=False,
                type=OpenApiTypes.INT,
            ),
            OpenApiParameter(
                name="search",
                description="Search by name",
                required=False,
                type=OpenApiTypes.STR,
            ),
        ]
    )
    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.LIST,
            entity="CSR",
        )
        return super().list(request, *args, **kwargs)


class CertificateViewSet(viewsets.ModelViewSet):
    queryset = Certificate.objects.all()
    serializer_class = CertificateSerialiser
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [
        rest_framework.DjangoFilterBackend,
        filters.SearchFilter,
    ]
    filterset_fields = [
        "sn",
        "parent",
        "imported",
        "revoked",
        "revocation_reason",
        "fingerprint",
    ]
    search_fields = ["csr__name"]

    http_method_names = ["get", "post", "put"]

    def create(self, request, *args, **kwargs):
        serializer = self.serializer_class(
            data=request.data, context={"request": request}
        )
        if serializer.is_valid():
            instance = serializer.save()
            if instance.csr.ca:
                crl = CRL(ca=instance)
                crl.save()

            log(
                user=request.user,
                module=Modules.X509,
                action=Actions.CREATE,
                entity="CERTIFICATE",
                object_id=instance.pk,
            )
            return Response(
                data=serializer.data, status=status.HTTP_201_CREATED
            )
        else:
            return Response(
                data=serializer.errors, status=status.HTTP_400_BAD_REQUEST
            )

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.revoked:
            return Response(
                data={"detail": "Certificate already revoked"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        # TODO: check only revoked & revocation_reason fields are changed
        if not request.data.get("revoked"):
            return Response(
                data={"detail": "Method can only be used for revocation"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        instance.revoke(request.data.get("reason"))

        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.UPDATE,
            entity="CERTIFICATE",
            object_id=instance.pk,
        )
        return Response(data=request.data, status=status.HTTP_200_OK)

    def retrieve(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.RETRIEVE,
            entity="CERTIFICATE",
            object_id=self.get_object().pk,
        )
        return super().retrieve(request, *args, **kwargs)

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="sn",
                description="Filter by Serial Number",
                required=False,
                type=OpenApiTypes.INT,
            ),
            OpenApiParameter(
                name="parent",
                description="Filter by parent ID. Integer or null for self-signed",  # noqa
                required=False,
                type=OpenApiTypes.INT,
            ),
            OpenApiParameter(
                name="imported",
                description="Filter by is Certificate imported. Can be either true or false",  # noqa
                required=False,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="revoked",
                description="Filter by is Certificate revoked. Can be either true or false",  # noqa
                required=False,
                type=OpenApiTypes.BOOL,
            ),
            OpenApiParameter(
                name="revocation_reason",
                description="Filter by revocation reason. String (for possible reasons look at the PUT method)",  # noqa
                required=False,
                type=OpenApiTypes.STR,
            ),
            OpenApiParameter(
                name="fingerprint",
                description="Filter by fingerprint",
                required=False,
                type=OpenApiTypes.STR,
            ),
            OpenApiParameter(
                name="search",
                description="Search by name",
                required=False,
                type=OpenApiTypes.STR,
            ),
        ]
    )
    def list(self, request, *args, **kwargs):
        log(
            user=request.user,
            module=Modules.X509,
            action=Actions.LIST,
            entity="CERTIFICATE",
        )
        return super().list(request, *args, **kwargs)


def crl_view(request, ca_slug, format: str = "crl"):
    crl = CRL.objects.filter(ca__csr__slug=ca_slug).first()
    if format == "crt":
        return HttpResponse(crl.as_der())
    else:
        return HttpResponse(crl.as_pem())


class KeyImportView(generics.GenericAPIView):
    authentication_classes = [authentication.TokenAuthentication]
    serializer_class = KeySerializer

    def post(self, request):
        # TODO: make it cleaner
        # TODO: add logging
        try:
            key_pem: bytes = request.read()
            private_key = key_from_pem(key_pem=key_pem, private=True)

            if isinstance(private_key, rsa.RSAPrivateKey):
                algo = "RSA"
            elif isinstance(private_key, dsa.DSAPrivateKey):
                algo = "DSA"
            else:
                return Response(
                    data={"detail": "Unknown key type"}, status=400
                )

            try:
                key_fingerprint = get_key_fingerprint(
                    private_key.public_key()
                ).decode()
                key = Key.objects.get(fingerprint=key_fingerprint)
                key.private = key_pem.decode()
                key.fingerprint = key_fingerprint
            except Key.DoesNotExist:
                key = Key(
                    name=str(uuid.uuid4()),
                    private=key_pem.decode(),
                    length=private_key.key_size,
                    algo=algo,
                )

            key.save()
            return Response(KeySerializer(instance=key).data)

        except Exception as e:
            return Response(data={"detail": str(e)}, status=500)


class CertificateImportView(generics.GenericAPIView):
    authentication_classes = [authentication.TokenAuthentication]
    serializer_class = CertificateSerialiser

    def post(self, request):
        # TODO: make it cleaner
        # TODO: add logging
        try:
            cert_pem: bytes = request.read()
            certificate = cert_from_pem(cert_pem=cert_pem)

            # First deal with the Key
            public_key = certificate.public_key()
            public_key_fingerprint = get_key_fingerprint(public_key).decode()
            try:
                key = Key.objects.get(fingerprint=public_key_fingerprint)
                key.used = True
                key.save()
            except Key.DoesNotExist:
                if isinstance(public_key, rsa.RSAPublicKey):
                    algo = "RSA"
                else:
                    algo = "DSA"
                key = Key(
                    name=str(uuid.uuid4()),
                    public=key_to_pem(public_key).decode(),
                    length=public_key.key_size,
                    algo=algo,
                    used=True,
                )
                key.save()
            # Now the Certificate itself
            issuer_fingerprint = get_cert_issuer_fingerprint(
                certificate
            ).decode()
            try:
                parent = Certificate.objects.get(name_hash=issuer_fingerprint)
            except Certificate.DoesNotExist:
                parent = None

            cert = Certificate(
                key=key,
                parent=parent,
                key_hash=public_key_fingerprint,
                body=cert_pem.decode(),
                imported=True,
            )
            cert.save()

            return Response(CertificateSerialiser(instance=cert).data)

        except Exception as e:
            return Response(data={"detail": str(e)}, status=500)


class KeyExportView(generics.RetrieveAPIView):
    authentication_classes = [authentication.TokenAuthentication]

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="type",
                description="Key type. Can be either private or public. Default is public",  # noqa
                required=False,
                type=OpenApiTypes.STR,
                default="private",
            ),
            OpenApiParameter(
                name="format",
                description="Export format. Can be either PEM or DER (p8/key). Default is pem",  # noqa
                required=False,
                type=OpenApiTypes.STR,
                default="pem",
            ),
        ],
        responses={200: OpenApiTypes.BINARY},
    )
    def get(self, request, key_id, *args, **kwargs):
        key_type = request.query_params.get("type", "public")
        key_format = request.query_params.get("format", "pem").lower()

        try:
            key = Key.objects.get(pk=key_id)
            if key_type == "private":
                if not key.private:
                    return Response(
                        data={"detail": "No private part"}, status=404
                    )

                if key_format == "pem":
                    data = key_to_pem(key.private_as_object(), private=True)
                else:
                    data = key_to_der(key.private_as_object(), private=True)

                response = HttpResponse(data, content_type=CTYPE[key_format])
                response[
                    "Content-Disposition"
                ] = f"attachment; filename='{key.name}'"

                return response
            else:
                if key_format == "pem":
                    data = key_to_pem(key.public_as_object())
                else:
                    data = key_to_der(key.public_as_object())

                response = HttpResponse(data, content_type=CTYPE[key_format])
                response[
                    "Content-Disposition"
                ] = f"attachment; filename='{key.name}'"

                return response

        except Key.DoesNotExist:
            return Response(data={"detail": "Not found"}, status=404)


class CertificateExportView(generics.GenericAPIView):
    authentication_classes = [authentication.TokenAuthentication]

    @extend_schema(
        parameters=[
            OpenApiParameter(
                name="format",
                description="Export format. Can be PEM, DER (der/crt) or PKCS12 (p12/pfx). Default is pem",  # noqa
                required=False,
                type=OpenApiTypes.STR,
                default="pem",
            )
        ],
        responses={200: OpenApiTypes.BINARY},
    )
    def get(self, request, cert_id, *args, **kwargs):
        cert_format = request.query_params.get("format", "pem").lower()

        try:
            cert = Certificate.objects.get(pk=cert_id)

            if cert_format == "pem":
                response = HttpResponse(
                    cert_to_pem(cert.as_object()),
                    content_type=CTYPE[cert_format],
                )

            else:
                response = HttpResponse(
                    cert_to_der(cert.as_object()),
                    content_type=CTYPE["der_ca"]
                    if cert.is_ca
                    else CTYPE["der_enduser"],
                )
            # TODO: Add PKCS12

            response[
                "Content-Disposition"
            ] = f"attachment; filename='{cert.cn}'"

            return response

        except Certificate.DoesNotExist:
            return Response(data={"detail": "Not found"}, status=404)
